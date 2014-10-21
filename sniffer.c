/*
 * sniffer skeleton (Linux kernel module)
 *
 * Copyright (C) 2014 Ki Suh Lee <kslee@cs.cornell.edu>
 * based on netslice implementation of Tudor Marian <tudorm@cs.cornell.edu>
 */

#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/mm.h>
#include <linux/udp.h>
#include <linux/fs.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/sched.h>
#include <linux/list.h>
#include "sniffer_ioctl.h"
#include "asm/spinlock.h"

MODULE_AUTHOR("");
MODULE_DESCRIPTION("CS5413 Packet Filter / Sniffer Framework");
MODULE_LICENSE("Dual BSD/GPL");

static dev_t sniffer_dev;
static struct cdev sniffer_cdev;
static int sniffer_minor = 1;
atomic_t refcnt;

static int hook_chain = NF_INET_LOCAL_IN;
static int hook_prio = NF_IP_PRI_FIRST;
struct nf_hook_ops nf_hook_ops;

// skb buffer between kernel and user space
struct list_head skbs;

// skb wrapper for buffering
struct skb_list 
{
    struct list_head list;
    struct sk_buff *skb;
};

struct rule{
    int mode;
    uint32_t src_ip;
    int src_port;
    uint32_t dst_ip;
    int dst_port;
    int action;
    struct list_head list;
};
static struct rule rules;
struct rule *r_tmp,*r_t;
spinlock_t r_lock ;
wait_queue_head_t r_que;
#define SIGNATURE "Hakim"
char * signature;
static inline struct tcphdr * ip_tcp_hdr(struct iphdr *iph)
{
    struct tcphdr *tcph = (void *) iph + iph->ihl*4;
    return tcph;
}

/* From kernel to userspace */
    static ssize_t 
sniffer_fs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
    struct skb_list* tmp;
    int cnt=-1;
    wait_event_interruptible(r_que,!list_empty(&skbs));
    if(list_empty(&skbs)) return -1; 
    tmp = list_entry(skbs.next, struct skb_list, list);
    cnt=tmp->skb->len;
    printk(KERN_DEBUG"get %d byte\n",cnt);
    copy_to_user(buf, tmp->skb->data, tmp->skb->len);

    spin_lock_irq(&r_lock);  
    list_del(skbs.next);
    spin_unlock_irq(&r_lock);
    //printk(KERN_DEBUG "Read buff %d\n",cnt);
    return cnt;
}

static int sniffer_fs_open(struct inode *inode, struct file *file)
{
    struct cdev *cdev = inode->i_cdev;
    int cindex = iminor(inode);

    if (!cdev) {
        printk(KERN_ERR "cdev error\n");
        return -ENODEV;
    }

    if (cindex != 0) {
        printk(KERN_ERR "Invalid cindex number %d\n", cindex);
        return -ENODEV;
    }

    return 0;
}

static int sniffer_fs_release(struct inode *inode, struct file *file)
{
    return 0;
}
int cmp(struct rule * l1,struct sniffer_flow_entry * l2){
    return (l1->src_ip==l2->src_ip) && (l1->src_port == l2->src_port) 
        && (l1->dst_ip==l2->dst_ip) && (l1->dst_port == l2->dst_port);
}
static long sniffer_fs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    long err =0 ;
    struct sniffer_flow_entry* entry=(struct sniffer_flow_entry*) arg;
    if (_IOC_TYPE(cmd) != SNIFFER_IOC_MAGIC)
        return -ENOTTY; 
    if (_IOC_NR(cmd) > SNIFFER_IOC_MAXNR)
        return -ENOTTY;
    if (_IOC_DIR(cmd) & _IOC_READ)
        err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
    if (_IOC_DIR(cmd) & _IOC_WRITE)
        err = !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
    if (err)
        return -EFAULT;

    switch(cmd) {
        case SNIFFER_FLOW_ENABLE:
        case SNIFFER_FLOW_DISABLE:
            list_for_each_entry(r_t, &rules.list, list){
                if(cmp(r_t,entry)){
                    r_t->mode = entry->mode;
                    r_t->action = entry->action;
                }
            };
            r_tmp= vmalloc(sizeof(struct rule));
            memcpy(r_tmp,entry,sizeof(struct sniffer_flow_entry));
            list_add(&(r_tmp->list), &(rules.list));
            break;
        default:
            printk(KERN_DEBUG "Unknown command\n");
            err = -EINVAL;
    }

    return err;
}

static struct file_operations sniffer_fops = {
    .open = sniffer_fs_open,
    .release = sniffer_fs_release,
    .read = sniffer_fs_read,
    .unlocked_ioctl = sniffer_fs_ioctl,
    .owner = THIS_MODULE,
};

static unsigned int sniffer_nf_hook(unsigned int hook, struct sk_buff* skb,
        const struct net_device *indev, const struct net_device *outdev,
        int (*okfn) (struct sk_buff*))
{
    struct iphdr *iph = ip_hdr(skb);
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = ip_tcp_hdr(iph);
        if (ntohs(tcph->dest) == 22){
            return NF_ACCEPT;
        }
        if (ntohs(tcph->dest ) != 22) {
            uint32_t s_ip,d_ip;
            int s_port=0,d_port=0;

            s_ip=iph->saddr;
            d_ip=iph->daddr;
            s_port=ntohs(tcph->source);
            d_port=ntohs(tcph->dest);
            list_for_each_entry(r_t, &rules.list, list){
                if( (s_ip==r_t->src_ip || r_t->src_ip==0) &&  (d_ip==r_t->dst_ip || r_t->dst_ip==0||r_t->dst_ip==0x100007f) &&
                        (d_port==r_t->dst_port ||r_t->dst_port==0 ) && (s_port==r_t->src_port||r_t->src_port ==0) ){
                    if (r_t->action == SNIFFER_ACTION_CAPTURE){
                        //printk(KERN_DEBUG"caputre!\n");
                        struct skb_list* skb_tmp=kmalloc(sizeof(struct skb_list),GFP_ATOMIC);
                        skb_tmp->skb=skb_copy(skb,GFP_ATOMIC);
                        spin_lock_irq(&r_lock); 
                        list_add_tail(&(skb_tmp->list), &(skbs));
                        spin_unlock_irq(&r_lock);
                        wake_up_interruptible(&r_que);
                    } 
                    if(r_t->action == SNIFFER_ACTION_DPI){
                        //printk(KERN_DEBUG"dpi\n");
                        struct zl_ip *ip_h =skb->data;
                        int ip_size=IP_HL(ip_h)*4;
                        struct zl_tcp *tcp_h = ip_h+ip_size;
                        char *data = tcp_h->data;
                        int data_len=skb->len-ip_size-sizeof(struct zl_tcp);
                        int i=0,j;
                   
                        int sig_len=strlen(SIGNATURE);
                        //printk(KERN_DEBUG"sig len:%d,sig:%s\n,data:%s\n",sig_len,signature,data);
                        int flag=0,flag_w=0;
                        while(i<data_len-sig_len){
                            flag_w=1;

                            for(j=0;j<sig_len;j++){
                                if(data[i+j]!=signature[j]){
                                    flag_w=0;
                                    break;
                                }
                            }
 
                            if(flag_w) {
                                flag=1;
                                break;
                            }
                            ++i;
                        }
                        if(flag){
                            printk(KERN_DEBUG"dpi_DROP\n");
                            r_t->mode=SNIFFER_FLOW_DISABLE;
                            return NF_DROP;
                        }

                    }

                    if (r_t->mode==SNIFFER_FLOW_ENABLE){
                        printk(KERN_DEBUG "Accepted|!!!!!!!!!!! src:%x %d  dst: %x %d",iph->saddr, s_port, iph->daddr,d_port);
                        return NF_ACCEPT;
                    }
                    else return NF_DROP;
                }  		
            }   
            printk(KERN_DEBUG "Rejected src:%x %d  dst: %x %d",iph->saddr, s_port, iph->daddr,d_port);
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}

static int __init sniffer_init(void)
{
    int status = 0;
    printk(KERN_DEBUG "sniffer_init\n");

    status = alloc_chrdev_region(&sniffer_dev, 0, sniffer_minor, "sniffer");
    if (status <0) {
        printk(KERN_ERR "alloc_chrdev_retion failed %d\n", status);
        goto out;
    }

    cdev_init(&sniffer_cdev, &sniffer_fops);
    status = cdev_add(&sniffer_cdev, sniffer_dev, sniffer_minor);
    if (status < 0) {
        printk(KERN_ERR "cdev_add failed %d\n", status);
        goto out_cdev;

    }

    atomic_set(&refcnt, 0);
    INIT_LIST_HEAD(&skbs);

    /* register netfilter hook */
    memset(&nf_hook_ops, 0, sizeof(nf_hook_ops));
    nf_hook_ops.hook = sniffer_nf_hook;
    nf_hook_ops.pf = PF_INET;
    nf_hook_ops.hooknum = hook_chain;
    nf_hook_ops.priority = hook_prio;
    status = nf_register_hook(&nf_hook_ops);
    if (status < 0) {
        printk(KERN_ERR "nf_register_hook failed\n");
        goto out_add;
    }
    // my init
    INIT_LIST_HEAD(&rules.list);
    DEFINE_SPINLOCK(r_lock);
    init_waitqueue_head(&r_que);
    signature=SIGNATURE;
    return 0;

out_add:
    cdev_del(&sniffer_cdev);
out_cdev:
    unregister_chrdev_region(sniffer_dev, sniffer_minor);
out:
    return status;
}

static void __exit sniffer_exit(void)
{

    if (nf_hook_ops.hook) {
        nf_unregister_hook(&nf_hook_ops);
        memset(&nf_hook_ops, 0, sizeof(nf_hook_ops));
    }
    cdev_del(&sniffer_cdev);
    unregister_chrdev_region(sniffer_dev, sniffer_minor);
}

module_init(sniffer_init);
module_exit(sniffer_exit);
