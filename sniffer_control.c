#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include "sniffer_ioctl.h"

static char * program_name;
static char * dev_file = "sniffer.dev";
struct hostent *host;
struct in_addr **addr_list;
void usage() 
{
    fprintf(stderr, "Usage: %s [parameters]\n"
                "parameters: \n"
                "    --mode [enable|disable]\n"
                "    --src_ip [url|any] : default is any \n"
                "    --src_port [XXX|any] : default is any \n"
                "    --dst_ip [url|any] : default is any \n" 
                "    --dst_port [XXX|any] : default is any \n"
                "    --action [capture|dpi] : default is null\n", program_name);
    exit(EXIT_FAILURE);
}

int sniffer_send_command(struct sniffer_flow_entry *flow)
{
    int fd;
    fd=open(dev_file,O_WRONLY);
    if(fd<0){
        printf(" open file err %x\n",fd);
        return 0;
    }
    ioctl(fd,flow->mode,flow);
    return 0;
}
void sniffer_flow_entry_init(struct sniffer_flow_entry* e){
    e->src_ip=0;
    e->src_port=0;
    e->dst_ip=0;
   e->dst_port=0;
    e->mode= SNIFFER_FLOW_ENABLE;
    e->action=0;
}
int main(int argc, char **argv)
{
    int c;
    program_name = argv[0];
    struct sniffer_flow_entry e;
    sniffer_flow_entry_init(&e);
    while(1) {
        static struct option long_options[] = 
        {
            {"mode", required_argument, 0, 0},
            {"src_ip", required_argument, 0, 0},
            {"src_port", required_argument, 0, 0},
            {"dst_ip", required_argument, 0, 0},
            {"dst_port", required_argument, 0, 0},
            {"action", required_argument, 0, 0},
            {"dev", required_argument, 0, 0},
            {0, 0, 0, 0}
        };
        int option_index = 0;
        c = getopt_long (argc, argv, "", long_options, &option_index);

        if (c == -1)
            break;
        switch (c) {
        case 0:
            printf("option %d %s", option_index, long_options[option_index].name);
            if (optarg)
                printf(" with arg %s", optarg);
            printf("\n");

            switch(option_index) {
            case 0:     // mode
                if(strcmp(optarg,"enable")==0){
                    e.mode=SNIFFER_FLOW_ENABLE;
                }else 
                if(strcmp(optarg,"disable")==0){
                    e.mode=SNIFFER_FLOW_DISABLE;
                }
                break;
            case 1:     // src_ip
                if(strcmp(optarg,"any")==0){
                    e.src_ip=0;
                }else {
                    if((host=gethostbyname(optarg))<=0){
                        printf("err\n");
                        return 0;
                    }
                   
                    addr_list = (struct in_addr **)host->h_addr_list;
                    int i=0;

                    for(i = 0; addr_list[i] != NULL; i++) {
                       printf("add address %x \n",addr_list[i]->s_addr);
                        e.src_ip=(addr_list[i]->s_addr);
                        break;
                    }
                }
                break;                break;
            case 2:     // src_port
                if(strcmp(optarg,"any")==0){
                    e.src_port=0;
                }else 
                    e.src_port=atoi(optarg);
                break;
            case 3:     // dst_ip

                if(strcmp(optarg,"any")==0){
                    e.dst_ip=0;
                }else 
                /*if(strcmp(optarg,"localhost")==0){

                    struct ifaddrs *addrs;
                    getifaddrs(&addrs);
                    struct ifaddrs *tmp = addrs;
                    printf("tmp %d\n",tmp->ifa_addr);
                    while (tmp) 
                    {
                        if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET)
                        {
                            struct sockaddr_in *pAddr = (struct sockaddr_in *)tmp->ifa_addr;
                            printf("%s: %s\n", tmp->ifa_name, inet_ntoa(pAddr->sin_addr));
                        }
                        tmp = tmp->ifa_next;
                    }

                    freeifaddrs(addrs);
                }else*/ {
                    if((host=gethostbyname(optarg))<=0){
                        printf("err\n");
                        return 0;
                    }
                   
                    addr_list = (struct in_addr **)host->h_addr_list;
                    int i=0;

                    for(i = 0; addr_list[i] != NULL; i++) {
                       printf("add address %x \n",addr_list[i]->s_addr);
                        e.dst_ip=(addr_list[i]->s_addr);
                        break;
                    }
                }
                break;
            case 4:     // dst_port
                if(strcmp(optarg,"any")==0){
                    e.dst_port=0;
                }else 
                    e.dst_port=atoi(optarg);
                break;
            case 5:     // action
                if(strcmp(optarg,"null")==0)
                    e.action=SNIFFER_ACTION_NULL;
                else if(strcmp(optarg,"capture")==0)
                    e.action=SNIFFER_ACTION_CAPTURE;
                else if(strcmp(optarg,"dpi")==0)
                    e.action=SNIFFER_ACTION_DPI;
                break;
            case 6:     // dev
                dev_file=optarg;
                break;
            }
            break;
        default:
            usage();
        }
    }
    sniffer_send_command(&e);
    return 0;
}
