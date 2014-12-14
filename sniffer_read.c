#define _BSD_SOURCE
#define __FAVOR_BSD
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sniffer_ioctl.h"
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/ip.h>   /* Internet Protocol  */
#include <netinet/tcp.h>   /* Internet Protocol  */

static char * program_name;
static char * dev_file = "sniffer.dev";

static char *buf;
int outfd;

void usage() 
{
    fprintf(stderr, "Usage: %s [-i input_file] [-o output_file]\n", program_name);
    exit(EXIT_FAILURE);
}
int print_packet(char * pkt, int len)
{
    /* print format is :
     * src_ip:src_port -> dst_ip:dst_port
     * pkt[0] pkt[1] ...    pkt[64] \n
     * ...
     * where pkt[i] is a hex byte */
    int i;
    struct ip *iph = (struct ip *)(pkt);
    struct tcphdr *tcph = (struct tcphdr*)(pkt+20);
    int sp=ntohs(tcph->th_sport);
    int dp=ntohs(tcph->th_dport);
    char *sinfo = strdup(inet_ntoa(iph->ip_src));
    char *dinfo = strdup(inet_ntoa(iph->ip_dst));

    dprintf(outfd,"\n%s:%d -> %s:%d",sinfo,sp,dinfo,dp);

    for (i = 0; i < len; ++i){
        if(i % 64 == 0)dprintf(outfd,"\n");
        dprintf(outfd,"%.2x ",(unsigned char)pkt[i]);
    }
    dprintf(outfd,"\n");
    free(sinfo);
    free(dinfo);
    return 0;
}

int main(int argc, char **argv)
{
    int c;
    char *input_file, *output_file = NULL;
    program_name = argv[0];
    input_file= dev_file;

    while((c = getopt(argc, argv, "i:o:")) != -1) {
        switch (c) {
            case 'i':
                input_file =strdup(optarg);
                break;
            case 'o':
                output_file = strdup(optarg);
                outfd = open(output_file, O_WRONLY);
                if(outfd < 0){
                    printf("Can't open output file %s\n", output_file);
                    exit(1);
                }
                break;
            default:
                usage();
        }
    }
    //write("input:%s,output:%s\n",input_file,output_file);
    int fd=open(input_file,O_RDONLY);

    buf = malloc(10000*sizeof(char));
    //printf("ready\n");
    int len=-1;
    while((len = read(fd,buf,10000))>0){
        print_packet(buf,len);
    }
    if(len == -456){
        printf("One reader already exists\n");
    }
    if(len < 0 ){
        printf("Read Error\n");
    }
    if(len == 0){
        printf("No more packets\n");
    }

    free(output_file);
    free(buf);
    close(fd);
    close(outfd);
    return 0;
}
