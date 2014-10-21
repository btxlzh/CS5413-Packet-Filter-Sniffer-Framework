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
static char * program_name;
static char * dev_file = "sniffer.dev";
void usage() 
{
    fprintf(stderr, "Usage: %s [-i input_file] [-o output_file]\n", program_name);
    exit(EXIT_FAILURE);
}
int outfd;
int print_packet(char * pkt, int len)
{
    /* print format is :
     * src_ip:src_port -> dst_ip:dst_port
     * pkt[0] pkt[1] ...    pkt[64] \n
     * ...
     * where pkt[i] is a hex byte */
    int i,ip_size;
    struct zl_ip *ip_h =pkt;
    ip_size=IP_HL(ip_h)*4;
    struct zl_tcp *tcp_h = pkt+ip_size;
    int sp=0,dp=0;
    sp=ntohs(tcp_h->th_sport);
    dp=ntohs(tcp_h->th_dport);
    struct in_addr a;
    a.s_addr=ip_h->ip_src;
    char *sinfo = strdup(inet_ntoa(a));
    a.s_addr=ip_h->ip_dst;
    char *dinfo = strdup(inet_ntoa(a));
    
    printf("%s:%d -> %s:%d",sinfo,sp,dinfo,dp);
    
    for(i = 0; i < len; ++i){
        if(i % 64 == 0)printf("\n");
        printf("%.2x ",(unsigned char)pkt[i]);
    }
    printf("\n");
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
                break;
            default:
                usage();
        }
    }
    //write("input:%s,output:%s\n",input_file,output_file);
    int fd=open(input_file,O_RDONLY);
    if(output_file) 
         freopen(output_file,"w",stdout);
    char *buf = malloc(4096*sizeof(char));
    printf("ready\n");
    int len=-1;
    while((len = read(fd,buf,0))>0){
        print_packet(buf,len);
    }
    return 0;
}
