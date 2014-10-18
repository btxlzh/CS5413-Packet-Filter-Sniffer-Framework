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
static char * program_name;
static char * dev_file = "sniffer.dev";

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
            
            break;
        case 'o':

            break;
        default:
            usage();
        }
    }
    int fd=open(input_file,O_RDONLY);
    if(fd<=0)printf("err\n");else printf("fd%x\n",fd);
    char *buf;
    read(fd,buf,0);
    return 0;
}
