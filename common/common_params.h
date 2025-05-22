#ifndef __COMMON_PARAMS_H
#define __COMMON_PARAMS_H

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <xdp/xsk.h>

struct config {
    int ifindex;          
    char *ifname;         
    char filename[512];   
    char progname[32];    
    int xsk_if_queue;     
    bool xsk_poll_mode;   
    int xdp_flags;        
    int xsk_bind_flags;   
    bool verbosity;        
    bool unload_all;       
    
    bool performance_mode; 
    int test_duration;     
    int packet_size;       
    int packet_rate;       
};

extern struct config cfg;


void usage(const char *prog_name, const char *doc);
void parse_cmdline_args(int argc, char **argv, const char *doc);

extern struct option long_options[];

#endif 
