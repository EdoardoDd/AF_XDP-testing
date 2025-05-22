/**
 * common_params.c - Funzioni per il parsing dei parametri da linea di comando
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <errno.h>

#include <net/if.h>
#include <linux/if_link.h> 
#include <linux/if_xdp.h>

#include "common_params.h"

extern const char *__doc__;

struct config cfg = {
    .ifindex = -1,
    .xsk_if_queue = 0,
    .xdp_flags = XDP_FLAGS_DRV_MODE,
    .xsk_bind_flags = XDP_COPY,
    .verbosity = true,
    .unload_all = false,
};


struct option long_options[] = {
    {"help",       no_argument,       NULL, 'h'},
    {"dev",        required_argument, NULL, 'd'},
    {"skb-mode",   no_argument,       NULL, 'S'},
    {"native-mode",no_argument,       NULL, 'N'},
    {"auto-mode",  no_argument,       NULL, 'A'},
    {"force",      no_argument,       NULL, 'F'},
    {"copy",       no_argument,       NULL, 'c'},
    {"zero-copy",  no_argument,       NULL, 'z'},
    {"queue",      required_argument, NULL, 'Q'},
    {"poll-mode",  no_argument,       NULL, 'p'},
    {"quiet",      no_argument,       NULL, 'q'},
    {"filename",   required_argument, NULL, 1},
    {"progname",   required_argument, NULL, 2},
    {"perf-mode",  no_argument,       NULL, 'P'},
    {"duration",   required_argument, NULL, 't'},
    {"packetsize", required_argument, NULL, 's'},
    {"rate",       required_argument, NULL, 'r'},
    {0, 0, NULL, 0}
};


void usage(const char *prog_name, const char *doc)
{
    printf("Usage: %s [options]\n", prog_name);
    printf("\nDOC:\n %s\n", doc);
    printf("\n");
    printf(" Options:\n");
    printf("  --help, -h       : Show this help\n");
    printf("  --dev, -d        : Operate on device <ifname>\n");
    printf("  --skb-mode, -S   : Install XDP program in SKB mode\n");
    printf("  --native-mode, -N: Install XDP program in native mode\n");
    printf("  --auto-mode, -A  : Auto-detect SKB or native mode\n");
    printf("  --force, -F      : Force install, replacing existing program\n");
    printf("  --copy, -c       : Force copy mode\n");
    printf("  --zero-copy, -z  : Force zero-copy mode\n");
    printf("  --queue, -Q      : Configure interface receive queue for AF_XDP\n");
    printf("  --poll-mode, -p  : Use poll() API waiting for packets\n");
    printf("  --quiet, -q      : Quiet mode (no output)\n");
    printf("  --filename       : Load program from <file>\n");
    printf("  --progname       : Load program from function <name> in ELF file\n");
    printf("  --perf-mode, -P  : Run in performance test mode\n");
    printf("  --duration, -t   : Test duration in seconds (default: 10)\n");
    printf("  --packetsize, -s : Packet size in bytes (default: 64)\n");
    printf("  --rate, -r       : Packet rate in pps (default: 1000, 0 = max)\n");
}


void parse_cmdline_args(int argc, char **argv, const char *doc){
    int c, option_index;

    while ((c = getopt_long(argc, argv, "hd:SNAFczQ:pqPt:s:r:", long_options, &option_index)) != -1) {
        switch (c) {
        case 'd': // --dev 
            if (strlen(optarg) >= IF_NAMESIZE) {
                fprintf(stderr, "ERR: --dev name too long\n");
                exit(EXIT_FAILURE); 
            }
            cfg.ifname = optarg;
            cfg.ifindex = if_nametoindex(cfg.ifname);
            if (cfg.ifindex == 0) {
                fprintf(stderr, "ERR: --dev name unknown err(%d):%s\n",
                    errno, strerror(errno));
                exit(EXIT_FAILURE); 
            }
            break;
        case 'S': // --skb-mode 
            cfg.xdp_flags &= ~XDP_FLAGS_MODES;
            cfg.xdp_flags |= XDP_FLAGS_SKB_MODE;
            break;
        case 'N': // --native-mode 
            cfg.xdp_flags &= ~XDP_FLAGS_MODES;
            cfg.xdp_flags |= XDP_FLAGS_DRV_MODE;
            break;
        case 'A': // --auto-mode 
            cfg.xdp_flags &= ~XDP_FLAGS_MODES;
            break;
        case 'F': // --force 
            cfg.xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
            break;
        case 'c': // --copy 
            cfg.xsk_bind_flags &= ~XDP_ZEROCOPY;
            cfg.xsk_bind_flags |= XDP_COPY;
            break;
        case 'z': // --zero-copy 
            cfg.xsk_bind_flags &= ~XDP_COPY;
            cfg.xsk_bind_flags |= XDP_ZEROCOPY;
            break;
        case 'Q': // --queue 
            cfg.xsk_if_queue = atoi(optarg);
            break;
        case 'p': // --poll-mode 
            cfg.xsk_poll_mode = true;
            break;
        case 'q': // --quiet 
            cfg.verbosity = false;
            break;
        case 1: // --filename 
            strncpy(cfg.filename, optarg, sizeof(cfg.filename) - 1);
            cfg.filename[sizeof(cfg.filename) - 1] = '\0';
            break;
        case 2: // --progname 
            strncpy(cfg.progname, optarg, sizeof(cfg.progname) - 1);
            cfg.progname[sizeof(cfg.progname) - 1] = '\0';
            break;
        case 'P': // --perf-mode
            cfg.performance_mode = true;
            break;
        case 't': // --duration
            cfg.test_duration = atoi(optarg);
            if (cfg.test_duration <= 0) {
                fprintf(stderr, "WARNING: Invalid test duration, using default (10 sec)\n");
                cfg.test_duration = 10;
            }
            break;
        case 's': // --packetsize
            cfg.packet_size = atoi(optarg);
            if (cfg.packet_size < 64 || cfg.packet_size > 1500) {
                fprintf(stderr, "WARNING: Invalid packet size, using default (64 bytes)\n");
                cfg.packet_size = 64;
            }
            break;
        case 'r': // --rate
            cfg.packet_rate = atoi(optarg);
            if (cfg.packet_rate < 0) {
                fprintf(stderr, "WARNING: Invalid packet rate, using default (1000 pps)\n");
                cfg.packet_rate = 1000;
            }
            break;

        case 'h': // --help 
        default:
            usage(argv[0], doc); 
            exit(c == 'h' ? EXIT_SUCCESS : EXIT_FAILURE);
        }
    }

    if (cfg.performance_mode) {
    printf("Performance test mode enabled with the following parameters:\n");
    printf("  Duration: %d seconds\n", cfg.test_duration);
    printf("  Packet size: %d bytes\n", cfg.packet_size);
    printf("  Packet rate: %d pps%s\n", 
           cfg.packet_rate, 
           cfg.packet_rate == 0 ? " (maximum)" : "");
    }
}

