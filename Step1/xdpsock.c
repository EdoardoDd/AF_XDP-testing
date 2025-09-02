#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <locale.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <math.h>

#include "bpf/libbpf.h"
#include <xdp/xsk.h>
#include <bpf/bpf.h>


#define NUM_FRAMES (4 * 1024)
#define BATCH_SIZE 64

#define DEBUG_HEXDUMP 0
#define MAX_SOCKS 8

typedef __u64 u64;
typedef __u32 u32;

#define TYPE_REQUEST  0x01		
#define TYPE_RESPONSE 0x02		  
#define TYPE_MASK     0x03		
#define GET_TYPE(type_data)     ((type_data) & TYPE_MASK)
#define SET_TYPE(type_data, t)  (((type_data) & ~TYPE_MASK) | (t))

static unsigned long prev_time;

enum benchmark_type {
        BENCH_RXPROCESS = 0,
        BENCH_TXONLY = 1,
        BENCH_ECHO = 2,
        BENCH_TXRX  = 3
};

static enum benchmark_type opt_bench = BENCH_ECHO;
static u32 opt_xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static const char *opt_if = "ens16np1";
static int opt_ifindex;
static int opt_queue = 0;
static int opt_poll;
static int opt_interval = 1;
static int opt_duration = 0;
static u32 opt_xdp_bind_flags;
static __u32 prog_id;

static uint32_t sequence_counter = 1;

// Variabili per calcolo throughput 
static unsigned long active_time =0;
static unsigned long total_received = 0;          
static unsigned long total_sent = 0;              

// rtt e jitter
static uint64_t count_rtt = 0;
static uint64_t total_rtt = 0;
static uint64_t  last_rtt  = 0;
static double jitter = 0.0;
static double total_jitter = 0;
static uint64_t min_rtt = UINT64_MAX;
static uint64_t max_rtt = 0;

struct xsk_umem_info {
        struct xsk_ring_prod fq;
        struct xsk_ring_cons cq;
        struct xsk_umem *umem;
        void *buffer;
};

struct xsk_socket_info {
        struct xsk_ring_cons rx;
        struct xsk_ring_prod tx;
        struct xsk_umem_info *umem;
        struct xsk_socket *xsk;
        unsigned long rx_npkts;
        unsigned long tx_npkts;
        unsigned long prev_rx_npkts;
        unsigned long prev_tx_npkts;
        u32 outstanding_tx;
};

static int num_socks;
struct xsk_socket_info *xsks[MAX_SOCKS];

static const char pkt_data[] =
    "\xc4\x70\xbd\x86\xb4\x8f"     // MAC dest
    "\xc4\x70\xbd\x86\xb8\xb7"     // MAC src
    "\x08\x00"                     
    
    // IP HEADER
    "\x45\x00\x00\x2c"             
    "\x00\x00\x00\x00\x40\x11"     
    "\x00\x00"                      
    "\xc0\xa8\x7b\x65"             // IP src:  192.168.123.101 (VM1)
    "\xc0\xa8\x7b\x66"             // IP dest: 192.168.123.102 (VM2)
    
    // UDP HEADER
    "\x1f\x90\x1f\x90"             // Src Port 8080 → Dst Port 8080 
    "\x00\x18\x00\x00"             
    
    // PAYLOAD 
    "\x00\x00\x00\x01"             // Seq
    "\x00\x00\x00\x00\x00\x00\x00\x00"  // Timestamp 
    "\x00\x00\x00\x01"            // Type = REQUEST

    // PADDING)
    "\x00\x00\x00\x00\x00\x00";


#define PACKET_SIZE (sizeof(pkt_data) - 1)

struct payload {
    uint32_t sequence;       
    uint64_t timestamp;     
    uint32_t type_data;     
} __attribute__((packed, aligned(4)));

static inline bool is_response(void *pkt_data)
{
    const struct payload *pl = (const struct payload*)((const char*)pkt_data + 42);
    uint32_t type_data = ntohl(pl->type_data);  // Converti da network order
    return (type_data & TYPE_MASK) == TYPE_RESPONSE;
}

static inline bool is_request(void *pkt_data) 
{
    const struct payload *pl = (const struct payload*)((const char*)pkt_data + 42);
    uint32_t type_data = ntohl(pl->type_data);  // Converti da network order
    return (type_data & TYPE_MASK) == TYPE_REQUEST;
}

static void convert_to_response(void *pkt_data)
{
    struct payload *pl = (struct payload*)((char*)pkt_data + 42);
    uint32_t type_data = ntohl(pl->type_data);  
    type_data = SET_TYPE(type_data, TYPE_RESPONSE); 
    pl->type_data = htonl(type_data);
}

static unsigned long get_nsecs(void)
{
        struct timespec ts;

        clock_gettime(CLOCK_MONOTONIC, &ts);
        return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

static void update_timestamp(void *pkt_data)
{
    struct payload *pl = (struct payload*)((char*)pkt_data + 42);
    pl->timestamp = get_nsecs(); 
}

static void print_benchmark(bool running)
{
        const char *bench_str = "INVALID";

	if (opt_bench == BENCH_RXPROCESS)
		bench_str = "rxprocess";
	else if (opt_bench == BENCH_TXONLY)
		bench_str = "txonly";
	else if (opt_bench == BENCH_ECHO)
		bench_str = "echo";
 	else if (opt_bench == BENCH_TXRX)
		bench_str = "txrx"; 

        printf("%s:%d %s ", opt_if, opt_queue, bench_str);
        if (opt_xdp_flags & XDP_FLAGS_SKB_MODE)
                printf("xdp-skb ");
        else if (opt_xdp_flags & XDP_FLAGS_DRV_MODE)
                printf("xdp-drv ");
        else
                printf("        ");

        if (opt_poll)
                printf("poll() ");

        if (running) {
                printf("running...");
                fflush(stdout);
        }
}

static void dump_stats(void)
{
        int i;
        unsigned long now = get_nsecs();
        long dt = now - prev_time;
        prev_time = now;

        for (i = 0; i < num_socks && xsks[i]; i++) {
                char *fmt = "%-15s %'-11.0f %'-11lu\n";
                double rx_pps, tx_pps;

                rx_pps = (xsks[i]->rx_npkts - xsks[i]->prev_rx_npkts) *
                         1000000000. / dt;
                tx_pps = (xsks[i]->tx_npkts - xsks[i]->prev_tx_npkts) *
                         1000000000. / dt;

                // Aggiorniamo statistiche globali per calcolo throughput
                total_sent += tx_pps;
                total_received += rx_pps;
                if(rx_pps > 0 || tx_pps > 0)
                        active_time += dt;

                printf("\n sock%d@", i);
                print_benchmark(false);
                printf("\n");

                printf("%-15s %-11s %-11s %-11.2f\n", "", "pps", "pkts",
                       dt / 1000000000.);
                printf(fmt, "rx", rx_pps, xsks[i]->rx_npkts);
                printf(fmt, "tx", tx_pps, xsks[i]->tx_npkts);

                xsks[i]->prev_rx_npkts = xsks[i]->rx_npkts;
                xsks[i]->prev_tx_npkts = xsks[i]->tx_npkts;
        }
}

static void *poller(void *arg)
{
        (void)arg;
        for (;;) {
                sleep(opt_interval);
                dump_stats();
        }

        return NULL;
}

static void remove_xdp_program(void)
{
        __u32 curr_prog_id = 0;

        if (bpf_xdp_query_id(opt_ifindex, opt_xdp_flags, &curr_prog_id)) {
                printf("bpf_xdp_query_id failed\n");
                exit(EXIT_FAILURE);
        }
        if (prog_id == curr_prog_id)
                bpf_xdp_detach(opt_ifindex, opt_xdp_flags, NULL);
        else if (!curr_prog_id)
                printf("couldn't find a prog id on a given interface\n");
        else
                printf("program on interface changed, not removing\n");
}

static void update_rtt_jitter(struct payload *pl) {
        uint64_t now = get_nsecs();
        //uint64_t sent = ntohll(pl->timestamp);
        uint64_t sent = pl->timestamp;
        
        if (sent == 0) {
                return; 
        }

        uint64_t rtt = now - sent;
        total_rtt += rtt;
        count_rtt++;

        if (rtt < min_rtt) min_rtt = rtt;
        if (rtt > max_rtt) max_rtt = rtt;

        if (last_rtt != 0) {
                int64_t delta = (int64_t)rtt - (int64_t)last_rtt;
                if (delta < 0) delta = -delta;
                jitter += ((double)delta - jitter) / 16.0;
        
                total_jitter += jitter;
        }

        last_rtt = rtt;
}

static void int_exit(int sig)
{
        struct xsk_umem *umem = xsks[0]->umem->umem;

        (void)sig;

        dump_stats();
        unsigned long now = get_nsecs();

        printf("\n=== THROUGHPUT STATISTICS ===\n");
        double elapsed_sec = active_time / 1e9;
        printf("Pacchetti inviati/s: %.3f Mpps\n", (total_sent / elapsed_sec) / 1e6);
        printf("Pacchetti ricevuti/s: %.3f Mpps\n", (total_received / elapsed_sec) / 1e6);
        printf("Throughput inviato: %.2f Mbps\n", (total_sent * PACKET_SIZE * 8.0) / (elapsed_sec * 1e6));
        printf("Throughput ricevuto: %.2f Mbps\n", (total_received * PACKET_SIZE * 8.0) / (elapsed_sec * 1e6));
        
        if (count_rtt != 0){
                double avg_rtt = (double)total_rtt / count_rtt;
                double avg_jitter = total_jitter / (count_rtt > 1 ? (count_rtt - 1) : 1);
                printf("RTT medio   = %.3f ms\n", avg_rtt / 1.0e6);
                printf("RTT minimo  = %.3f ms\n", min_rtt / 1.0e6);
                printf("RTT massimo = %.3f ms\n", max_rtt / 1.0e6);
                printf("Jitter medio = %.3f µs\n", avg_jitter / 1.0e3);
        } 

        xsk_socket__delete(xsks[0]->xsk);
        (void)xsk_umem__delete(umem);
        remove_xdp_program();

        exit(EXIT_SUCCESS);
}

static void alarm_exit(int sig)
{
    (void)sig;
    printf("\nTest completed after %lu seconds\n", opt_duration);
    int_exit(0);
}

static void __exit_with_error(int error, const char *file, const char *func,
                              int line)
{
        fprintf(stderr, "%s:%s:%i: errno: %d/\"%s\"\n", file, func,
                line, error, strerror(error));
        dump_stats();
        remove_xdp_program();
        exit(EXIT_FAILURE);
}

#define exit_with_error(error) __exit_with_error(error, __FILE__, __func__, \
                                                 __LINE__)


static void swap_addresses(void *data)
{
    struct ether_header *eth = (struct ether_header *)data;
    struct iphdr *ip = (struct iphdr *)((char*)data + 14); 

    uint64_t *src = (uint64_t*)&eth->ether_shost;
    uint64_t *dst = (uint64_t*)&eth->ether_dhost;
    uint64_t tmp = *src;
    *src = *dst;
    *dst = tmp;

    uint32_t tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;
}

static void hex_dump(void *pkt, size_t length, u64 addr)
{
        const unsigned char *address = (unsigned char *)pkt;
        const unsigned char *line = address;
        size_t line_size = 32;
        unsigned char c;
        char buf[32];
        int i = 0;

        if (!DEBUG_HEXDUMP)
                return;

        sprintf(buf, "addr=%llu", addr);
        printf("length = %zu\n", length);
        printf("%s | ", buf);
        while (length-- > 0) {
                printf("%02X ", *address++);
                if (!(++i % line_size) || (length == 0 && i % line_size)) {
                        if (length == 0) {
                                while (i++ % line_size)
                                        printf("__ ");
                        }
                        printf(" | ");  /* right close */
                        while (line < address) {
                                c = *line++;
                                printf("%c", (c < 33 || c == 255) ? 0x2E : c);
                        }
                        printf("\n");
                        if (length > 0)
                                printf("%s | ", buf);
                }
        }
        printf("\n");
}

static size_t gen_eth_frame(struct xsk_umem_info *umem, u64 addr)
{
        memcpy(xsk_umem__get_data(umem->buffer, addr), pkt_data,
               sizeof(pkt_data) - 1);
        return sizeof(pkt_data) - 1;
}

static struct xsk_umem_info *xsk_configure_umem(void *buffer, u64 size)
{
        struct xsk_umem_info *umem;
        int ret;

        umem = calloc(1, sizeof(*umem));
        if (!umem)
                exit_with_error(errno);

        ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
                               NULL);
        if (ret)
                exit_with_error(-ret);

        umem->buffer = buffer;
        return umem;
}

static struct xsk_socket_info *xsk_configure_socket(struct xsk_umem_info *umem)
{
        struct xsk_socket_config cfg;
        struct xsk_socket_info *xsk;
        int ret;
        u32 idx;
        int i;

        xsk = calloc(1, sizeof(*xsk));
        if (!xsk)
                exit_with_error(errno);

        xsk->umem = umem;
        cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
        cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
        cfg.libbpf_flags = 0;
        cfg.xdp_flags = opt_xdp_flags;
        cfg.bind_flags = opt_xdp_bind_flags;
        ret = xsk_socket__create(&xsk->xsk, opt_if, opt_queue, umem->umem,
                                 &xsk->rx, &xsk->tx, &cfg);
        if (ret)
                exit_with_error(-ret);

        ret = bpf_xdp_query_id(opt_ifindex, opt_xdp_flags, &prog_id);
        if (ret)
                exit_with_error(-ret);

        ret = xsk_ring_prod__reserve(&xsk->umem->fq,
                                     XSK_RING_PROD__DEFAULT_NUM_DESCS,
                                     &idx);
        if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
                exit_with_error(-ret);
        for (i = 0;
             i < XSK_RING_PROD__DEFAULT_NUM_DESCS *
                     XSK_UMEM__DEFAULT_FRAME_SIZE;
             i += XSK_UMEM__DEFAULT_FRAME_SIZE)
                *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx++) = i;
        xsk_ring_prod__submit(&xsk->umem->fq,
                              XSK_RING_PROD__DEFAULT_NUM_DESCS);

        return xsk;
}

static struct option long_options[] = {
        {"rxprocess", no_argument, 0, 'r'},
        {"txonly", no_argument, 0, 't'},
        {"echo", no_argument, 0, 'e'},
        {"txrx", no_argument, 0, 'x'},
        {"interface", required_argument, 0, 'i'},
        {"queue", required_argument, 0, 'q'},
        {"poll", no_argument, 0, 'p'},
        {"xdp-skb", no_argument, 0, 'S'},
        {"xdp-native", no_argument, 0, 'N'},
        {"interval", required_argument, 0, 'n'},
        {"zero-copy", no_argument, 0, 'z'},
        {"copy", no_argument, 0, 'c'},
        {"duration", required_argument, 0, 'd'},
        {0, 0, 0, 0}
};

static void usage(const char *prog)
{
        const char *str =
		"  Usage: %s [OPTIONS]\n"
		"  Options:\n"
		"  -r, --rxprocess      Process and analyze incoming packets for performance metrics\n"
		"  -t, --txonly         Only send packets for throughput testing\n"
		"  -e, --echo           Address swap + payload processing (echo server mode)\n"
		"  -x, --txrx           Bidirectional ping test with RTT measurement\n"
		"  -i, --interface=n    Run on interface n (default: ens16np1)\n"
		"  -q, --queue=n        Use queue n (default: 0)\n"
		"  -p, --poll           Use poll() syscall instead of busy polling\n"
		"  -S, --xdp-skb        Use XDP skb mode\n"
		"  -N, --xdp-native     Enforce XDP native mode\n"
		"  -n, --interval=n     Statistics update interval in seconds (default: 1)\n"
		"  -z, --zero-copy      Force zero-copy mode\n"
		"  -c, --copy           Force copy mode (default)\n"
		"  -d, --duration=n     Run for n seconds (default: infinite)\n"
		"\n"
		"  Modes:\n"
		"    rxprocess: Receive packets and calculate RTT, jitter, loss statistics\n"
		"    txonly:    Transmit packets continuously for throughput testing\n"
		"    echo:     Echo server - swap MAC/IP and respond to requests\n"
		"    txrx:      Ping client - send requests and measure response times\n"
		"\n";
        fprintf(stderr, str, prog);
        exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv)
{
        int option_index, c;

        opterr = 0;

        for (;;) {
                c = getopt_long(argc, argv, "Frtexi:q:psSNn:czR:d:", long_options,
                                &option_index);
                if (c == -1)
                        break;

                switch (c) {
                case 'r':
                        opt_bench = BENCH_RXPROCESS;
                        break;
                case 't':
                        opt_bench = BENCH_TXONLY;
                        break;
		case 'e':
			opt_bench = BENCH_ECHO;
			break;
                case 'i':
                        opt_if = optarg;
                        break;
		case 'x':                        
			opt_bench = BENCH_TXRX;
			break;
                case 'q':
                        opt_queue = atoi(optarg);
                        break;
                case 'p':
                        opt_poll = 1;
                        break;
                case 'S':
                        opt_xdp_flags |= XDP_FLAGS_SKB_MODE;
                        opt_xdp_bind_flags |= XDP_COPY;
                        break;
                case 'N':
                        opt_xdp_flags |= XDP_FLAGS_DRV_MODE;
                        break;
                case 'n':
                        opt_interval = atoi(optarg);
                        break;
                case 'z':
                        opt_xdp_bind_flags |= XDP_ZEROCOPY;
                        break;
                case 'c':
                        opt_xdp_bind_flags |= XDP_COPY;
                        break;
                case 'F':
                        opt_xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
                        break;
                case 'd':
			opt_duration = atoi(optarg);
			break;
                default:
                        usage(basename(argv[0]));
                }
        }

        opt_ifindex = if_nametoindex(opt_if);
        if (!opt_ifindex) {
                fprintf(stderr, "ERROR: interface \"%s\" does not exist\n",
                        opt_if);
                usage(basename(argv[0]));
        }

        if (opt_queue < 0) {
                fprintf(stderr, "ERROR: queue index must be >= 0\n");
                usage(basename(argv[0]));
        }
        
        if(opt_duration < 0) {
                fprintf(stderr, "ERROR: duration must be >= 0\n");
                usage(basename(argv[0]));
        }
}

static void kick_tx(struct xsk_socket_info *xsk)
{
        int ret;

        ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN || errno == EBUSY)
                return;
        exit_with_error(errno);
}

static inline void complete_tx_echo(struct xsk_socket_info *xsk)
{
	u32 idx_cq = 0, idx_fq = 0;
	unsigned int rcvd;
	size_t ndescs;

	if (!xsk->outstanding_tx)
		return;

	kick_tx(xsk);
	ndescs = (xsk->outstanding_tx > BATCH_SIZE) ? BATCH_SIZE : xsk->outstanding_tx;

	/* re-add completed Tx buffers */
	rcvd = xsk_ring_cons__peek(&xsk->umem->cq, ndescs, &idx_cq);
	if (rcvd > 0) {
		unsigned int i;
		int ret;

		ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
		while (ret != rcvd) {
			if (ret < 0)
				exit_with_error(-ret);
			ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
		}
		for (i = 0; i < rcvd; i++)
			*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = *xsk_ring_cons__comp_addr(&xsk->umem->cq, idx_cq++);

		xsk_ring_prod__submit(&xsk->umem->fq, rcvd);
		xsk_ring_cons__release(&xsk->umem->cq, rcvd);
		xsk->outstanding_tx -= rcvd;
		xsk->tx_npkts += rcvd;
	}
}

static inline void complete_tx_only(struct xsk_socket_info *xsk)
{
        unsigned int rcvd;
        u32 idx;

        if (!xsk->outstanding_tx)
                return;

        kick_tx(xsk);

        rcvd = xsk_ring_cons__peek(&xsk->umem->cq, BATCH_SIZE, &idx);
        if (rcvd > 0) {
                        xsk_ring_cons__release(&xsk->umem->cq, rcvd);
                        xsk->outstanding_tx -= rcvd;
                        xsk->tx_npkts += rcvd;
        }
}

static void rx_process(struct xsk_socket_info *xsk)
{
        unsigned int rcvd, i;
        u32 idx_rx = 0, idx_fq = 0;
        int ret;

        rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &idx_rx);
        if (!rcvd)
                return;

        ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
        while (ret != rcvd) {
                if (ret < 0)
                        exit_with_error(-ret);
                ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
        }

        for (i = 0; i < rcvd; i++) {
                u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
                u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;
                char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

                 if(is_response(pkt)) {
                        struct payload *pl = (struct payload*)((char*)pkt + 42);
                        update_rtt_jitter(pl);
                }

                hex_dump(pkt, len, addr);
                *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = addr;
        }

        xsk_ring_prod__submit(&xsk->umem->fq, rcvd);
        xsk_ring_cons__release(&xsk->rx, rcvd);
        xsk->rx_npkts += rcvd;
}

static void rx_process_all(void)
{
        struct pollfd fds[MAX_SOCKS + 1];
        int i, ret, timeout, nfds = 1;

        memset(fds, 0, sizeof(fds));

        for (i = 0; i < num_socks; i++) {
                fds[i].fd = xsk_socket__fd(xsks[i]->xsk);
                fds[i].events = POLLIN;
                timeout = 1000; /* 1sn */
        }

        for (;;) {              
                if (opt_poll) {
                        ret = poll(fds, nfds, timeout);
                        if (ret <= 0)
                                continue;
                }

                for (i = 0; i < num_socks; i++)
                        rx_process(xsks[i]);
        }
}

static void tx_only(struct xsk_socket_info *xsk)
{
        int timeout, ret, nfds = 1;
        struct pollfd fds[nfds + 1];
        u32 idx, frame_nb = 0;

        memset(fds, 0, sizeof(fds));
        fds[0].fd = xsk_socket__fd(xsk->xsk);
        fds[0].events = POLLOUT;
        timeout = 1000; // 1sn

        for (;;) {
                if (opt_poll) {
                        ret = poll(fds, nfds, timeout);
                        if (ret <= 0)
                                continue;

                        if (!(fds[0].revents & POLLOUT))
                                continue;
                }

                if (xsk_ring_prod__reserve(&xsk->tx, BATCH_SIZE, &idx) ==
                    BATCH_SIZE) {
                        unsigned int i;

                        for (i = 0; i < BATCH_SIZE; i++) {
                                u64 frame_addr = (frame_nb + i) << XSK_UMEM__DEFAULT_FRAME_SHIFT;

				void *pkt_buffer = xsk_umem__get_data(xsk->umem->buffer, frame_addr);
				struct payload *pl = (struct payload *)(pkt_buffer + 42);
                                pl->timestamp = get_nsecs();
				pl->sequence = sequence_counter++;

                                struct xdp_desc *desc = xsk_ring_prod__tx_desc(&xsk->tx, idx + i);
                                desc->addr = frame_addr;
                                desc->len =sizeof(pkt_data) - 1;
                        }

                        xsk_ring_prod__submit(&xsk->tx, BATCH_SIZE);
                        xsk->outstanding_tx += BATCH_SIZE;

                        frame_nb += BATCH_SIZE;
                        frame_nb %= NUM_FRAMES;
                }

                complete_tx_only(xsk);
        }
}

static void txrx(struct xsk_socket_info *xsk)
{
    int timeout, ret, nfds = 1;
    struct pollfd fds[nfds + 1];
    u32 idx, frame_nb = 0;

    memset(fds, 0, sizeof(fds));
    fds[0].fd = xsk_socket__fd(xsk->xsk);
    fds[0].events = POLLIN | POLLOUT;  // Monitor sia RX che TX
    timeout = 1000;

    for (;;) {
        // 1. Controllo RX
        unsigned int rcvd, i;
        u32 idx_rx = 0;

        rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &idx_rx);
        if (rcvd > 0) {
            for (i = 0; i < rcvd; i++) {
                u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
                u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;
                char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

                if (len >= 42 + sizeof(struct payload) && (is_response(pkt) || is_request(pkt))) {
			struct payload *pl = (struct payload*)((char*)pkt + 42);
			uint32_t seq = ntohl(pl->sequence);
		}
            }
            
            // Rilascia i buffer RX
            u32 idx_fq = 0;
            ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
            while (ret != rcvd) {
                if (ret < 0) exit_with_error(-ret);
                ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
            }
            
            for (i = 0; i < rcvd; i++) {
                *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = 
                    xsk_ring_cons__rx_desc(&xsk->rx, idx_rx - rcvd + i)->addr;
            }
            
            xsk_ring_prod__submit(&xsk->umem->fq, rcvd);
            xsk_ring_cons__release(&xsk->rx, rcvd);
            xsk->rx_npkts += rcvd;
        }

        // 2. Invio Tx
        if (opt_poll) {
            ret = poll(fds, nfds, timeout);
            if (ret <= 0) continue;
        }
	if (xsk_ring_prod__reserve(&xsk->tx, BATCH_SIZE, &idx) == BATCH_SIZE) {
			unsigned int i;

		for (i = 0; i < BATCH_SIZE; i++) {
			u64 addr = (frame_nb + i) << XSK_UMEM__DEFAULT_FRAME_SHIFT;
			void *pkt_buffer = xsk_umem__get_data(xsk->umem->buffer, addr);
			struct payload *pl = (struct payload *)(pkt_buffer + 42);
            	        update_timestamp(pkt_buffer);
			pl->sequence = htonl(sequence_counter++);
			xsk_ring_prod__tx_desc(&xsk->tx, idx + i)->addr = addr;
			xsk_ring_prod__tx_desc(&xsk->tx, idx + i)->len = sizeof(pkt_data) - 1;
		}
			
		xsk_ring_prod__submit(&xsk->tx, BATCH_SIZE);
		xsk->outstanding_tx += BATCH_SIZE;

                frame_nb += BATCH_SIZE;
                frame_nb %= NUM_FRAMES;	
	}
        complete_tx_only(xsk);
    }
}

static void echo_server(struct xsk_socket_info *xsk)
{
        for (;;) {
                unsigned int rcvd, i;
                u32 idx_rx = 0, idx_tx = 0;
                int ret;

                for (;;) {
                        complete_tx_echo(xsk);

                        rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE,
                                                   &idx_rx);
                        if (rcvd > 0)
                                break;
                }

                ret = xsk_ring_prod__reserve(&xsk->tx, rcvd, &idx_tx);
                while (ret != rcvd) {
                        if (ret < 0)
                                exit_with_error(-ret);
                        ret = xsk_ring_prod__reserve(&xsk->tx, rcvd, &idx_tx);
                }

                for (i = 0; i < rcvd; i++) {
                        u64 addr = xsk_ring_cons__rx_desc(&xsk->rx,
                                                          idx_rx)->addr;
                        u32 len = xsk_ring_cons__rx_desc(&xsk->rx,
                                                         idx_rx++)->len;
                        char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

                        swap_addresses(pkt);
			if (is_request(pkt)){
                                convert_to_response(pkt);
                        }

		
                        hex_dump(pkt, len, addr);
                        xsk_ring_prod__tx_desc(&xsk->tx, idx_tx)->addr = addr;
                        xsk_ring_prod__tx_desc(&xsk->tx, idx_tx++)->len = len;
                }

                xsk_ring_prod__submit(&xsk->tx, rcvd);
                xsk_ring_cons__release(&xsk->rx, rcvd);

                xsk->rx_npkts += rcvd;
                xsk->outstanding_tx += rcvd;

        }
}

int main(int argc, char **argv)
{
        struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
        struct xsk_umem_info *umem;
        pthread_t pt;
        void *bufs;
        int ret;

        parse_command_line(argc, argv);

        if (setrlimit(RLIMIT_MEMLOCK, &r)) {
                fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
                        strerror(errno));
                exit(EXIT_FAILURE);
        }

        ret = posix_memalign(&bufs, getpagesize(), /* PAGE_SIZE aligned */
                             NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);
        if (ret)
                exit_with_error(ret);

        umem = xsk_configure_umem(bufs,
                                  NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);
        xsks[num_socks++] = xsk_configure_socket(umem);

        if (opt_bench == BENCH_TXONLY) {
                int i;

                for (i = 0; i < NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE;
                     i += XSK_UMEM__DEFAULT_FRAME_SIZE)
                        (void)gen_eth_frame(umem, i);
        }

        signal(SIGINT, int_exit);
        signal(SIGTERM, int_exit);
        signal(SIGABRT, int_exit);

        if (opt_duration > 0) {
                signal(SIGALRM, alarm_exit);
                alarm(opt_duration);
        }       

        setlocale(LC_ALL, "");

        ret = pthread_create(&pt, NULL, poller, NULL);
        if (ret)
                exit_with_error(ret);

        prev_time = get_nsecs();

        if (opt_bench == BENCH_RXPROCESS)
                rx_process_all();
        else if (opt_bench == BENCH_TXONLY)
                tx_only(xsks[0]);
        else if (opt_bench == BENCH_TXRX) {
		printf("Starting TXRX mode with shared socket\n");
		txrx(xsks[0]);
	}
        else
                echo_server(xsks[0]);

        return 0;
}