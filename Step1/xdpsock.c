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


#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#define NUM_FRAMES (8 * 1024)		
#define BATCH_SIZE 64				

#define DEBUG_HEXDUMP 0
#define MAX_SOCKS 8

// Type field nel LSB di type_data
#define TYPE_REQUEST  0x01		// 00000001
#define TYPE_RESPONSE 0x02		// 00000010  
#define TYPE_MASK     0x03		// 00000011

// Macro per gestire il type
#define GET_TYPE(type_data)     ((type_data) & TYPE_MASK)
#define SET_TYPE(type_data, t)  (((type_data) & ~TYPE_MASK) | (t))
#define GET_DATA(type_data)     ((type_data) >> 2)
#define SET_DATA(type_data, d)  (((d) << 2) | ((type_data) & TYPE_MASK))

// Variabili globali per statistiche RTT
static unsigned long total_responses = 0;
static double total_rtt_ms = 0.0;
static double min_rtt_ms = 999999.0;
static double max_rtt_ms = 0.0;

// Variabili per statistiche loss e out-of-order
static uint32_t total_sent = 0;        
static uint32_t total_received = 0;    
static uint32_t out_of_order = 0;  
static uint32_t last_seq_received = 0;    

// Variabili per calcolo jitter
static double prev_rtt_ms = 0.0;       					
static double total_jitter_ms = 0.0;   					// Jitter totale accumulato
static unsigned long jitter_samples = 0;				// Num di campioni di jitter	

// Variabili per throughput
static unsigned long throughput_start_time = 0;  		// Tempo inizio per calcolo finale
static unsigned long throughput_bytes_sent = 0;  		
static unsigned long throughput_bytes_received = 0; 	

typedef __u64 u64;
typedef __u32 u32;

static int opt_rate_pps = 0;

static unsigned long prev_time;
static uint32_t sequence_counter = 1; // Contatore per il numero di sequenza

enum benchmark_type {
	BENCH_RXPROCESS = 0,
	BENCH_TXONLY = 1,
	BENCH_ECHO  = 2,		// era BENCH_L2FWD
	BENCH_TXRX  = 3			// TODO Elimin questa modalità
};

static enum benchmark_type opt_bench = BENCH_ECHO;                 
static u32 opt_xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static const char *opt_if = "enp18s0";								// default interface	
static int opt_ifindex;
static int opt_queue = 0;                     						// Default queue 0
static int opt_poll;
static int opt_interval = 1;
static int opt_duration = 0;									// Default 0 (infinite)		
static u32 opt_xdp_bind_flags = XDP_COPY;						// Default: copy mode
static __u32 prog_id;

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
    // === ETHERNET HEADER ===
/*     "\x22\x44\x19\xe0\x4e\xd7"     // MAC dest 			
    "\x4a\x3c\xb9\x2e\x89\xee"     // MAC src */
	"\x52\x54\x00\xbd\x25\x01"     // MAC dest rete virtuale (52:54:00:bd:25:01)
    "\x52\x54\x00\x06\xfb\x6f"     // MAC src rete virtuale (52:54:00:06:fb:6f)
    "\x08\x00"                     // EtherType
    
    // === IP HEADER ===
    "\x45\x00\x00\x2c"             // Version + IHL + ToS + Length(58)
    "\x00\x00\x00\x00\x40\x11"     // ID + Flags + TTL + Protocol
    "\x00\x00"                     // Checksum 
/*     "\xc0\xa8\x38\x67"             // IP source (192.168.56.103)	- VM 1
    "\xc0\xa8\x38\x68"             // IP dest (192.168.56.104)		- VM 2 */
	"\xc0\xa8\x7b\x67"             // IP src:  192.168.123.103 (VM1)
    "\xc0\xa8\x7b\x68"             // IP dest: 192.168.123.104 (VM2)
    
    // === UDP HEADER ===
    "\x1f\x90\x1f\x90"             // Port 12345 → 67890 
    "\x00\x18\x00\x00"             // Length(24) + Checksum(0)
    
    // === PAYLOAD (16 bytes) ===
    "\x00\x00\x00\x01"             // Sequence = 1
    "\x00\x00\x00\x00\x00\x00\x00\x00"  // Timestamp = 0 (aggiornato runtime)
    "\x00\x00\x00\x01";            // Type = REQUEST


/* 
TODO:
- [ ] Capire se è conveniente usare più code per TX
- [ ] Verifica se è più conveniente usare busy polling o poll()
- [ ] Controlla con quale logica pinnare le socket ai core
Parte di Prestazioni:
- [ ]Avevamo errore di rtt troppo alto quando chiudo la connessione, correggi e vedi se c'è ancora
- [ ] Fai confronto con socket UDP normali per le prestazioni
- [ ] Potremmo fare confronto con solo AF_XDP che fa solo modifica MAC e IP, senza elaborazione payload. Secondo me ci sta.
		- [ ] Aggiungere nel report anche la dimensione del pacchetto che stiamo inviando, calcolando il limite teorico per la NIC
		- [ ] Verifica se aumentando dimensione del pacchetto aumenta il throughput 
*/

struct payload {
    uint32_t sequence;      // Numero sequenza (4 bytes)
    uint64_t timestamp;     // Timestamp invio (8 bytes)  
    uint32_t type_data;     // Type + dati (4 bytes)
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

// Calcola RTT (quando ricevi response)
static double calculate_rtt_ms(void *pkt_data)
{
    struct payload *pl = (struct payload*)((char*)pkt_data + 42);
    unsigned long now = get_nsecs();			// get_nsecs da tempo relativo all'avvio della macchina
										// NON ASSOLUTO, invio e ricezione devono esssere sulla stessa macchina			
    unsigned long sent_time = pl->timestamp	;
    return (double)(now - sent_time) / 1000000.0;  // ns → ms
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
		printf("	");

	if (opt_poll)
		printf("poll() ");

	if (running) {
		printf("running...");
		fflush(stdout);
	}
}

static void dump_stats(void)
{
	unsigned long now = get_nsecs();
	long dt = now - prev_time;
	int i;

	prev_time = now;

	for (i = 0; i < num_socks && xsks[i]; i++) {
		char *fmt = "%-15s %'-11.0f %'-11lu\n";
		double rx_pps, tx_pps;

		rx_pps = (xsks[i]->rx_npkts - xsks[i]->prev_rx_npkts) *
			 1000000000. / dt;
		tx_pps = (xsks[i]->tx_npkts - xsks[i]->prev_tx_npkts) *
			 1000000000. / dt;

		printf("\n sock%d@", i);
		print_benchmark(false);
		printf("\n");

		printf("%-15s %-11s %-11s %-11s %-11s\n", "", "pps", "pkts", "Mbps", dt / 1000000000.);
		printf("%-15s %'-11.0f %'-11lu %-11.2f\n", "rx", rx_pps, xsks[i]->rx_npkts, rx_mbps);
		printf("%-15s %'-11.0f %'-11lu %-11.2f\n", "tx", tx_pps, xsks[i]->tx_npkts, tx_mbps);
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

static void int_exit(int sig)
{
    struct xsk_umem *umem = xsks[0]->umem->umem;

    (void)sig;

    dump_stats();
    if ((opt_bench == BENCH_RXPROCESS || opt_bench == BENCH_TXRX ) && total_responses > 0) {
        double avg_rtt = total_rtt_ms / total_responses;
		double loss_rate = 0.0;
        
        if (total_sent > 0) {
            loss_rate = ((double)(total_sent - total_received) / total_sent) * 100.0;
        }

		// Calcola throughput finale
    	unsigned long test_duration_ns = get_nsecs() - throughput_start_time;
    	double test_duration_sec = test_duration_ns / 1000000000.0;
    
    	double final_tx_pps = total_sent / test_duration_sec;
    	double final_rx_pps = total_received / test_duration_sec;
    	double final_tx_mbps = (throughput_bytes_sent * 8.0) / (test_duration_sec * 1000000.0);
    	double final_rx_mbps = (throughput_bytes_received * 8.0) / (test_duration_sec * 1000000.0);
		printf("\n=== THROUGHPUT STATISTICS ===\n");
		printf("Test duration:   %.1f seconds\n", test_duration_sec);
		printf("TX Rate:         %.0f pps (%.2f Mbps)\n", final_tx_pps, final_tx_mbps);
		printf("RX Rate:         %.0f pps (%.2f Mbps)\n", final_rx_pps, final_rx_mbps);
		printf("Packet size:     %d bytes\n", PACKET_SIZE);
        printf("\n=== PERFORMANCE STATISTICS ===\n");
        printf("Total sent:      %u packets\n", total_sent);
        printf("Total received:  %u packets\n", total_received);
        printf("Packet loss:     %.2f%% (%u lost)\n", loss_rate, total_sent - total_received);
        printf("Out-of-order:    %u packets\n", out_of_order);
        printf("\n=== RTT STATISTICS ===\n");
        printf("Total responses: %lu\n", total_responses);
        printf("Average RTT:     %.3f ms\n", avg_rtt);
        printf("Minimum RTT:     %.3f ms\n", min_rtt_ms);
        printf("Maximum RTT:     %.3f ms\n", max_rtt_ms); 	    

		if (jitter_samples > 0) {
			double avg_jitter = total_jitter_ms / jitter_samples;
			printf("Average Jitter:  %.3f ms\n", avg_jitter);
		} else {
			printf("Average Jitter:  N/A (insufficient samples)\n");
		}
	}

    xsk_socket__delete(xsks[0]->xsk);
    (void)xsk_umem__delete(umem);
    remove_xdp_program();

    exit(EXIT_SUCCESS);
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


/* static unsigned short ip_checksum(struct iphdr *ip)
{
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t*)ip;
    int len = ip->ihl * 4; // lunghezza header in bytes
    
    // Azzera il checksum prima del calcolo
    ip->check = 0;
    
    // Somma tutti i 16-bit words
    while (len > 1) {
        sum += ntohs(*ptr++);
        len -= 2;
    }
    
    // Aggiungi eventuale byte rimasto
    if (len > 0)
        sum += (ntohs(*(uint8_t*)ptr) << 8);
    
    // Aggiungi carry
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    
    return htons(~sum);
} */

/* static uint16_t udp_checksum(struct iphdr *ip, struct udphdr *udp, void *data, int datalen)
{
	    // Crea un buffer temporaneo con pseudo-header + UDP
    uint16_t pseudo_header[6];  // 12 bytes
    uint32_t sum = 0;
    
    // Pseudo-header
    pseudo_header[0] = ip->saddr >> 16;        // IP src high
    pseudo_header[1] = ip->saddr & 0xFFFF;     // IP src low  
    pseudo_header[2] = ip->daddr >> 16;        // IP dst high
    pseudo_header[3] = ip->daddr & 0xFFFF;     // IP dst low
    pseudo_header[4] = htons(IPPROTO_UDP);     // Protocol
    pseudo_header[5] = udp->len;               // UDP length
    
    // Somma pseudo-header
    for (int i = 0; i < 6; i++) {
        sum += ntohs(pseudo_header[i]);
    }
    
    // Azzera checksum UDP
    udp->check = 0;
    
    // Somma UDP header + data
    uint16_t *ptr = (uint16_t*)udp;
    int total_len = ntohs(udp->len);  // 8 + 16 = 24 bytes
    
    while (total_len > 1) {
        sum += ntohs(*ptr++);
        total_len -= 2;
    }
    
    if (total_len > 0) {
        sum += (*(uint8_t*)ptr) << 8;
    }
    
    // Fold carry
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return htons(~sum);
} */

static void swap_addresses(void *data)
{
	struct ether_header *eth = (struct ether_header *)data;
	struct iphdr *ip = (struct iphdr *)((char*)data + 14); 
	// struct udphdr *udp = (struct udphdr *)((char*)data + 34);
	// struct payload *pl = (struct payload *)((char*)data + 42);

	// Swap MAC
/*     struct ether_addr tmp_mac;
    tmp_mac = *(struct ether_addr*)&eth->ether_shost;
    *(struct ether_addr*)&eth->ether_shost = *(struct ether_addr*)&eth->ether_dhost;
    *(struct ether_addr*)&eth->ether_dhost = tmp_mac; */

	uint64_t *src = (uint64_t*)&eth->ether_shost;
    uint64_t *dst = (uint64_t*)&eth->ether_dhost;
    uint64_t tmp = *src;
    *src = *dst;
    *dst = tmp;

	// Swap anche gli IP 
	uint32_t tmp_ip = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp_ip;
	


	// Ricalcola checksum per nuovo routing
	// ip->check = 0;
	// ip->check = ip_checksum(ip);  // Funzione da aggiungere se serve

	// Ricalcola checksum UDP
	// udp->check = 0; 
	// udp->check = udp_checksum(ip, udp, pl, sizeof(struct payload));
}

static struct option long_options[] = {
	{"rxprocess", no_argument, 0, 'r'},
	{"txonly", no_argument, 0, 't'},
	{"echo", no_argument, 0, 'l'},
	{"txrx", no_argument, 0, 'x'},
	{"interface", required_argument, 0, 'i'},
	{"queue", required_argument, 0, 'q'},
	{"poll", no_argument, 0, 'p'},
	{"xdp-skb", no_argument, 0, 'S'},
	{"xdp-native", no_argument, 0, 'N'},
	{"interval", required_argument, 0, 'n'},
	{"zero-copy", no_argument, 0, 'z'},
	{"copy", no_argument, 0, 'c'},
	{"rate", required_argument, 0, 'R'},
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
		"  -l, --echo           Address swap + payload processing (echo server mode)\n"
		"  -x, --txrx           Bidirectional ping test with RTT measurement\n"
		"  -i, --interface=n    Run on interface n (default: enp18s0)\n"
		"  -q, --queue=n        Use queue n (default: 0)\n"
		"  -p, --poll           Use poll() syscall instead of busy polling\n"
		"  -S, --xdp-skb        Use XDP skb mode\n"
		"  -N, --xdp-native     Enforce XDP native mode\n"
		"  -n, --interval=n     Statistics update interval in seconds (default: 1)\n"
		"  -z, --zero-copy      Force zero-copy mode\n"
		"  -c, --copy           Force copy mode (default)\n"
		"  -R, --rate=n         Specify TX rate in packets per second (for txrx mode)\n"
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
		c = getopt_long(argc, argv, "Frtexi:q:psSNn:czR:d:", long_options, &option_index);
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
		case 'x':                        
			opt_bench = BENCH_TXRX;
			break;
		case 'i':
			opt_if = optarg;
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
			if (opt_duration <= 0) {
				fprintf(stderr, "ERROR: duration must be > 0\n");
				usage(basename(argv[0]));
			}
			break;
		case 'R':
			opt_rate_pps = atoi(optarg);
			if (opt_rate_pps <= 0) {
				fprintf(stderr, "ERROR: rate must be > 0\n");
				usage(basename(argv[0]));
			}
			break;
		default:
			usage(basename(argv[0]));
		}
	}

	opt_ifindex = if_nametoindex(opt_if);
	if (!opt_ifindex || strlen(opt_if) == 0) {
		fprintf(stderr, "ERROR: interface \"%s\" does not exist\n",
			opt_if);
		usage(basename(argv[0]));
	}

    // Controllo che la coda sia >= 0
    if (opt_queue < 0) {
        fprintf(stderr, "ERROR: queue index must be >= 0\n");
        usage(basename(argv[0]));
    }

    if (!opt_ifindex) {
        fprintf(stderr, "ERROR: interface \"%s\" does not exist\n",
            opt_if);
        usage(basename(argv[0]));
    }
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
			printf(" | ");	/* right close */
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

/* static size_t gen_eth_frame(struct xsk_umem_info *umem, u64 addr)
{
	memcpy(xsk_umem__get_data(umem->buffer, addr), pkt_data,
	       sizeof(pkt_data) - 1);

	char *pkt = (char *)xsk_umem__get_data(umem->buffer, addr);
	struct payload *pl = (struct payload *)(pkt + 42);		// Skip Eth + IP
    // struct iphdr *ip = (struct iphdr *)(pkt + 14);			// Skip Ethernet
	// struct udphdr *udp = (struct udphdr *)(pkt + 34);  		// Skip Eth + IP
	 
	// Aggiorna sequence
    pl->sequence = htonl(sequence_counter++);

	// IP Checksum
	// ip->check = ip_checksum(ip);  

	// UDP Checksum
	// udp->check = udp_checksum(ip, udp, pl, sizeof(struct payload));
	return sizeof(pkt_data) - 1;
}  */

static void gen_eth_frame(struct xsk_umem_info *umem, u64 addr)
{
	memcpy(xsk_umem__get_data(umem->buffer, addr), pkt_data, sizeof(pkt_data) - 1);
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
	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS *XSK_UMEM__DEFAULT_FRAME_SIZE; i += XSK_UMEM__DEFAULT_FRAME_SIZE)
		*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx++) = i;
	xsk_ring_prod__submit(&xsk->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

	return xsk;
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
		
		if (len >= 42 + sizeof(struct payload) && (is_response(pkt) || is_request(pkt))) {
			double rtt = calculate_rtt_ms(pkt);    
			struct payload *pl = (struct payload*)((char*)pkt + 42);
			uint32_t seq = ntohl(pl->sequence);

			throughput_bytes_received += PACKET_SIZE;
			
			// tracking packet loss
			total_received++;
			if (seq <= last_seq_received && seq != 0) {
				printf("WARNING: Out of order packet seq=%u (last=%u)\n", seq, last_seq_received);
				out_of_order++;
			} else {
				last_seq_received = seq;
			}
			
			// tracking RTT and jitter
			if (prev_rtt_ms > 0.0) {  // salta il primo pacchetto
				double jitter = fabs(rtt - prev_rtt_ms);
				total_jitter_ms += jitter;
				jitter_samples++;
			}
			prev_rtt_ms = rtt;

			total_responses++;
			total_rtt_ms += rtt;

			if (rtt < min_rtt_ms) {
				min_rtt_ms = rtt;
				printf("New min RTT: %.3f ms (seq=%u)\n", rtt, seq);
			}
			if (rtt > max_rtt_ms) {
				max_rtt_ms = rtt;
				printf("New max RTT: %.3f ms (seq=%u)\n", rtt, seq);
			}
			
			// Debug ogni 100 pacchetti
			if (total_responses % 100 == 0) {
				printf("Response seq=%u RTT=%.3f ms (total: %lu)\n", seq, rtt, total_responses);
			}
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
		timeout = 1000; // 1sn
	}

	for (;;) {
		if (opt_duration > 0) {
            unsigned long elapsed = (get_nsecs() - throughput_start_time) / 1000000000UL;
            if (elapsed >= opt_duration) {
                printf("\nTest completed after %lu seconds\n", elapsed);
                int_exit(0);
            }
        }

		if (opt_poll) {
			ret = poll(fds, nfds, timeout);
			if (ret <= 0)
				continue;
		}

		for (i = 0; i < num_socks; i++)
			rx_process(xsks[i]);
	}
} 

static void echo_server(struct xsk_socket_info *xsk)			// Era l2fwd
{
	for (;;) {
		if (opt_duration > 0) {
            unsigned long elapsed = (get_nsecs() - throughput_start_time) / 1000000000UL;
            if (elapsed >= opt_duration) {
                printf("\nTest completed after %lu seconds\n", elapsed);
                int_exit(0);
            }
        }
		unsigned int rcvd, i;
		u32 idx_rx = 0, idx_tx = 0;
		int ret;

		for (;;) {
			complete_tx_echo(xsk);

			rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &idx_rx);
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
			u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
			u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;
			char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

			// Controllo lunghezza minima (Ethernet + IP + UDP + payload)
/*  		if (len < 42 + sizeof(struct payload)) {
				fprintf(stderr, "Packet too short: %u bytes (expected at least %zu)\n", len, 42 + sizeof(struct payload));
				continue;
			} */

			swap_addresses(pkt);

			if (is_request(pkt)) {
				// struct payload *pl = (struct payload*)((char*)pkt + 42);
				// uint32_t seq =  ntohl(pl->sequence);
				// printf("Server: REQ seq=%u → RSP\n", seq);
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
		if (opt_duration > 0) {
			unsigned long elapsed = (get_nsecs() - throughput_start_time) / 1000000000UL;
			if (elapsed >= opt_duration) {
				printf("\nTest completed after %lu seconds\n", elapsed);
				int_exit(0);
			}
        }

		if (opt_poll) {
			ret = poll(fds, nfds, timeout);
			if (ret <= 0)
				continue;

			if (!(fds[0].revents & POLLOUT))
				continue;
		}

		if (xsk_ring_prod__reserve(&xsk->tx, BATCH_SIZE, &idx) == BATCH_SIZE) {
			unsigned int i;

			for (i = 0; i < BATCH_SIZE; i++) {
				u64 addr = (frame_nb + i) << XSK_UMEM__DEFAULT_FRAME_SHIFT;
				void *pkt_buffer = xsk_umem__get_data(xsk->umem->buffer, addr);
				struct payload *pl = (struct payload *)(pkt_buffer + 42);
            	update_timestamp(pkt_buffer);
				// pl->timestamp = get_nsecs();
				pl->sequence = htonl(sequence_counter++);

				xsk_ring_prod__tx_desc(&xsk->tx, idx + i)->addr = addr;
				xsk_ring_prod__tx_desc(&xsk->tx, idx + i)->len = sizeof(pkt_data) - 1;
			}
			
			xsk_ring_prod__submit(&xsk->tx, BATCH_SIZE);
			xsk->outstanding_tx += BATCH_SIZE;
			total_sent += BATCH_SIZE;							// tracking packet loss 
			throughput_bytes_sent += BATCH_SIZE * PACKET_SIZE;  // Aggiorna throughput
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
    
    // Rate limiting per test controllato
    int delay_us = 0;
    if (opt_rate_pps > 0) {
        delay_us = (1000000 * BATCH_SIZE) / opt_rate_pps;  // Delay tra singoli pacchetti
        printf("TXRX ping test at %d pps (delay %d μs)\n", opt_rate_pps, delay_us);
    } 

    memset(fds, 0, sizeof(fds));
    fds[0].fd = xsk_socket__fd(xsk->xsk);
    fds[0].events = POLLIN | POLLOUT;  // Monitor sia RX che TX
    timeout = 1000;

    printf("Starting ping test - sending requests and measuring RTT...\n");

    for (;;) {
		if (opt_duration > 0) {
            unsigned long elapsed = (get_nsecs() - throughput_start_time) / 1000000000UL;
            if (elapsed >= opt_duration) {
                printf("\nTest completed after %lu seconds\n", elapsed);
                int_exit(0);
            }
        }
        // 1. CONTROLLA RX PRIMA (ricevi eventuali response)
        unsigned int rcvd, i;
        u32 idx_rx = 0;

        rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &idx_rx);
        if (rcvd > 0) {
            // Processo response ricevute
            for (i = 0; i < rcvd; i++) {
                u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
                u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;
                char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

                if (len >= 42 + sizeof(struct payload) && is_response(pkt)) {
                    double rtt = calculate_rtt_ms(pkt);
                    struct payload *pl = (struct payload*)((char*)pkt + 42);
                    uint32_t seq = ntohl(pl->sequence);

					// tracking packet loss
					total_received++;
					throughput_bytes_received += PACKET_SIZE;
					if (seq <= last_seq_received && seq != 0) {
						printf("WARNING: Out of order packet seq=%u (last=%u)\n", seq, last_seq_received);
						out_of_order++;
					} else {
						last_seq_received = seq;
					}
                    
					// tracking RTT and jitter
					if (prev_rtt_ms > 0.0) {  // Salta il primo pacchetto  
						double jitter = fabs(rtt - prev_rtt_ms);
						total_jitter_ms += jitter;
						jitter_samples++;
					}
					prev_rtt_ms = rtt;

					total_responses++;
                    total_rtt_ms += rtt;

					if (rtt < min_rtt_ms) {
						min_rtt_ms = rtt;
						printf("New min RTT: %.3f ms (seq=%u)\n", rtt, seq);
					}
					if (rtt > max_rtt_ms) {
						max_rtt_ms = rtt;
						printf("New max RTT: %.3f ms (seq=%u)\n", rtt, seq);
					}
                    
                    //printf("Response seq=%u RTT=%.3f ms\n", seq, rtt);
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

        // 2. INVIA TX (nuove request)
        if (opt_poll) {
            ret = poll(fds, nfds, timeout);
            if (ret <= 0) continue;
        }

        // Invia una request
		if (xsk_ring_prod__reserve(&xsk->tx, BATCH_SIZE, &idx) == BATCH_SIZE) {
			unsigned int i;

			for (i = 0; i < BATCH_SIZE; i++) {
				u64 addr = (frame_nb + i) << XSK_UMEM__DEFAULT_FRAME_SHIFT;
				void *pkt_buffer = xsk_umem__get_data(xsk->umem->buffer, addr);
				struct payload *pl = (struct payload *)(pkt_buffer + 42);
            	update_timestamp(pkt_buffer);
				//pl->timestamp = get_nsecs();
				pl->sequence = htonl(sequence_counter++);

				xsk_ring_prod__tx_desc(&xsk->tx, idx + i)->addr = addr;
				xsk_ring_prod__tx_desc(&xsk->tx, idx + i)->len = sizeof(pkt_data) - 1;
			}
			
			xsk_ring_prod__submit(&xsk->tx, BATCH_SIZE);
			xsk->outstanding_tx += BATCH_SIZE;
			total_sent += BATCH_SIZE;
			throughput_bytes_sent += BATCH_SIZE * PACKET_SIZE;
			frame_nb += BATCH_SIZE;
			frame_nb %= NUM_FRAMES;

			if (delay_us > 0) {
                usleep(delay_us);
            }		
		}

        complete_tx_only(xsk);
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

       /* Create sockets... */
	umem = xsk_configure_umem(bufs,
				  NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);
	xsks[num_socks++] = xsk_configure_socket(umem);

	if (opt_bench == BENCH_TXONLY || opt_bench == BENCH_TXRX) {
		int i;

		for (i = 0; i < NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE;
		     i += XSK_UMEM__DEFAULT_FRAME_SIZE)
			gen_eth_frame(umem, i);
	}

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	signal(SIGABRT, int_exit);

	setlocale(LC_ALL, "");


	if (sizeof(pkt_data) - 1 > XSK_UMEM__DEFAULT_FRAME_SIZE) {
    printf("ERROR: Packet too large for UMEM frame!\n");
    exit(1);
}

	ret = pthread_create(&pt, NULL, poller, NULL);
	if (ret)
		exit_with_error(ret);

	prev_time = get_nsecs();
	throughput_start_time = prev_time;

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