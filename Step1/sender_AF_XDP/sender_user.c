#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <ctype.h>

#include <bpf/bpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <fcntl.h>       
#include <netinet/in.h>  
#include <sys/socket.h> 

#include "common_params.h"
#include "common_user_bpf_xdp.h"
#include "common_stats.h"
#include "common_packet.h"

const char *__doc__ = "XDP Ping Sender - Invia pacchetti PING ed elabora PONG in ricezione.\n";

extern struct xdp_program *prog;
extern int xsk_map_fd;
extern bool custom_xsk;
extern bool global_exit;
extern struct config cfg;

#define DEFAULT_INTERFACE "enp8s0"
#define DEST_IP "192.168.56.104"
#define SRC_IP "192.168.56.103"  
#define SRC_PORT 12345
#define DEST_PORT 6789

#define PING_INTERVAL_MS 1000  
#define NUM_PINGS 10           
#define PING_MSG "PING"        
#define PONG_MSG "PONG"      
#define PING_TIMEOUT_MS 1000  

#define DEFAULT_DURATION 10 
#define DEFAULT_PACKET_SIZE 64
#define DEFAULT_RATE 1000

static uint8_t dest_mac[ETH_ALEN];
static uint8_t src_mac[ETH_ALEN];
static bool mac_set = false;

#define MAX_UNACKED_PINGS 8192  
typedef struct {
    uint32_t seq_num;
    uint64_t send_time;
    bool active;
} ping_tracker_t;

static ping_tracker_t ping_tracker[MAX_UNACKED_PINGS];
static int process_pong(uint32_t seq_num);

struct ping_stats {
    uint64_t sent;            
    uint64_t received;        
    uint64_t errors;          
    uint64_t lost;            
    uint64_t total_rtt;       
    uint64_t min_rtt;         
    uint64_t max_rtt;         
};

static struct ping_stats stats = {0, 0, 0, 0, 0, UINT64_MAX, 0};


struct perf_stats perf_stats;

static void init_ping_tracker(void)
{
    memset(ping_tracker, 0, sizeof(ping_tracker));
}

static int track_ping(uint32_t seq_num)
{
    int i;
    
    for (i = 0; i < MAX_UNACKED_PINGS; i++) {
        if (!ping_tracker[i].active) {
            ping_tracker[i].seq_num = seq_num;
            ping_tracker[i].send_time = gettime();
            ping_tracker[i].active = true;
            return 0;
        }
    }
    
    return -1; 
}

static int process_pong(uint32_t seq_num)
{
    int i;
    uint64_t now = gettime();
    uint64_t rtt;
    
    for (i = 0; i < MAX_UNACKED_PINGS; i++) {
        if (ping_tracker[i].active && ping_tracker[i].seq_num == seq_num) {
            rtt = (now - ping_tracker[i].send_time) / 1000; 
            
            stats.received++;
            stats.total_rtt += rtt;
            
            if (rtt < stats.min_rtt)
                stats.min_rtt = rtt;
            
            if (rtt > stats.max_rtt)
                stats.max_rtt = rtt;
            
            ping_tracker[i].active = false;
            
            printf("Ricevuto PONG da %s: seq=%u time=%.2f ms\n", 
                   DEST_IP, seq_num, rtt / 1000.0);
            
            return 0;
        }
    }
    
    return -1; 
}

static void check_timeouts(int timeout_ms)
{
    int i;
    uint64_t now = gettime();
    uint64_t timeout_ns = timeout_ms * 1000000ULL;
    
    for (i = 0; i < MAX_UNACKED_PINGS; i++) {
        if (ping_tracker[i].active) {
            if (now - ping_tracker[i].send_time > timeout_ns) {
                printf("PING timeout: seq=%u\n", ping_tracker[i].seq_num);
                stats.lost++;
                ping_tracker[i].active = false;
            }
        }
    }
}

static int process_packet_cb(struct xsk_socket_info *xsk,
                           const void *data, size_t length,
                           uint64_t addr, void *user_data)
{
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    uint16_t src_port, dst_port;
    const void *payload;
    size_t payload_len;
    uint32_t seq_num;
    int ret;

    
    ret = extract_packet_info(data, length, 
                            NULL, NULL, 
                            src_ip, dst_ip, 
                            &src_port, &dst_port, 
                            &payload, &payload_len);
                            
    if (ret < 0) {
        fprintf(stderr, "\n\nERROR: Not a valid UDP/IP packet (error code: %d)\n\n\n", ret);
        goto free_packet;
    }

    printf("UDP Packet: %s:%d -> %s:%d, Payload length: %zu\n",
           src_ip, src_port, dst_ip, dst_port, payload_len);
    
    if (payload_len > 0) {
        printf("Payload: ");
        for (size_t i = 0; i < payload_len && i < 32; i++) {
            char c = ((const char *)payload)[i];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        printf("\n");
    }
    
    if (strcmp(src_ip, DEST_IP) == 0 && 
        strcmp(dst_ip, SRC_IP) == 0 &&
        src_port == DEST_PORT && 
        dst_port == SRC_PORT) {
        
        if (payload_len >= 4 && memcmp(payload, PONG_MSG, 4) == 0) {
            if (payload_len >= 9 && sscanf((const char *)payload + 5, "%u", &seq_num) == 1) {
                process_pong(seq_num);
            }
        }
    }
    
free_packet:
    
    xsk_free_umem_frame(xsk, addr);
    return 0;
}

static int initialize_mac_addresses(void)
{
    char buf[18];
    int ret;
    
    ret = get_interface_mac(cfg.ifname, src_mac);
    if (ret < 0) {
        fprintf(stderr, "ERROR: Could not determine MAC address of interface %s\n", cfg.ifname);
        return ret;
    }
    
    printf("Using source MAC: %s\n", mac_addr_to_str(src_mac, buf, sizeof(buf)));
    
/*  ret = discover_mac_address(DEST_IP, dest_mac, 1000);
    if (ret < 0) {
        
        char mac_str[18];
        if (fgets(mac_str, sizeof(mac_str), stdin) != NULL) {
            if (str_to_mac_addr(mac_str, dest_mac) < 0) {
                fprintf(stderr, "ERRORE: formato MAC errato\n");
                return -1;
            }
        } else {
            return -1;
        }
    } */

    // Per testing impostiamo un MAC address statico
    str_to_mac_addr("22:44:19:e0:4e:d7", dest_mac);
    
    printf("MAC destinazione: %s\n", mac_addr_to_str(dest_mac, buf, sizeof(buf)));
    mac_set = true;
    
    return 0;
}


static int send_ping(struct xsk_socket_info *xsk, uint32_t seq_num)
{
    char buffer[FRAME_SIZE];
    char payload[64];
    int packet_len;
    
    if (!mac_set) {
        fprintf(stderr, "Errore: indirizzo MAC non inizializzato\n");
        stats.errors++;
        return -1;
    }
    
    snprintf(payload, sizeof(payload), "%s %u", PING_MSG, seq_num);
    
    packet_len = create_udp_packet(buffer, sizeof(buffer),
                                  dest_mac, src_mac,
                                  SRC_IP, DEST_IP,
                                  SRC_PORT, DEST_PORT,
                                  payload, strlen(payload));
    
    if (packet_len < 0) {
        fprintf(stderr, "Errore: creazione pacchetto\n");
        stats.errors++;
        return -1;
    }
    
    if (xsk_send_packet(xsk, buffer, packet_len) < 0) {
        fprintf(stderr, "Errore: invio pacchetto\n");
        stats.errors++;
        return -2;
    }
    
    stats.sent++;
    track_ping(seq_num);
    
    printf("PING %s: seq=%u, %d bytes\n", DEST_IP, seq_num, packet_len);
    
    return 0;
}

static void ping_pong_loop(struct xsk_socket_info *xsk_socket)
{
    uint32_t seq = 1;
    uint64_t next_ping_time = gettime() / 1000000; 
    int sent = 0;
    void *packet;
    uint64_t pkt_addr;
    uint32_t pkt_len;

    
    init_ping_tracker();
    
    printf("PING inviato a %s, interfaccia %s\n", DEST_IP, cfg.ifname);
    printf("Ctrl+C to stop\n\n");
    
    while (!global_exit && (NUM_PINGS == 0 || sent < NUM_PINGS)) {
        uint64_t current_time = gettime() / 1000000;
        
        if (current_time >= next_ping_time) {
            if (send_ping(xsk_socket, seq++) == 0) {
                sent++;
            }
            
            next_ping_time = current_time + PING_INTERVAL_MS;
            
            complete_tx(xsk_socket);
        }
    
        check_timeouts(PING_TIMEOUT_MS);


        packet = xsk_receive_packet(xsk_socket, NULL, 0, 100, &pkt_addr, &pkt_len);
        if (packet) {
            printf("Dimensione pacchetto: %u\n", pkt_len);
            process_packet_cb(xsk_socket, packet, pkt_len, pkt_addr, NULL);
        }
    }


    printf("\n--- %s statistiche ping ---\n", DEST_IP);
    printf("%lu pachetti trasmessi, %lu ricevuti, %.1f%% pacchetti persi\n",
           stats.sent, stats.received,
           stats.sent > 0 ? 100.0 * (stats.sent - stats.received) / stats.sent : 0.0);
    
    if (stats.received > 0) {
        printf("round-trip min/avg/max = %.3f/%.3f/%.3f ms\n",
               stats.min_rtt / 1000.0,
               stats.total_rtt / (double)stats.received / 1000.0,
               stats.max_rtt / 1000.0);
    }
}

static void exit_application(int signal)
{
    printf("\nTerminazione...\n");
    
    if (prog) {
        cfg.unload_all = true;
        int err = do_unload(&cfg);
        if (err) {
            fprintf(stderr, "Errore: unload XDP %s\n", cfg.ifname);
        }
    }
    
    global_exit = true;
}


static void performance_test(struct xsk_socket_info *xsk_socket)
{
    uint32_t seq = 1;
    uint64_t start_time = gettime();
    uint64_t end_time = start_time + (cfg.test_duration * NANOSEC_PER_SEC);
    uint64_t next_send_time = start_time;
    char xsk_buffer[FRAME_SIZE];
    
    uint64_t packet_interval = 0;
    if (cfg.packet_rate > 0) {
        packet_interval = NANOSEC_PER_SEC / cfg.packet_rate;
    }
    
    perf_stats_init(&xsk_socket->perf_stats);
    init_ping_tracker();
    
    printf("Inizio - performance test - %d seconds (packet size: %d bytes, rate: %d pps)\n",
           cfg.test_duration, cfg.packet_size, cfg.packet_rate);
    
    while (gettime() < end_time && !global_exit) {
        uint64_t current_time = gettime();
        
        if (current_time >= next_send_time) {
            int payload_size = cfg.packet_size - 42; 
            if (payload_size < 8) payload_size = 8;
            
            char payload[payload_size];
            snprintf(payload, sizeof(payload), "PING %u", seq);
            
            int packet_len = create_udp_packet(xsk_buffer, FRAME_SIZE,
                                             dest_mac, src_mac,
                                             SRC_IP, DEST_IP,
                                             SRC_PORT, DEST_PORT,
                                             payload, payload_size);
            
            if (packet_len > 0 && xsk_send_packet(xsk_socket, xsk_buffer, packet_len) == 0) {
                track_ping(seq);
                xsk_socket->perf_stats.packets_sent++;
                xsk_socket->perf_stats.bytes_sent += packet_len;
                seq++;
                
                if (packet_interval > 0) {
                    next_send_time += packet_interval;
                    if (next_send_time < current_time)
                        next_send_time = current_time;
                } else {
                    next_send_time = current_time; 
                }
            }
            
            complete_tx(xsk_socket);
        }
        
        void *pkt;
        uint64_t addr;
        uint32_t len;
        
        pkt = xsk_receive_packet(xsk_socket, NULL, 0, 0, &addr, &len);
        if (pkt) {
            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            uint16_t src_port, dst_port;
            const void *payload;
            size_t payload_len;
            
            int ret = extract_packet_info(pkt, len, NULL, NULL,
                                        src_ip, dst_ip, &src_port, &dst_port,
                                        &payload, &payload_len);
            
            if (ret >= 0 && 
                strcmp(src_ip, DEST_IP) == 0 && strcmp(dst_ip, SRC_IP) == 0 &&
                src_port == DEST_PORT && dst_port == SRC_PORT &&
                payload_len >= 4 && memcmp(payload, "PONG", 4) == 0) {
                
                uint32_t recv_seq = 0;
                if (sscanf((const char *)payload + 5, "%u", &recv_seq) == 1) {
                    for (int i = 0; i < MAX_UNACKED_PINGS; i++) {
                        if (ping_tracker[i].active && ping_tracker[i].seq_num == recv_seq) {
                            // RTT calculte 
                            uint64_t rtt = current_time - ping_tracker[i].send_time;
                            xsk_socket->perf_stats.packets_received++;
                            xsk_socket->perf_stats.bytes_received += len;
                            perf_stats_add_latency(&xsk_socket->perf_stats, rtt);
                            
                            ping_tracker[i].active = false;
                            break;
                        }
                    }
                }
            }
            
            xsk_free_umem_frame(xsk_socket, addr);
        }
        
        static uint64_t last_timeout_check = 0;
        if (current_time - last_timeout_check > 10000000) { 
            last_timeout_check = current_time;
            check_timeouts(PING_TIMEOUT_MS);
        }
        
        static uint64_t last_progress = 0;
        if (current_time - last_progress > NANOSEC_PER_SEC) { 
            last_progress = current_time;
            double elapsed = (current_time - start_time) / (double)NANOSEC_PER_SEC;
            printf("\r%.1f sec: Inviato=%lu Ricevuto=%lu Loss=%.1f%% ",
                  elapsed,
                  xsk_socket->perf_stats.packets_sent,
                  xsk_socket->perf_stats.packets_received,
                  xsk_socket->perf_stats.packets_sent > 0 ?
                  100.0 * (xsk_socket->perf_stats.packets_sent - xsk_socket->perf_stats.packets_received) / 
                  xsk_socket->perf_stats.packets_sent : 0.0);
            fflush(stdout);
        }
    }
    
    perf_stats_print_summary(&xsk_socket->perf_stats);
}



int main(int argc, char **argv)
{
    void *packet_buffer;
    uint64_t packet_buffer_size;
    struct xsk_umem_info *umem;
    struct xsk_socket_info *xsk_socket;
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, bpf_opts);
    DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    
    signal(SIGINT, exit_application);
    
    cfg.ifname = DEFAULT_INTERFACE;
    cfg.ifindex = if_nametoindex(cfg.ifname);
    if (cfg.ifindex == 0) {
        fprintf(stderr, "ERRORE: interfaccia '%s' non trovata\n", cfg.ifname);
        return EXIT_FAILURE;
    }
    
    printf("Configurazione socket: ifindex=%d, queue=%d, flags=0x%x\n", 
       cfg.ifindex, cfg.xsk_if_queue, cfg.xsk_bind_flags);

    if (argc > 1) {
        parse_cmdline_args(argc, argv, __doc__);
    }
    
    if (initialize_mac_addresses() < 0) {
        fprintf(stderr, "ERRORE: inizializzazione indirizzo MAC\n");
        return EXIT_FAILURE;
    }
    
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "ERRORE: setrlimit(RLIMIT_MEMLOCK): %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    
    packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
    if (posix_memalign(&packet_buffer, getpagesize(), packet_buffer_size)) {
        fprintf(stderr, "ERRORE: allocate packet buffer\n");
        return EXIT_FAILURE;
    }
    
    umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
    if (!umem) {
        fprintf(stderr, "ERRORE: configurazione UMEM\n");
        free(packet_buffer);
        return EXIT_FAILURE;
    }
    
    xsk_socket = xsk_configure_socket(&cfg, umem);
    if (!xsk_socket) {
        fprintf(stderr, "ERRORE: configurazione socket AF_XDP\n");
        xsk_umem__delete(umem->umem);
        free(packet_buffer);
        return EXIT_FAILURE;
    }
    
    srand(time(NULL));
    
    if (cfg.performance_mode) {
        performance_test(xsk_socket);
    } else {
        ping_pong_loop(xsk_socket);
    }
    
    // Cleanup 
    xsk_socket__delete(xsk_socket->xsk);
    xsk_umem__delete(umem->umem);
    free(packet_buffer);
    
    return EXIT_SUCCESS;
}