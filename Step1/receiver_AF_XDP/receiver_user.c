#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <bpf/bpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "common_params.h"
#include "common_user_bpf_xdp.h"
#include "common_packet.h"

const char *__doc__ = "PING-PONG receiver\n";

static struct {
    uint64_t ping_received;
    uint64_t pong_sent;
    uint64_t errors;
} stats = {0, 0, 0};

// Callback 
static int process_ping_packet(struct xsk_socket_info *xsk,
                               const void *data, size_t length,
                               uint64_t addr, void *user_data)
{
    const void *payload;
    size_t payload_len;
    int ret;

    ret = extract_packet_info(data, length, 
                            NULL, NULL,           
                            NULL, NULL,           
                            NULL, NULL,           
                            &payload, &payload_len);
    
    if (ret < 0) {
        xsk_free_umem_frame(xsk, addr);
        return 0;
    }

    if (payload_len < 4 || memcmp(payload, "PING", 4) != 0) {
        xsk_free_umem_frame(xsk, addr);
        return 0;
    }

    stats.ping_received++;
    
    if (cfg.verbosity) {
        printf("PING ricevuto (#%lu), rispondiamo con PONG\n", stats.ping_received);
    }

    char response_buffer[FRAME_SIZE];
    int resp_len = create_response_packet(data, length, 
                                         response_buffer, sizeof(response_buffer),
                                         payload, payload_len);  
    
    if (resp_len > 0) {
        size_t resp_payload_len;
        
        ret = extract_packet_info(response_buffer, resp_len, 
                                NULL, NULL, NULL, NULL, NULL, NULL,
                                &resp_payload, &resp_payload_len);
        
        if (ret >= 0 && resp_payload_len >= 4) {
            char *pong_start = (char *)resp_payload;
            memcpy(pong_start, "PONG", 4);
        }
        
        ret = xsk_send_packet(xsk, response_buffer, resp_len);
        if (ret < 0) {
            stats.errors++;
            if (cfg.verbosity) {
                printf("Invio PONG fallito: %s\n", strerror(-ret));
            }
        } else {
            stats.pong_sent++;
            if (cfg.verbosity) {
                printf("Invio PONG avvenuto con successo\n");
            }
        }
    } else {
        stats.errors++;
        if (cfg.verbosity) {
            printf("Errore creazione risposta PONG\n");
        }
    }
    
    xsk_free_umem_frame(xsk, addr);
    return 0;
}


static void run_receiver(struct xsk_socket_info *xsk_socket)
{
    time_t last_stats = time(NULL);
    uint64_t last_ping = 0, last_pong = 0;
    
    printf("PING-PONG receiver attivo %s\n", cfg.ifname);
    printf("Ctrl+C to stop\n\n");
    
    while (!global_exit) {
        int processed = xsk_process_packets(xsk_socket, process_ping_packet, 
                                          NULL, 1000, 0);
        
        if (processed < 0 && processed != -ETIMEDOUT) {
            printf("Errore elaborazione pacchetti: %s\n", strerror(-processed));
            stats.errors++;
        }
        
        time_t now = time(NULL);
        if (now - last_stats >= 5 && stats.ping_received > 0) {
            uint64_t ping_delta = stats.ping_received - last_ping;
            uint64_t pong_delta = stats.pong_sent - last_pong;
            
            printf("PING: %lu (+%lu) | PONG: %lu (+%lu) | Errors: %lu | Frame liberi: %lu\n",
                   stats.ping_received, ping_delta,
                   stats.pong_sent, pong_delta,
                   stats.errors, xsk_umem_free_frames(xsk_socket));
            
            last_stats = now;
            last_ping = stats.ping_received;
            last_pong = stats.pong_sent;
        }
    }
}

static void exit_handler(int signal)
{
    printf("\nTerminazione...\n");
    global_exit = true;
    
    if (cfg.filename[0] != 0) {
        cfg.unload_all = true;
        do_unload(&cfg);
    }
}

int main(int argc, char **argv)
{
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    void *packet_buffer;
    uint64_t packet_buffer_size;
    struct xsk_umem_info *umem;
    struct xsk_socket_info *xsk_socket;
    
    signal(SIGINT, exit_handler);
    signal(SIGTERM, exit_handler);
    
    parse_cmdline_args(argc, argv, __doc__);
    
    if (cfg.ifindex == -1) {
        fprintf(stderr, "ERRORE: specifica interfaccia --dev <interface>\n");
        usage(argv[0], __doc__);
        return EXIT_FAILURE;
    }
    
    printf("PING-PONG Receiver\n");
    printf("Interfaccia: %s (queue %d)\n", cfg.ifname, cfg.xsk_if_queue);
    printf("Verbosity: %s\n", cfg.verbosity ? "ON" : "OFF");
    
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "ERRORE: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    
    packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
    if (posix_memalign(&packet_buffer, getpagesize(), packet_buffer_size)) {
        fprintf(stderr, "ERRORE: allocazione Buffer fallita: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    
    umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
    if (!umem) {
        fprintf(stderr, "ERRORE: configurazione UMEM fallita: %s\n", strerror(errno));
        free(packet_buffer);
        return EXIT_FAILURE;
    }
    
    xsk_socket = xsk_configure_socket(&cfg, umem);
    if (!xsk_socket) {
        fprintf(stderr, "ERRORE: configurazione XDP socket fallita: %s\n", strerror(errno));
        xsk_umem__delete(umem->umem);
        free(umem);
        free(packet_buffer);
        return EXIT_FAILURE;
    }
    
    printf("AF_XDP setup completato, frame disponibili: %lu\n", 
           xsk_umem_free_frames(xsk_socket));
    printf("In attesa di PING...\n\n");
    
    run_receiver(xsk_socket);
    
    printf("\nFinal statistics:\n");
    printf("PING ricevuti: %lu\n", stats.ping_received);
    printf("PONG inviati: %lu\n", stats.pong_sent);
    printf("Errori: %lu\n", stats.errors);
    
    xsk_socket__delete(xsk_socket->xsk);
    xsk_umem__delete(umem->umem);
    free(umem);
    free(packet_buffer);
    
    return EXIT_SUCCESS;
}