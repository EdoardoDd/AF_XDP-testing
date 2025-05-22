#ifndef COMMON_USER_BPF_XDP_H
#define COMMON_USER_BPF_XDP_H

#include <bpf/bpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>
#include <linux/if_link.h>
#include <stdbool.h>
#include <linux/types.h>

#include "common_stats.h"  
#include "common_params.h" 

#define NUM_FRAMES         8192
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

extern struct xdp_program *prog;
extern int xsk_map_fd;
extern bool custom_xsk;
extern bool global_exit;

struct config;

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

    uint64_t umem_frame_addr[NUM_FRAMES]; 
    uint32_t umem_frame_free;             
    uint32_t outstanding_tx;              

    struct stats_record stats;            
    struct stats_record prev_stats;       
    struct perf_stats perf_stats;         
};

// Funzione per gestione dei frame UMEM
uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk);



void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame);
uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk);
__u32 xsk_ring_prod__free(struct xsk_ring_prod *r);
int xsk_refill_fill_queue(struct xsk_socket_info *xsk, unsigned int target);


// Configurazione UMEM e socket
struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size);
struct xsk_socket_info *xsk_configure_socket(struct config *cfg, struct xsk_umem_info *umem);

// Unload XDP 
int do_unload(struct config *cfg);

// Gestione della coda di completamento (CQ) per TX
void complete_tx(struct xsk_socket_info *xsk);


// Funzioni per invio e ricezione di pacchetti
int xsk_send_packet(struct xsk_socket_info *xsk,
                    const void *data, size_t length);
void *xsk_receive_packet(struct xsk_socket_info *xsk,
                        void *buffer, size_t size,
                        int timeout_ms,
                        uint64_t *addr, uint32_t *len);
int xsk_process_packets(struct xsk_socket_info *xsk,
                        int (*callback)(struct xsk_socket_info *xsk,
                                        const void *data, size_t length,
                                        uint64_t addr, void *user_data),
                        void *user_data,
                        int timeout_ms,
                        unsigned int max_packets);
int xsk_request_response(struct xsk_socket_info *xsk,
                         const void *request, size_t request_len,
                         void *response, size_t response_size,
                         int timeout_ms);

#endif 