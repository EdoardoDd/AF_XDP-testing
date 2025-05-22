/**
 * common_user_bpf_xdp.c - Funzioni per la gestione di AF_XDP
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <poll.h>      
#include <sys/types.h> 
#include <string.h>  

#include "common_user_bpf_xdp.h"


struct xdp_program *prog;
int xsk_map_fd;
bool custom_xsk = false;
bool global_exit;

// Funzione per fare unload del programma XDP
int do_unload(struct config *cfg)
{
    if (cfg->unload_all) {
        if (prog) {
            return xdp_program__detach(prog, cfg->ifindex, cfg->xdp_flags, 0);
        } else {
            return 0;
        }
    } else if (prog) {
        return xdp_program__detach(prog, cfg->ifindex, cfg->xdp_flags, 0);
    }
    
    return 0;
}

// Conta il numero di frame liberi in un xsk_ring_prod
__u32 xsk_ring_prod__free(struct xsk_ring_prod *r)
{
    if (!r || !r->consumer || !r->producer) {
        return 0; 
    }

    uint32_t cons = *r->consumer;
    uint32_t prod = *r->producer;
    
    if (cons > prod + r->size) {
        return 0;
    }
    
    r->cached_cons = cons + r->size;
    
    if (r->cached_cons < r->cached_prod) {
        return 0;
    }
    
    return r->cached_cons - r->cached_prod;
}

/**
 * Configura l'UMEM per AF_XDP
 * 
 * @param buffer Puntatore al buffer da utilizzare per l'UMEM
 * @param size Dimensione del buffer
 * @return Puntatore alla struttura xsk_umem_info, NULL in caso di errore
 */
struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{
    struct xsk_umem_info *umem;
    struct xsk_umem_config umem_config = {
        .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,  
        .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS * 2,  
        .frame_size = FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0
    };
    int ret;

    umem = calloc(1, sizeof(*umem));
    if (!umem)
        return NULL;

    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, &umem_config);
    if (ret) {
        errno = -ret;
        free(umem);
        return NULL;
    }

    umem->buffer = buffer;
    return umem;
}

/**
 * Alloca un frame dall'UMEM
 * 
 * @param xsk Puntatore alla struttura xsk_socket_info
 * @return Indirizzo del frame allocato, o INVALID_UMEM_FRAME se non ci sono frame disponibili
 */
uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
    uint64_t frame;
    if (xsk->umem_frame_free == 0)
        return INVALID_UMEM_FRAME;

    frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
    xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
    return frame;
}

/**
 * Libera un frame restituendolo all'UMEM
 * 
 * @param xsk Puntatore alla struttura xsk_socket_info
 * @param frame Indirizzo del frame da liberare
 */
void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
    if (!xsk) {
        printf("ERROR: xsk is NULL in xsk_free_umem_frame\n");
        return;
    }

    if (frame == INVALID_UMEM_FRAME) {
        printf("ERROR: Attempted to free invalid UMEM frame!\n");
        return;
    }

    if (frame >= NUM_FRAMES * FRAME_SIZE) {
        printf("ERROR: Frame address 0x%lx is out of bounds (max: 0x%lx)\n", 
               frame, (uint64_t)(NUM_FRAMES * FRAME_SIZE - 1));
        return;
    }

    // Controlla se il frame è già nella lista dei frame liberi
    for (uint32_t i = 0; i < xsk->umem_frame_free; i++) {
        if (xsk->umem_frame_addr[i] == frame) {
         printf("ERROR: Frame %lu is already in the free list at index %u!\n",
            frame, i); 
            return;
        }
    }

    if (xsk->umem_frame_free >= NUM_FRAMES) {
         printf("ERROR: Too many free frames! umem_frame_free=%u, NUM_FRAMES=%d\n",
            xsk->umem_frame_free, NUM_FRAMES);   
        return;
    }

    if (frame % FRAME_SIZE != 0) {
        printf("ERROR: Frame address 0x%lx is not aligned to FRAME_SIZE (%d)\n", 
               frame, FRAME_SIZE);
        return;
    }
    
    // Aggiunge il frame di nuovo alla lista dei frame liberi
    xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
         printf("DEBUG: Frame %lu freed, now have %u free frames\n", 
            frame, xsk->umem_frame_free); 
} 




/**
 * Restituisce il numero di frame liberi nell'UMEM
 * 
 * @param xsk Puntatore alla struttura xsk_socket_info
 * @return Numero di frame liberi
 */
uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk)
{
    return xsk->umem_frame_free;
}

/**
 * Configura il socket AF_XDP e l'UMEM
 * 
 * @param cfg Puntatore alla struttura di configurazione
 * @param umem Puntatore alla struttura xsk_umem_info
 * @return Puntatore alla struttura xsk_socket_info, NULL in caso di errore
 */
struct xsk_socket_info *xsk_configure_socket(struct config *cfg, struct xsk_umem_info *umem)
{
    struct xsk_socket_config xsk_cfg;
    struct xsk_socket_info *xsk_info;
    uint32_t idx;
    int i;
    int ret;

    xsk_info = calloc(1, sizeof(*xsk_info));
    if (!xsk_info)
        return NULL;

    xsk_info->umem = umem;
    xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    xsk_cfg.xdp_flags = cfg->xdp_flags;
    xsk_cfg.bind_flags = cfg->xsk_bind_flags;
    xsk_cfg.libbpf_flags = (custom_xsk) ? XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD : 0;

    ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname, cfg->xsk_if_queue, 
                            umem->umem, &xsk_info->rx, &xsk_info->tx, &xsk_cfg);
    if (ret) {
        errno = -ret;
        goto error_exit;
    }

    if (custom_xsk) {
        ret = xsk_socket__update_xskmap(xsk_info->xsk, xsk_map_fd);
        if (ret) {
            errno = -ret;
            goto error_exit;
        }
    }

    for (i = 0; i < NUM_FRAMES; i++)
        xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

    xsk_info->umem_frame_free = NUM_FRAMES;

    ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
                                XSK_RING_PROD__DEFAULT_NUM_DESCS,
                                &idx);

    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
        goto error_exit;

    for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
        *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
            xsk_alloc_umem_frame(xsk_info);

    xsk_ring_prod__submit(&xsk_info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);
    xsk_refill_fill_queue(xsk_info, XSK_RING_PROD__DEFAULT_NUM_DESCS);  
    return xsk_info;

error_exit:
    free(xsk_info);
    return NULL;
}

/**
 * Gestisce la coda di completamento (CQ) per TX
 * 
 * @param xsk Puntatore alla struttura xsk_socket_info
 */
void complete_tx(struct xsk_socket_info *xsk)
{
    unsigned int completed;
    uint32_t idx_cq;

    if (!xsk || !xsk->umem) {
        return;
    }
    
    if (!xsk->outstanding_tx)
        return;

    if (!xsk->umem->cq.ring || !xsk->umem->cq.consumer || !xsk->umem->cq.producer) {
        return;
    }
        
    sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    
    completed = xsk_ring_cons__peek(&xsk->umem->cq, 
                                  xsk->outstanding_tx > 64 ? 64 : xsk->outstanding_tx, 
                                  &idx_cq);
    
    if (completed > 0) {
        if (completed > xsk->outstanding_tx) {
            printf("ERROR: CQ returned more completed (%u) than outstanding (%u)\n", 
                   completed, xsk->outstanding_tx);
            completed = xsk->outstanding_tx;
        }
        
        for (unsigned int i = 0; i < completed; i++) {
            if (idx_cq + i >= xsk->umem->cq.size) {
                printf("ERROR: CQ index out of bounds\n");
                break;
            }
            
            uint64_t addr = *xsk_ring_cons__comp_addr(&xsk->umem->cq, idx_cq + i);
            
            if (addr == INVALID_UMEM_FRAME) {
                printf("ERROR: Invalid frame address in CQ\n");
                continue;
            }
            
            if (addr >= NUM_FRAMES * FRAME_SIZE) {
                printf("ERROR: Frame address 0x%lx out of bounds\n", addr);
                continue;
            }
            
            xsk_free_umem_frame(xsk, addr);
        }
        
        xsk_ring_cons__release(&xsk->umem->cq, completed);
        
        if (completed > xsk->outstanding_tx) {
            xsk->outstanding_tx = 0;
        } else {
            xsk->outstanding_tx -= completed;
        }
    }
}


/**
 * Invia un pacchetto tramite socket AF_XDP
 * 
 * @param xsk Puntatore alla struttura xsk_socket_info
 * @param data Dati del pacchetto da inviare
 * @param length Lunghezza del pacchetto
 * @return 0 in caso di successo, valore negativo in caso di errore
 */
int xsk_send_packet(struct xsk_socket_info *xsk,
                    const void *data, size_t length)
{
    uint32_t idx = 0;
    uint64_t addr=INVALID_UMEM_FRAME;
    void *pkt;
    int reserved = 0;
    
    if (!xsk || !data || length == 0 || length > FRAME_SIZE)
        return -EINVAL;

    if (xsk_ring_prod__reserve(&xsk->tx, 1, &idx) != 1) {
        complete_tx(xsk);
        
        if (xsk_ring_prod__reserve(&xsk->tx, 1, &idx) != 1) {
            return -EAGAIN; 
        }
    }
    reserved = 1;
    
    addr = xsk_alloc_umem_frame(xsk);
    if (addr == INVALID_UMEM_FRAME) {
        return -ENOMEM; 
    }
    
    pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
    if (!pkt) {
        xsk_free_umem_frame(xsk, addr);
        return -EFAULT;
    }
    __builtin_prefetch(pkt, 1, 1);  
    
    if (length <= 64) {
        char *dst = (char *)pkt;
        const char *src = (const char *)data;
        
        for (size_t i = 0; i < length; i += 8) {
            if (i + 8 <= length) {
                *((uint64_t *)(dst + i)) = *((const uint64_t *)(src + i));
            } else {
                for (size_t j = i; j < length; j++) {
                    dst[j] = src[j];
                }
                break;
            }
        }
    } else {
        memcpy(pkt, data, length);
    }
    
    xsk_ring_prod__tx_desc(&xsk->tx, idx)->addr = addr;
    xsk_ring_prod__tx_desc(&xsk->tx, idx)->len = length;
    
    xsk_ring_prod__submit(&xsk->tx, 1);
    
    if (xsk->outstanding_tx == 0) {
        sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    } else if (xsk->outstanding_tx % 8 == 0) {
        sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    }
    
    xsk->outstanding_tx++;
    
    return 0;
}

/**
 * Riceve un pacchetto tramite socket AF_XDP con timeout
 * 
 * @param xsk Puntatore alla struttura xsk_socket_info
 * @param buffer Buffer dove memorizzare il pacchetto (NULL per usare l'UMEM interno)
 * @param size Dimensione massima del buffer (ignorata se buffer è NULL)
 * @param timeout_ms Timeout in millisecondi (-1 per bloccante)
 * @param addr Puntatore per memorizzare l'indirizzo UMEM del pacchetto (può essere NULL)
 * @param len Puntatore per memorizzare la lunghezza del pacchetto (può essere NULL)
 * @return Puntatore ai dati del pacchetto, NULL in caso di errore o timeout
 * @note Se buffer è NULL, il pacchetto rimane nell'UMEM e deve essere liberato con xsk_free_umem_frame
 */
void *xsk_receive_packet(struct xsk_socket_info *xsk,
                        void *buffer, size_t size,
                        int timeout_ms,
                        uint64_t *addr_ret, uint32_t *len_ret)
{
    struct pollfd fds;
    unsigned int rcvd;
    uint32_t idx_rx = 0;
    int ret;
    void *pkt;
    uint64_t addr;
    uint32_t len;
    
    if (!xsk)
        return NULL;
    

    xsk_refill_fill_queue(xsk, 32);  
    
    fds.fd = xsk_socket__fd(xsk->xsk);
    fds.events = POLLIN;
    
    if (timeout_ms != 0) {
        ret = poll(&fds, 1, timeout_ms);
        if (ret <= 0)
            return NULL; 
    }
    
    rcvd = xsk_ring_cons__peek(&xsk->rx, 1, &idx_rx);
    if (rcvd == 0)
        return NULL; 
    
    addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
    len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->len;
    
    pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
    
    if (buffer && size > 0) {
        size_t copy_len = len < size ? len : size;
        memcpy(buffer, pkt, copy_len);
        
        xsk_free_umem_frame(xsk, addr);
        
        xsk_ring_cons__release(&xsk->rx, 1);
        
        xsk_refill_fill_queue(xsk, 1);  
        
        xsk->stats.rx_packets++;
        xsk->stats.rx_bytes += len;
        
        if (addr_ret)
            *addr_ret = 0; 
        if (len_ret)
            *len_ret = copy_len;
        return buffer;
    } else {

        xsk_ring_cons__release(&xsk->rx, 1);
        

        xsk->stats.rx_packets++;
        xsk->stats.rx_bytes += len;
        
        if (addr_ret)
            *addr_ret = addr;
        if (len_ret)
            *len_ret = len;
        return pkt;
    }
}




/**
 * Riempie la coda di riempimento con frame
 * 
 * @param xsk Puntatore alla struttura xsk_socket_info
 */
int xsk_refill_fill_queue(struct xsk_socket_info *xsk, unsigned int target)
{
    uint32_t idx;
    unsigned int free_entries, to_add, added;
    
    free_entries = xsk_ring_prod__free(&xsk->umem->fq);
    if (free_entries == 0)
        return 0; 

    to_add = free_entries > target ? target : free_entries;
    
    if (xsk->umem_frame_free < to_add)
        to_add = xsk->umem_frame_free;
    
    if (to_add == 0)
        return 0; 
    
    added = xsk_ring_prod__reserve(&xsk->umem->fq, to_add, &idx);
    
    for (unsigned int i = 0; i < added; i++)
        *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx++) = xsk_alloc_umem_frame(xsk);
    
    xsk_ring_prod__submit(&xsk->umem->fq, added);
    
    return added;  
}



/**
 * Processa i pacchetti ricevuti con una funzione di callback
 * 
 * @param xsk Puntatore alla struttura xsk_socket_info
 * @param callback Funzione da chiamare per ogni pacchetto ricevuto
 * @param user_data Dati utente da passare al callback
 * @param timeout_ms Timeout in millisecondi (-1 per bloccante)
 * @param max_packets Numero massimo di pacchetti da elaborare (0 per tutti quelli disponibili)
 * @return Numero di pacchetti elaborati, valore negativo in caso di errore
 * @note Il callback è responsabile per liberare i frame UMEM
 */
int xsk_process_packets(struct xsk_socket_info *xsk,
                        int (*callback)(struct xsk_socket_info *xsk,
                                       const void *data, size_t length,
                                       uint64_t addr, void *user_data),
                        void *user_data,
                        int timeout_ms,
                        unsigned int max_packets)
{
    struct pollfd fds;
    unsigned int rcvd, processed = 0;
    uint32_t idx_rx = 0;
    int ret, i;
    
    if (!xsk || !callback)
        return -EINVAL;
    
    xsk_refill_fill_queue(xsk, 64);
    
    fds.fd = xsk_socket__fd(xsk->xsk);
    fds.events = POLLIN;
    
    if (timeout_ms != 0) {
        ret = poll(&fds, 1, timeout_ms);
        if (ret <= 0)
            return ret; 
    }
    
    rcvd = xsk_ring_cons__peek(&xsk->rx, max_packets > 0 ? max_packets : RX_BATCH_SIZE, &idx_rx);
    if (rcvd == 0)
        return 0;
    
    for (i = 0; i < rcvd; i++) {
        uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
        uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;
        void *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
        
        ret = callback(xsk, pkt, len, addr, user_data);
        
        xsk->stats.rx_packets++;
        xsk->stats.rx_bytes += len;
        
        processed++;

        if (i % 8 == 0) {
            complete_tx(xsk);
        }
        
        if (max_packets > 0 && processed >= max_packets)
            break;
    }
    
    xsk_ring_cons__release(&xsk->rx, i);
    
    xsk_refill_fill_queue(xsk, 64);
    
    return processed;
}

/**
 * Esegue scambio richiesta-risposta
 * 
 * @param xsk Puntatore alla struttura xsk_socket_info
 * @param request Dati del pacchetto di richiesta
 * @param request_len Lunghezza del pacchetto di richiesta
 * @param response Buffer per la risposta
 * @param response_size Dimensione massima del buffer di risposta
 * @param timeout_ms Timeout in millisecondi
 * @return Lunghezza della risposta, o valore negativo in caso di errore
 */
int xsk_request_response(struct xsk_socket_info *xsk,
                         const void *request, size_t request_len,
                         void *response, size_t response_size,
                         int timeout_ms)
{
    int ret;
    uint64_t addr;
    uint32_t len;
    void *resp_data;
    unsigned long start_time, current_time;
    
    if (!xsk || !request || request_len == 0 || !response || response_size == 0)
        return -EINVAL;
    
    ret = xsk_send_packet(xsk, request, request_len);
    if (ret < 0)
        return ret;
    
    complete_tx(xsk);
    
    start_time = gettime() / 1000000; 
    
    while (1) {
        if (timeout_ms >= 0) {
            current_time = gettime() / 1000000;
            if (current_time - start_time >= (unsigned long)timeout_ms)
                return -ETIMEDOUT;
            
            int remaining_ms = timeout_ms - (current_time - start_time);
            if (remaining_ms <= 0)
                return -ETIMEDOUT;
            
            resp_data = xsk_receive_packet(xsk, response, response_size, 
                                          remaining_ms, &addr, &len);
        } else {
            resp_data = xsk_receive_packet(xsk, response, response_size, 
                                          -1, &addr, &len);
        }
        
        if (resp_data)
            return len; 
    }
    
    return -ENODATA;
}

