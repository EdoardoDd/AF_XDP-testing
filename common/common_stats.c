/**
 * common_stats.c - Funzioni per la gestione delle statistiche
 */
#include <stdlib.h> 
#include <math.h>
#include "common_stats.h"
#include "common_user_bpf_xdp.h"


uint64_t gettime(void)
{
    struct timespec t;
    int res;

    res = clock_gettime(CLOCK_MONOTONIC, &t);
    if (res < 0) {
        fprintf(stderr, "Error with clock_gettime! (%i)\n", res);
        exit(EXIT_FAILURE);
    }
    return (uint64_t) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

double calc_period(struct stats_record *r, struct stats_record *p)
{
    double period_ = 0;
    uint64_t period = 0;

    period = r->timestamp - p->timestamp;
    if (period > 0)
        period_ = ((double) period / NANOSEC_PER_SEC);

    return period_;
}

// Stampa le statistiche di ricezione e invio (RX e TX)
void stats_print(struct stats_record *stats_rec, struct stats_record *stats_prev)
{
    uint64_t packets, bytes;
    double period;
    double pps; 
    double bps; 

    char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
        " %'11lld Kbytes (%'6.0f Mbits/s)"
        " period:%f\n";

    period = calc_period(stats_rec, stats_prev);
    if (period == 0)
        period = 1;

    packets = stats_rec->rx_packets - stats_prev->rx_packets;
    pps     = packets / period;

    bytes   = stats_rec->rx_bytes   - stats_prev->rx_bytes;
    bps     = (bytes * 8) / period / 1000000;

    printf(fmt, "AF_XDP RX:", stats_rec->rx_packets, pps,
           stats_rec->rx_bytes / 1000 , bps,
           period);

    printf("\n");
}

// Thread per il polling delle statistiche
void *stats_poll(void *arg)
{
    unsigned int interval = 2;
    struct xsk_socket_info *xsk = arg;
    static struct stats_record previous_stats = { 0 };

    previous_stats.timestamp = gettime();

    setlocale(LC_NUMERIC, "en_US");

    while (!global_exit) {
        sleep(interval);
        xsk->stats.timestamp = gettime();
        stats_print(&xsk->stats, &previous_stats);
        previous_stats = xsk->stats;
    }
    return NULL;
}


void perf_stats_init(struct perf_stats *stats)
{
    memset(stats, 0, sizeof(*stats));
    stats->min_latency = UINT64_MAX;
    stats->start_time = gettime();
}


// Aggiunge la latenza alla statistica
void perf_stats_add_latency(struct perf_stats *stats, uint64_t latency_ns)
{
    stats->total_latency += latency_ns;
    stats->squared_latency += (latency_ns * latency_ns);
    
    if (latency_ns < stats->min_latency)
        stats->min_latency = latency_ns;
    if (latency_ns > stats->max_latency)
        stats->max_latency = latency_ns;
    
    if (stats->sample_count < MAX_PERCENTILE_SAMPLES)
        stats->sample_count++;
    
    stats->latency_samples[stats->sample_index] = latency_ns;
    stats->sample_index = (stats->sample_index + 1) % MAX_PERCENTILE_SAMPLES;
}


static int compare_uint64(const void *a, const void *b)
{
    const uint64_t *ua = (const uint64_t *)a;
    const uint64_t *ub = (const uint64_t *)b;
    return (*ua > *ub) - (*ua < *ub);
}


// Stampa le statistiche di prestazione
void perf_stats_print_summary(struct perf_stats *stats)
{
    uint64_t end_time = gettime();
    double duration_sec = (end_time - stats->start_time) / (double)NANOSEC_PER_SEC;
    
    double pps_tx = stats->packets_sent / duration_sec;
    double pps_rx = stats->packets_received / duration_sec;
    double mbps_tx = (stats->bytes_sent * 8.0) / duration_sec / 1000000.0;
    double mbps_rx = (stats->bytes_received * 8.0) / duration_sec / 1000000.0;
    
    double loss_percent = 0.0;
    if (stats->packets_sent > 0) {
        loss_percent = 100.0 * (stats->packets_sent - stats->packets_received) / stats->packets_sent;
    }
    
    double avg_latency_ms = 0.0, jitter_ms = 0.0;
    if (stats->packets_received > 0) {
        avg_latency_ms = stats->total_latency / (double)stats->packets_received / 1000000.0;
        
        if (stats->packets_received > 1) {
            double mean_latency = stats->total_latency / (double)stats->packets_received;
            double variance = (stats->squared_latency / (double)stats->packets_received) - (mean_latency * mean_latency);
            if (variance > 0)
                jitter_ms = sqrt(variance) / 1000000.0;
        }
    }
    
    double p50 = 0.0, p90 = 0.0, p99 = 0.0;
    if (stats->sample_count > 0) {
        uint64_t sorted[MAX_PERCENTILE_SAMPLES];
        int count = stats->sample_count;
        
        if (count == MAX_PERCENTILE_SAMPLES) {          // If buffer is full, copy all samples
            memcpy(sorted, stats->latency_samples, sizeof(uint64_t) * count);
        } else {
            memcpy(sorted, stats->latency_samples, sizeof(uint64_t) * count);
        }
        
        qsort(sorted, count, sizeof(uint64_t), compare_uint64);
        
        p50 = sorted[count * 50 / 100] / 1000000.0;  
        p90 = sorted[count * 90 / 100] / 1000000.0;  
        p99 = sorted[count * 99 / 100] / 1000000.0;  
    }
    
    printf("\n--- AF_XDP Performance Test Results ---\n");
    printf("Test duration: %.2f seconds\n\n", duration_sec);
    
    printf("Throughput:\n");
    printf("  TX: %.2f pps (%.2f Mbps)\n", pps_tx, mbps_tx);
    printf("  RX: %.2f pps (%.2f Mbps)\n", pps_rx, mbps_rx);
    printf("  Packets: %lu sent, %lu received\n", stats->packets_sent, stats->packets_received);
    printf("  Packet loss: %.2f%%\n\n", loss_percent);
    
    if (stats->packets_received > 0) {
        printf("Latency:\n");
        printf("  Min: %.3f ms\n", stats->min_latency / 1000000.0);
        printf("  Avg: %.3f ms\n", avg_latency_ms);
        printf("  Max: %.3f ms\n", stats->max_latency / 1000000.0);
        printf("  Jitter: %.3f ms\n", jitter_ms);
        printf("  P50: %.3f ms\n", p50);
        printf("  P90: %.3f ms\n", p90);
        printf("  P99: %.3f ms\n", p99);
    }
}