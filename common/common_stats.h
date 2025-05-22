#ifndef COMMON_STATS_H
#define COMMON_STATS_H

#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <locale.h>
#include <unistd.h>
#include <stdlib.h> 
#include <stdbool.h>

extern bool global_exit;

#define NANOSEC_PER_SEC 1000000000 

struct stats_record {
    uint64_t timestamp;    
    uint64_t rx_packets;  
    uint64_t rx_bytes;    
};

struct perf_stats {
    uint64_t packets_sent;
    uint64_t packets_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    
    uint64_t total_latency;    
    uint64_t min_latency;     
    uint64_t max_latency;     
    uint64_t squared_latency; 
    
    #define MAX_PERCENTILE_SAMPLES 1000
    uint64_t latency_samples[MAX_PERCENTILE_SAMPLES];
    int sample_count;
    int sample_index;  
    
    uint64_t start_time;
};

uint64_t gettime(void);
double calc_period(struct stats_record *r, struct stats_record *p);
void stats_print(struct stats_record *stats_rec, struct stats_record *stats_prev);
void *stats_poll(void *arg);

void perf_stats_init(struct perf_stats *stats);
void perf_stats_add_latency(struct perf_stats *stats, uint64_t latency_ns);
void perf_stats_print_summary(struct perf_stats *stats);

#endif 