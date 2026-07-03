/* Microbenchmark do lookup da allowlist (x86-64).
   Mede ciclos/busca isolando policy_find_{linear,binary,direct} em função de N,
   separando hit e miss. 
*/
#include "allowlist.h"
#include "allowlist_sweep.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define PROBE_LEN  4096u          /* potência de 2: índice por máscara */
#define PROBE_MASK (PROBE_LEN - 1u)

static volatile uintptr_t g_sink;

static inline uint64_t tsc_start(void)
{
    unsigned lo, hi;
    __asm__ __volatile__("lfence\n\trdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}
static inline uint64_t tsc_end(void)
{
    unsigned lo, hi;
    __asm__ __volatile__("rdtscp\n\tlfence" : "=a"(lo), "=d"(hi) : : "%rcx");
    return ((uint64_t)hi << 32) | lo;
}

typedef policy_rule_t *(*find_fn)(canid_t);

static uint64_t bench(find_fn find, const canid_t *probe, uint64_t M)
{
    uintptr_t acc = 0;
    uint64_t t0 = tsc_start();
    for (uint64_t i = 0; i < M; i++)
        acc ^= (uintptr_t)find(probe[i & PROBE_MASK]);
    uint64_t t1 = tsc_end();
    g_sink = acc;              /* impede eliminação do laço */
    return t1 - t0;
}
static uint64_t bench_baseline(const canid_t *probe, uint64_t M)
{
    uintptr_t acc = 0;
    uint64_t t0 = tsc_start();
    for (uint64_t i = 0; i < M; i++)
        acc ^= (uintptr_t)probe[i & PROBE_MASK];  /* mesmo laço, sem busca */
    uint64_t t1 = tsc_end();
    g_sink = acc;
    return t1 - t0;
}

int main(int argc, char **argv)
{
    uint64_t M = (argc > 1) ? strtoull(argv[1], NULL, 10) : 1000000;
    int      R = (argc > 2) ? atoi(argv[2]) : 30;

    srand(42);
    printf("strategy,N,path,rep,lookups,cycles,cycles_per_lookup\n");

    static canid_t hit_probe[PROBE_LEN], miss_probe[PROBE_LEN];
    struct { const char *name; find_fn fn; } strat[] = {
        {"linear", policy_find_linear},
        {"binary", policy_find_binary},
        {"direct", policy_find_direct},
    };

    for (int s = 0; s < SWEEP_COUNT; s++) {
        size_t N = (size_t)g_sweep_sizes[s];
        policy_load_ids(g_micro_ids, N);
        policy_sort_allowlist();
        policy_build_index();

        /* sondas aleatórias: hits = IDs presentes; misses = IDs ausentes */
        for (unsigned i = 0; i < PROBE_LEN; i++)
            hit_probe[i] = g_allowlist[rand() % (int)N].can_id;
        for (unsigned i = 0; i < PROBE_LEN; i++) {
            canid_t id;
            do { id = (canid_t)(rand() & CAN_SFF_MASK); } while (policy_find_direct(id));
            miss_probe[i] = id;
        }

        (void)bench(policy_find_linear, hit_probe, M / 10 + 1);  /* warm-up */

        for (int rep = 0; rep < R; rep++) {
            uint64_t cb = bench_baseline(hit_probe, M);
            printf("baseline,%zu,na,%d,%llu,%llu,%.4f\n", N, rep,
                   (unsigned long long)M, (unsigned long long)cb, (double)cb / M);
            for (int k = 0; k < 3; k++) {
                uint64_t ch = bench(strat[k].fn, hit_probe, M);
                printf("%s,%zu,hit,%d,%llu,%llu,%.4f\n", strat[k].name, N, rep,
                       (unsigned long long)M, (unsigned long long)ch, (double)ch / M);
                uint64_t cm = bench(strat[k].fn, miss_probe, M);
                printf("%s,%zu,miss,%d,%llu,%llu,%.4f\n", strat[k].name, N, rep,
                       (unsigned long long)M, (unsigned long long)cm, (double)cm / M);
            }
        }
    }
    return 0;
}
