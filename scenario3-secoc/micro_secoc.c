/* 
 * Isola o custo de secoc_protect/secoc_verify em ciclos (rdtscp), por ponto
 * do sweep de payload {4,8,20,36,52}.
 *
 * Método: pin de core (rig deve passar um core isolado), warm-up, seed fixa.
 * O verify tem o FV resetado fora do trecho medido para sempre alcançar o MAC
 * (do contrário vira replay e morre barato antes da cripto).
 */

#define _GNU_SOURCE
#include "secoc.h"

#include <getopt.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if !defined(__x86_64__) && !defined(__i386__)
#error "micro_secoc requer x86 (rdtscp)"
#endif

static inline uint64_t rdtsc_begin(void)
{
    unsigned lo, hi;
    __asm__ __volatile__("lfence\n\trdtsc" : "=a"(lo), "=d"(hi) :: "memory");
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t rdtsc_end(void)
{
    unsigned lo, hi, aux;
    __asm__ __volatile__("rdtscp\n\tlfence" : "=a"(lo), "=d"(hi), "=c"(aux) :: "memory");
    return ((uint64_t)hi << 32) | lo;
}

static void pin_cpu(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0)
        fprintf(stderr, "[micro] aviso: sched_setaffinity(cpu=%d) falhou — segue sem pin\n", cpu);
}

/* Preenchimento determinístico (LCG). O conteúdo não afeta o custo do AES,
 * mas fixa a reprodutibilidade. */
static void fill_seeded(uint8_t *buf, size_t n, uint32_t seed)
{
    uint32_t x = seed ? seed : 1u;
    for (size_t i = 0; i < n; i++) {
        x = x * 1664525u + 1013904223u;
        buf[i] = (uint8_t)(x >> 24);
    }
}

static void reset_assoc(uint8_t plain_len)
{
    memset(&g_secoc_assocs[0], 0, sizeof(g_secoc_assocs[0]));
    g_secoc_assocs[0].data_id            = 0x244;
    g_secoc_assocs[0].expected_plain_len = plain_len;
    g_secoc_assocs[0].name               = "SPEED";
}

static int cmp_long(const void *a, const void *b)
{
    long x = *(const long *)a, y = *(const long *)b;
    return (x > y) - (x < y);
}

/* Percentil por nearest-rank sobre um array já ordenado. */
static long pct(const long *sorted, int n, double p)
{
    int i = (int)((n - 1) * p);
    return sorted[i];
}

/* Regressão linear simples y = c0 + c1*x (mínimos quadrados). */
static void fit(const double *x, const double *y, int n,
                double *c0, double *c1, double *r2)
{
    double sx = 0, sy = 0;
    for (int i = 0; i < n; i++) { sx += x[i]; sy += y[i]; }
    double mx = sx / n, my = sy / n, sxy = 0, sxx = 0;
    for (int i = 0; i < n; i++) { sxy += (x[i]-mx)*(y[i]-my); sxx += (x[i]-mx)*(x[i]-mx); }
    *c1 = sxy / sxx;
    *c0 = my - *c1 * mx;
    double ssr = 0, sst = 0;
    for (int i = 0; i < n; i++) {
        double e = y[i] - (*c0 + *c1 * x[i]);
        ssr += e * e; sst += (y[i]-my)*(y[i]-my);
    }
    *r2 = 1 - ssr / sst;
}

/* Warm-up global: satura o core antes de qualquer medição para fixar a
 * frequência (HWP/P-state). O warm-up por grupo não basta — sem isto, o 1º
 * grupo medido sai em P-state baixo (freq menor => mais ticks de TSC). */
static void global_warmup(long iters)
{
    struct canfd_frame p, s;
    memset(&p, 0, sizeof(p));
    p.can_id = 0x244;
    p.len    = SECOC_MAX_PLAIN_LEN;
    reset_assoc(SECOC_MAX_PLAIN_LEN);
    volatile uint8_t sink = 0;
    for (long i = 0; i < iters; i++) { secoc_protect(&p, &s); sink ^= s.data[0]; }
    (void)sink;
}

int main(int argc, char **argv)
{
    int cpu = 1, reps = 200, warmup = 5000;
    long gwarm = 1000000;   /* warm-up global — fixa a frequência antes de medir */
    uint32_t seed = 42;

    int opt;
    while ((opt = getopt(argc, argv, "c:r:w:W:s:h")) != -1) {
        switch (opt) {
        case 'c': cpu    = atoi(optarg); break;
        case 'r': reps   = atoi(optarg); break;
        case 'w': warmup = atoi(optarg); break;
        case 'W': gwarm  = atol(optarg); break;
        case 's': seed   = (uint32_t)strtoul(optarg, NULL, 10); break;
        default:
            fprintf(stderr, "uso: %s [-c cpu] [-r reps] [-w warmup] [-W global_warmup] [-s seed]\n", argv[0]);
            return 1;
        }
    }

    pin_cpu(cpu);
    secoc_init(SECOC_DEMO_KEY);
    global_warmup(gwarm);   /* fixa a frequência antes de medir */

    volatile uint64_t sink = 0;
    enum { NSW = 5 };
    const uint8_t sweep[NSW] = {4, 8, 20, 36, 52};

    /* Buffers por grupo para o resumo (mediana/IQR) no fim. */
    long *ovh = malloc((size_t)reps * sizeof(long));
    long *samp[2][NSW];
    for (int o = 0; o < 2; o++)
        for (int i = 0; i < NSW; i++) samp[o][i] = malloc((size_t)reps * sizeof(long));

    printf("op,plain,blocks,rep,cycles,cycles_per_op\n");

    /* Calibração do overhead do par rdtsc/rdtscp (região vazia). */
    for (int r = 0; r < reps; r++) {
        uint64_t t0 = rdtsc_begin();
        uint64_t t1 = rdtsc_end();
        long c = (long)(t1 - t0);
        ovh[r] = c;
        printf("rdtsc_ovh,0,0,%d,%ld,%ld\n", r + 1, c, c);
    }

    for (int s = 0; s < NSW; s++) {
        uint8_t L      = sweep[s];
        size_t  blocks = (size_t)((8 + L + 15) / 16);

        struct canfd_frame plain, secured, out;
        memset(&plain, 0, sizeof(plain));
        plain.can_id = 0x244;
        plain.len    = L;
        fill_seeded(plain.data, L, seed);

        /* ---- protect ---- */
        reset_assoc(L);
        for (int w = 0; w < warmup; w++) {
            secoc_result_t pr = secoc_protect(&plain, &secured);
            sink ^= (uint64_t)pr ^ secured.data[L + SECOC_FV_LEN];
        }
        for (int r = 0; r < reps; r++) {
            uint64_t t0 = rdtsc_begin();
            secoc_result_t pr = secoc_protect(&plain, &secured);
            uint64_t t1 = rdtsc_end();
            sink ^= (uint64_t)pr ^ secured.data[L + SECOC_FV_LEN];
            long c = (long)(t1 - t0);
            samp[0][s][r] = c;
            printf("protect,%u,%zu,%d,%ld,%ld\n", (unsigned)L, blocks, r + 1, c, c);
        }

        /* ---- verify ---- (FV resetada fora do trecho medido) */
        reset_assoc(L);
        secoc_protect(&plain, &secured);   /* secured com FV=0 */
        for (int w = 0; w < warmup; w++) {
            g_secoc_assocs[0].fv_rx_expected = 0;
            secoc_result_t vr = secoc_verify(&secured, &out);
            sink ^= (uint64_t)vr ^ out.data[0];
        }
        for (int r = 0; r < reps; r++) {
            g_secoc_assocs[0].fv_rx_expected = 0;   /* untimed */
            uint64_t t0 = rdtsc_begin();
            secoc_result_t vr = secoc_verify(&secured, &out);
            uint64_t t1 = rdtsc_end();
            sink ^= (uint64_t)vr ^ out.data[0];
            long c = (long)(t1 - t0);
            samp[1][s][r] = c;
            printf("verify,%u,%zu,%d,%ld,%ld\n", (unsigned)L, blocks, r + 1, c, c);
        }
    }

    /* ---- resumo por ponto (stderr): mediana + IQR, robusto a outliers ---- */
    qsort(ovh, (size_t)reps, sizeof(long), cmp_long);
    fprintf(stderr, "\n[micro] cpu=%d reps=%d warmup=%d gwarm=%ld seed=%u sink=%llu\n",
            cpu, reps, warmup, gwarm, seed, (unsigned long long)sink);
    fprintf(stderr, "[micro] overhead rdtsc: mediana=%ld min=%ld\n",
            pct(ovh, reps, 0.50), ovh[0]);
    fprintf(stderr, "[micro] resumo por ponto (mediana e IQR — robusto a outliers de escalonamento):\n");
    fprintf(stderr, "  %-8s %5s %4s %6s %8s %8s %8s %8s %7s\n",
            "op", "plain", "blk", "n", "min", "Q1", "mediana", "Q3", "IQR");

    double bx[2][NSW], my[2][NSW];
    const char *opn[2] = {"protect", "verify"};
    for (int o = 0; o < 2; o++) {
        for (int s = 0; s < NSW; s++) {
            long *a = samp[o][s];
            qsort(a, (size_t)reps, sizeof(long), cmp_long);
            long q1 = pct(a, reps, 0.25), md = pct(a, reps, 0.50), q3 = pct(a, reps, 0.75);
            size_t blocks = (size_t)((8 + sweep[s] + 15) / 16);
            bx[o][s] = (double)blocks;
            my[o][s] = (double)md;
            fprintf(stderr, "  %-8s %5u %4zu %6d %8ld %8ld %8ld %8ld %7ld\n",
                    opn[o], (unsigned)sweep[s], blocks, reps, a[0], q1, md, q3, q3 - q1);
        }
    }

    /* Ajuste indicativo mediana ~ c0 + c1*b (autoritativo = Fase 4, com IC). */
    for (int o = 0; o < 2; o++) {
        double c0, c1, r2;
        fit(bx[o], my[o], NSW, &c0, &c1, &r2);
        fprintf(stderr, "[micro] %-7s (indicativo): c0=%.0f cyc  c1=%.0f cyc/bloco  R2=%.4f\n",
                opn[o], c0, c1, r2);
    }

    free(ovh);
    for (int o = 0; o < 2; o++)
        for (int i = 0; i < NSW; i++) free(samp[o][i]);
    return 0;
}