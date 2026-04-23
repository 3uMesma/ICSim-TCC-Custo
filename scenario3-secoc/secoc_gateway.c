/*
 * secoc_gateway.c - Security Gateway com verificação SecOC-Lite
 *
 *   vcan0  ──►  [ secoc_gateway (verifica MAC e FV) ]  ──►  vcan1
 *   (arame)                                                (zona crítica)
 *
 * Todo frame que chega em vcan0 passa pela função secoc_verify(); apenas
 * os que possuem MAC válido e Freshness Value dentro da janela são
 * encaminhados — *em forma plain* — para vcan1, onde o ICSim os consome
 * sem qualquer modificação.
 *
 * Diferenças do cenário 2: substitui as 3 camadas sintáticas (ID/DLC/Rate) 
 * por 3 camadas criptográficas (ID+DLC/FV/MAC).
 */

#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <linux/can.h>
#include <linux/can/raw.h>

#include "secoc.h"

static const char *g_iface_in  = "vcan0";
static const char *g_iface_out = "vcan1";
static int         g_verbose   = 0;
static int         g_strip     = 1;   /* 1 = remove SecOC antes de reenviar */
static int         g_skip_mac  = 0;
static int         g_skip_fv   = 0;
static volatile sig_atomic_t g_stop = 0;

static uint64_t g_rx_total = 0;
static uint64_t g_fwd_ok   = 0;

static uint64_t now_monotonic_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

static int open_can_socket(const char *iface)
{
    int sock = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (sock < 0) { perror("socket(PF_CAN)"); return -1; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        fprintf(stderr, "ioctl(%s): %s\n", iface, strerror(errno));
        close(sock);
        return -1;
    }
    struct sockaddr_can addr;
    memset(&addr, 0, sizeof(addr));
    addr.can_family  = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "bind(%s): %s\n", iface, strerror(errno));
        close(sock);
        return -1;
    }
    return sock;
}

static void on_sigint(int sig) { (void)sig; g_stop = 1; }

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Uso: %s [opções]\n"
        "  -i <iface>     interface de entrada (default: vcan0)\n"
        "  -o <iface>     interface de saída  (default: vcan1)\n"
        "  --no-strip     encaminha o secured PDU sem remover overhead\n"
        "  --skip-mac     desabilita verificação de MAC (estudo ablativo)\n"
        "  --skip-fv      desabilita verificação de FV  (estudo ablativo)\n"
        "  -v             verboso (NÃO usar durante perf!)\n",
        prog);
}

static void print_stats(double elapsed_s)
{
    uint64_t sum_verdicts =
        g_secoc_counts[SECOC_OK]      +
        g_secoc_counts[SECOC_ERR_ID]  +
        g_secoc_counts[SECOC_ERR_LEN] +
        g_secoc_counts[SECOC_ERR_FV]  +
        g_secoc_counts[SECOC_ERR_MAC] +
        g_secoc_counts[SECOC_ERR_FD];

    fprintf(stderr,
        "\n========================================================\n"
        " Cenário 3 — SecOC gateway: relatório final\n"
        "========================================================\n"
        " Duração de execução .............. %.3f s\n"
        " Frames recebidos em %-6s ....... %" PRIu64 "\n"
        " Frames autenticados (FWD) ........ %" PRIu64 "\n"
        " Verdicts SECOC_OK (pré-write) .... %" PRIu64 "\n"
        " Rejeições por ID desconhecido .... %" PRIu64 "\n"
        " Rejeições por DLC ................ %" PRIu64 "\n"
        " Rejeições por FV (freshness) ..... %" PRIu64 "\n"
        " Rejeições por MAC ................ %" PRIu64 "\n"
        " Rejeições por EFF/CAN-FD ......... %" PRIu64 "\n"
        " [check] Σ verdicts == rx_total ... %s (Σ=%" PRIu64 ")\n"
        "--------------------------------------------------------\n",
        elapsed_s,
        g_iface_in, g_rx_total, g_fwd_ok,
        g_secoc_counts[SECOC_OK],
        g_secoc_counts[SECOC_ERR_ID],
        g_secoc_counts[SECOC_ERR_LEN],
        g_secoc_counts[SECOC_ERR_FV],
        g_secoc_counts[SECOC_ERR_MAC],
        g_secoc_counts[SECOC_ERR_FD],
        (sum_verdicts == g_rx_total ? "OK" : "MISMATCH"),
        sum_verdicts);

    fprintf(stderr, " Por ID associado:\n");
    for (size_t i = 0; i < g_secoc_assocs_size; i++) {
        fprintf(stderr,
            "   0x%03X (%-12s): ok=%-10" PRIu64 " mac_err=%-6" PRIu64
            " fv_err=%-6" PRIu64 " len_err=%" PRIu64 "\n",
            g_secoc_assocs[i].data_id,
            g_secoc_assocs[i].name,
            g_secoc_assocs[i].accepted,
            g_secoc_assocs[i].rej_mac,
            g_secoc_assocs[i].rej_fv,
            g_secoc_assocs[i].rej_len);
    }

    if (g_rx_total > 0 && elapsed_s > 0) {
        double block_rate =
            100.0 * (double)(g_rx_total - g_fwd_ok) / (double)g_rx_total;
        fprintf(stderr,
            "--------------------------------------------------------\n"
            " Taxa de bloqueio total ........... %.2f %%\n"
            " Throughput médio do gateway ...... %.0f frames/s\n"
            " Flags: strip=%d skip_mac=%d skip_fv=%d\n"
            "========================================================\n",
            block_rate, (double)g_rx_total / elapsed_s,
            g_strip, g_skip_mac, g_skip_fv);
    }
}

/* 
 * Verify com ablação opcional — equivalente ao secoc_verify() normal,
 * mas honra as flags --skip-mac e --skip-fv. 
*/
static secoc_result_t verify_with_ablation(const struct can_frame *secured,
                                           struct can_frame *plain)
{
    if (secured->can_id & CAN_EFF_FLAG) {
        g_secoc_counts[SECOC_ERR_FD]++;
        return SECOC_ERR_FD;
    }

    secoc_assoc_t *a = secoc_find(secured->can_id & CAN_SFF_MASK);
    if (a == NULL) {
        g_secoc_counts[SECOC_ERR_ID]++;
        return SECOC_ERR_ID;
    }

    uint8_t expect_dlc = (uint8_t)(a->expected_plain_len + SECOC_OVERHEAD);
    if (secured->can_dlc != expect_dlc) {
        a->rej_len++;
        g_secoc_counts[SECOC_ERR_LEN]++;
        return SECOC_ERR_LEN;
    }

    /* Quando a primitiva completa é habilitada, delega para a biblioteca. */
    if (!g_skip_mac && !g_skip_fv) {
        return secoc_verify(secured, plain);
    }

    /* Caminho com ablação. */
    uint8_t  fv_low   = secured->data[a->expected_plain_len];
    const uint8_t *mac_rx = &secured->data[a->expected_plain_len + SECOC_FV_LEN];
    (void)mac_rx;

    uint32_t fv_full;
    if (!g_skip_fv) {
        uint32_t base = a->fv_rx_expected & 0xFFFFFF00u;
        fv_full = base | fv_low;
        if (fv_full < a->fv_rx_expected) fv_full += 0x100;
        if (fv_full - a->fv_rx_expected >= SECOC_FRESHNESS_WINDOW) {
            a->rej_fv++;
            g_secoc_counts[SECOC_ERR_FV]++;
            return SECOC_ERR_FV;
        }
    } else {
        fv_full = a->fv_rx_expected;
    }

    if (!g_skip_mac) {
        uint8_t auth_in[8 + SECOC_MAX_PLAIN_LEN];
        auth_in[0] = (uint8_t)((secured->can_id & CAN_SFF_MASK) >> 24);
        auth_in[1] = (uint8_t)((secured->can_id & CAN_SFF_MASK) >> 16);
        auth_in[2] = (uint8_t)((secured->can_id & CAN_SFF_MASK) >> 8);
        auth_in[3] = (uint8_t)(secured->can_id & CAN_SFF_MASK);
        auth_in[4] = (uint8_t)(fv_full >> 24);
        auth_in[5] = (uint8_t)(fv_full >> 16);
        auth_in[6] = (uint8_t)(fv_full >> 8);
        auth_in[7] = (uint8_t)(fv_full);
        memcpy(auth_in + 8, secured->data, a->expected_plain_len);

        uint8_t tag[16];
        aes_cmac(SECOC_DEMO_KEY, auth_in, 8 + a->expected_plain_len, tag);

        uint8_t diff = 0;
        for (size_t i = 0; i < SECOC_MAC_LEN; i++) {
            diff |= (uint8_t)(mac_rx[i] ^ tag[i]);
        }
        if (diff != 0) {
            a->rej_mac++;
            g_secoc_counts[SECOC_ERR_MAC]++;
            return SECOC_ERR_MAC;
        }
    }

    a->fv_rx_expected = fv_full + 1;
    a->accepted++;
    g_secoc_counts[SECOC_OK]++;

    plain->can_id  = secured->can_id;
    plain->can_dlc = a->expected_plain_len;
    memcpy(plain->data, secured->data, a->expected_plain_len);
    memset(plain->data + a->expected_plain_len, 0,
           CAN_MAX_DLEN - a->expected_plain_len);
    return SECOC_OK;
}

int main(int argc, char **argv)
{
    static struct option long_opts[] = {
        {"no-strip",  no_argument, 0, 1001},
        {"skip-mac",  no_argument, 0, 1002},
        {"skip-fv",   no_argument, 0, 1003},
        {"help",      no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:o:vh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i':  g_iface_in  = optarg; break;
        case 'o':  g_iface_out = optarg; break;
        case 'v':  g_verbose   = 1; break;
        case 1001: g_strip     = 0; break;
        case 1002: g_skip_mac  = 1; break;
        case 1003: g_skip_fv   = 1; break;
        case 'h':  print_usage(argv[0]); return 0;
        default:   print_usage(argv[0]); return 1;
        }
    }

    signal(SIGINT,  on_sigint);
    signal(SIGTERM, on_sigint);
    signal(SIGPIPE, SIG_IGN);

    secoc_init(SECOC_DEMO_KEY);

    int sock_in  = open_can_socket(g_iface_in);
    if (sock_in  < 0) return 2;
    int sock_out = open_can_socket(g_iface_out);
    if (sock_out < 0) { close(sock_in); return 2; }

    fprintf(stderr,
        "[gateway] in=%s out=%s strip=%d skip_mac=%d skip_fv=%d verbose=%d PID=%d\n"
        "[gateway] %zu associação(ões) SecOC carregada(s)\n",
        g_iface_in, g_iface_out,
        g_strip, g_skip_mac, g_skip_fv, g_verbose, (int)getpid(),
        g_secoc_assocs_size);

    struct pollfd pfd = { .fd = sock_in, .events = POLLIN };
    struct can_frame cf_in, cf_out;
    uint64_t t_start_us = now_monotonic_us();

    while (!g_stop) {
        int pr = poll(&pfd, 1, 500);
        if (pr < 0) { if (errno == EINTR) continue; perror("poll"); break; }
        if (pr == 0) continue;

        ssize_t n = read(sock_in, &cf_in, sizeof(cf_in));
        if (n <= 0) { if (errno == EINTR) continue; perror("read"); break; }
        if (n != (ssize_t)sizeof(cf_in)) continue;

        g_rx_total++;

        secoc_result_t r = verify_with_ablation(&cf_in, &cf_out);

        if (r == SECOC_OK) {
            const struct can_frame *to_send = g_strip ? &cf_out : &cf_in;
            if (write(sock_out, to_send, sizeof(*to_send)) !=
                (ssize_t)sizeof(*to_send)) {
                if (!g_stop) perror("write(sock_out)");
            } else {
                g_fwd_ok++;
            }
        }

        if (g_verbose) {
            fprintf(stderr, "[gw] id=0x%03X dlc=%u -> %s\n",
                cf_in.can_id & CAN_SFF_MASK, cf_in.can_dlc,
                secoc_result_name(r));
        }
    }

    double elapsed = (double)(now_monotonic_us() - t_start_us) / 1e6;
    close(sock_in);
    close(sock_out);
    print_stats(elapsed);
    return 0;
}
