/*
 * -----------------------------------------------------------------------
 * Modelo arquitetural
 * -----------------------------------------------------------------------
 *
 *   +--------------------+      +---------+      +---------------------+
 *   | vcan0              |      | Gateway |      | vcan1               |
 *   | (zona comprometida)|----->| (este   |----->| (zona crítica)      |
 *   |  controls, attacker|      |  prog.) |      |  icsim (IC)         |
 *   +--------------------+      +---------+      +---------------------+
 *          ^-- frames             ^-- policy        ^-- só recebe
 *              legítimos + maliciosos                    o que passou
 *
 * O encaminhamento é unidirecional, pois o atacante está do lado externo
 * tentando atingir a ECU interna (ICSim). Um gateway bidirecional fica 
 * como trabalho futuro
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

#include "allowlist.h"

/* Configuração e estado global do gateway */
static const char *g_iface_in = "vcan0";
static const char *g_iface_out = "vcan1";
static int g_verbose = 0;
static volatile sig_atomic_t g_stop = 0;
static uint64_t g_rx_total = 0;

/* Funções auxiliares */
static uint64_t now_monotonic_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

static int open_can_socket(const char *iface) {
    int sock = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (sock < 0) {
        perror("socket(PF_CAN)");
        return -1;
    }

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
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "bind(%s): %s\n", iface, strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

static void on_sigint(int sig) {
    (void)sig;
    g_stop = 1;
}

static void print_usage(const char *prog) {
    fprintf(
        stderr,
        "Uso: %s [opções]\n"
        "  -i <iface>   interface de entrada (default: vcan0)\n"
        "  -o <iface>   interface de saída  (default: vcan1)\n"
        "  --no-dlc     desabilita validação de DLC (estudo ablativo)\n"
        "  --no-rate    desabilita rate-limiting   (estudo ablativo)\n"
        "  -v           verboso (loga cada frame — NÃO usar durante perf!)\n"
        prog);
}

static void print_stats(double elapsed_s) {
    fprintf(stderr,
            "\n========================================================\n"
            " Cenário 2 — Firewall/Gateway: relatório final\n"
            "========================================================\n"
            " Duração de execução .............. %.3f s\n"
            " Frames recebidos em %-6s ....... %" PRIu64 "\n"
            " Frames liberados ................. %" PRIu64 "\n"
            " Frames bloqueados (ID) ........... %" PRIu64 "\n"
            " Frames bloqueados (DLC) .......... %" PRIu64 "\n"
            " Frames bloqueados (rate) ......... %" PRIu64 "\n"
            "--------------------------------------------------------\n",
            elapsed_s, g_iface_in, g_rx_total, g_drops_by_reason[POLICY_PASS],
            g_drops_by_reason[POLICY_REJECT_ID],
            g_drops_by_reason[POLICY_REJECT_DLC],
            g_drops_by_reason[POLICY_REJECT_RATE]);

    fprintf(stderr, " Por ID permitido:\n");
    for (size_t i = 0; i < g_allowlist_size; i++) {
        fprintf(stderr,
                "   0x%03X (%-12s): pass=%-10" PRIu64 " drop=%" PRIu64 "\n",
                g_allowlist[i].can_id, g_allowlist[i].name,
                g_allowlist[i].pass_count, g_allowlist[i].drop_count);
    }

    if (g_rx_total > 0) {
        double block_rate = 100.0 *
                            (double)(g_drops_by_reason[POLICY_REJECT_ID] +
                                     g_drops_by_reason[POLICY_REJECT_DLC] +
                                     g_drops_by_reason[POLICY_REJECT_RATE]) /
                            (double)g_rx_total;
        fprintf(stderr,
                "--------------------------------------------------------\n"
                " Taxa de bloqueio total ........... %.2f %%\n"
                " Throughput médio do gateway ...... %.0f frames/s\n"
                "========================================================\n",
                block_rate,
                (double)g_rx_total / (elapsed_s > 0 ? elapsed_s : 1.0));
    }
}

int main(int argc, char **argv) {
    static struct option long_opts[] = {{"no-dlc", no_argument, 0, 1001},
                                        {"no-rate", no_argument, 0, 1002},
                                        {"help", no_argument, 0, 'h'},
                                        {0, 0, 0, 0}};

    int opt;
    while ((opt = getopt_long(argc, argv, "i:o:vh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i':
            g_iface_in = optarg;
            break;
        case 'o':
            g_iface_out = optarg;
            break;
        case 'v':
            g_verbose = 1;
            break;
        case 1001:
            g_enforce_dlc = false;
            break;
        case 1002:
            g_enforce_rate = false;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);
    signal(SIGPIPE, SIG_IGN);

    int sock_in = open_can_socket(g_iface_in);
    if (sock_in < 0)
        return 2;
    int sock_out = open_can_socket(g_iface_out);
    if (sock_out < 0) {
        close(sock_in);
        return 2;
    }

    fprintf(stderr,
            "[gateway] in=%s out=%s enforce_dlc=%d enforce_rate=%d verbose=%d\n"
            "[gateway] política carregada com %zu regra(s); PID=%d\n",
            g_iface_in, g_iface_out, g_enforce_dlc, g_enforce_rate, g_verbose,
            g_allowlist_size, (int)getpid());

    struct pollfd pfd = {.fd = sock_in, .events = POLLIN};
    struct can_frame cf;
    uint64_t t_start_us = now_monotonic_us();

    while (!g_stop) {
        int pr = poll(&pfd, 1, 500 /* ms */);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            perror("poll");
            break;
        }
        if (pr == 0)
            continue;

        ssize_t n = read(sock_in, &cf, sizeof(cf));
        if (n <= 0) {
            if (errno == EINTR)
                continue;
            perror("read");
            break;
        }
        if (n != (ssize_t)sizeof(cf)) {
            /* descartamos CAN FD , o gateway declara
             * apenas CAN 2.0 clássico no seu modelo de ameaça. */
            g_drops_by_reason[POLICY_REJECT_FD]++;
            continue;
        }

        g_rx_total++;

        uint64_t ts = now_monotonic_us();
        policy_verdict_t v = policy_evaluate(&cf, ts);

        if (v == POLICY_PASS) {
            /* Encaminha para a rede crítica. write() é bloqueante no
             * socket CAN apenas se o buffer do driver estiver cheio —
             * em vcan praticamente nunca ocorre; em hardware real seria
             * necessário lidar com ENOBUFS. */
            if (write(sock_out, &cf, sizeof(cf)) != (ssize_t)sizeof(cf)) {
                if (!g_stop)
                    perror("write(sock_out)");
            }
        }

        if (g_verbose) {
            fprintf(stderr, "[gw] id=0x%03X dlc=%u -> %s\n",
                    cf.can_id & CAN_SFF_MASK, cf.can_dlc,
                    policy_verdict_name(v));
        }
    }

    double elapsed = (double)(now_monotonic_us() - t_start_us) / 1e6;
    close(sock_in);
    close(sock_out);

    print_stats(elapsed);
    return 0;
}
