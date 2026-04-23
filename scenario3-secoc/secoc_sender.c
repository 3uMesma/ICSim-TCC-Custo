/*
 * secoc_sender.c - ECU "autenticadora"
 *
 *   +------------+   +------------+   +-----------+   +-------------+   +----------+
 *   | controls.c |-->| vcan_trust |-->| secoc_    |-->|   vcan0     |-->| secoc_   |
 *   |            |   |            |   | sender    |   |             |   | gateway  |
 *   +------------+   +------------+   +-----------+   +-------------+   +----------+
 *                                           |                                |
 *                                           |                                v
 *                                           |                          +----------+
 *                                           |                          |  vcan1   |
 *                                           |                          +----------+
 *                                           |                                |
 *                                           |                                v
 *                                           |                          +----------+
 *                                           |                          |  icsim   |
 *                                           |                          +----------+
 *                                           |
 *                                         attacker -- injeta cru em vcan0
 *                                                  ( sem MAC válido )
 *
 * Esta arquitetura é fiel ao modelo real:
 *
 *   * O ECU emissor (aqui: secoc_sender) é o único detentor legítimo da
 *     chave simétrica: ele *produz* MAC+FV.
 *   * O Security Gateway (secoc_gateway) também tem a chave e *verifica*
 *     cada mensagem antes de ceder a zona crítica.
 *   * controls.c permanece inalterado — roda em vcan_trusted, o que
 *     corresponde a uma sub-rede CAN interna sem adversário
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

static const char *g_iface_in  = "vcan_trust";
static const char *g_iface_out = "vcan0";
static int         g_verbose   = 0;
static volatile sig_atomic_t g_stop = 0;

static uint64_t g_rx_total   = 0;
static uint64_t g_tx_ok      = 0;
static uint64_t g_tx_dropped = 0;

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
        "  -i <iface>   interface confiável (default: vcan_trust)\n"
        "  -o <iface>   interface de saída   (default: vcan0)\n"
        "  -v           verboso (NÃO usar em medição)\n",
        prog);
}

static void print_stats(double elapsed_s)
{
    fprintf(stderr,
        "\n========================================================\n"
        " Cenário 3 — SecOC sender: relatório final\n"
        "========================================================\n"
        " Duração de execução .............. %.3f s\n"
        " Frames lidos em %-10s ........ %" PRIu64 "\n"
        " Frames autenticados (TX) ......... %" PRIu64 "\n"
        " Frames descartados (ID/LEN) ...... %" PRIu64 "\n"
        "--------------------------------------------------------\n",
        elapsed_s, g_iface_in, g_rx_total, g_tx_ok, g_tx_dropped);

    fprintf(stderr, " Por ID associado:\n");
    for (size_t i = 0; i < g_secoc_assocs_size; i++) {
        fprintf(stderr,
            "   0x%03X (%-12s): sent=%-10" PRIu64
            " fv_tx=%" PRIu32 "\n",
            g_secoc_assocs[i].data_id, g_secoc_assocs[i].name,
            g_secoc_assocs[i].sent, g_secoc_assocs[i].fv_tx);
    }

    if (elapsed_s > 0) {
        fprintf(stderr,
            "--------------------------------------------------------\n"
            " Throughput médio de autenticação .. %.0f frames/s\n"
            "========================================================\n",
            (double)g_tx_ok / elapsed_s);
    }
}

int main(int argc, char **argv)
{
    int opt;
    while ((opt = getopt(argc, argv, "i:o:vh")) != -1) {
        switch (opt) {
        case 'i': g_iface_in  = optarg; break;
        case 'o': g_iface_out = optarg; break;
        case 'v': g_verbose   = 1; break;
        case 'h': print_usage(argv[0]); return 0;
        default:  print_usage(argv[0]); return 1;
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
        "[sender] in=%s out=%s PID=%d chave=%02x%02x%02x...%02x (128 bits)\n",
        g_iface_in, g_iface_out, (int)getpid(),
        SECOC_DEMO_KEY[0], SECOC_DEMO_KEY[1], SECOC_DEMO_KEY[2],
        SECOC_DEMO_KEY[SECOC_KEY_LEN - 1]);

    struct pollfd pfd = { .fd = sock_in, .events = POLLIN };
    struct can_frame plain, secured;
    uint64_t t_start_us = now_monotonic_us();

    while (!g_stop) {
        int pr = poll(&pfd, 1, 500);
        if (pr < 0) { if (errno == EINTR) continue; perror("poll"); break; }
        if (pr == 0) continue;

        ssize_t n = read(sock_in, &plain, sizeof(plain));
        if (n <= 0) { if (errno == EINTR) continue; perror("read"); break; }
        if (n != (ssize_t)sizeof(plain)) continue;
        g_rx_total++;

        secoc_result_t r = secoc_protect(&plain, &secured);
        if (r != SECOC_OK) {
            g_tx_dropped++;
            if (g_verbose) {
                fprintf(stderr, "[sender] drop id=0x%03X dlc=%u reason=%s\n",
                    plain.can_id & CAN_SFF_MASK, plain.can_dlc,
                    secoc_result_name(r));
            }
            continue;
        }

        if (write(sock_out, &secured, sizeof(secured)) != (ssize_t)sizeof(secured)) {
            if (!g_stop) perror("write(sock_out)");
            continue;
        }
        g_tx_ok++;

        if (g_verbose) {
            fprintf(stderr, "[sender] auth id=0x%03X dlc=%u -> dlc=%u fv=%u\n",
                plain.can_id & CAN_SFF_MASK,
                plain.can_dlc, secured.can_dlc,
                (unsigned)secured.data[plain.can_dlc]);
        }
    }

    double elapsed = (double)(now_monotonic_us() - t_start_us) / 1e6;
    close(sock_in);
    close(sock_out);
    print_stats(elapsed);
    return 0;
}
