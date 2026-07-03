/*
 * passthrough.c — Forwarder transparente vcan0 -> vcan1.
 * 
 * Este binário é o BASELINE process-attached da campanha. Ele encaminha todo
 * frame recebido em vcan0 para vcan1 SEM aplicar nenhuma política de
 * segurança. Existe exclusivamente para que a comparação entre cenários seja justa.
 *
 * Compila em dois modos (Trilha B / D0):
 *   - clássico (default): struct can_frame, socket CAN 2.0.
 *   - CAN FD (-DFD_MODE): struct canfd_frame + CAN_RAW_FD_FRAMES.
 * O par {passthrough, passthrough-fd} isola o delta de I/O clássico↔FD
 * (struct de 16 B vs 72 B transferida por syscall).
 *
 * Modelo arquitetural (idêntico ao cen2, apenas sem allowlist):
 * ---------------------------------------------------------------------------
 *
 *   +--------------------+      +-------------+      +---------------------+
 *   | vcan0              |      | Passthrough |      | vcan1               |
 *   | (zona comprometida)|----->| (este       |----->| (zona crítica)      |
 *   |  controls, attacker|      |  programa)  |      |  icsim (IC)         |
 *   +--------------------+      +-------------+      +---------------------+
 *          ^-- frames               ^-- nenhuma      ^-- recebe TODOS
 *              legítimos + maliciosos     filtragem       (incl. ataque)
 *
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

#ifdef FD_MODE
typedef struct canfd_frame frame_t;
#  define FRAME_LEN(f)  ((f).len)
#else
typedef struct can_frame frame_t;
#  define FRAME_LEN(f)  ((f).can_dlc)
#endif

/* Configuração e estado global */
static const char *g_iface_in = "vcan0";
static const char *g_iface_out = "vcan1";
static int g_verbose = 0;
static volatile sig_atomic_t g_stop = 0;

static uint64_t g_rx_total = 0;
static uint64_t g_fwd_total = 0;
static uint64_t g_drop_fd = 0;      /* descartes por tamanho de frame inválido  */
static uint64_t g_drop_write = 0;   /* falhas em write() — diagnóstico apenas    */

/* Funções auxiliares (idênticas à gateway.c para manter comparabilidade) */
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

#ifdef FD_MODE
    int enable_fd = 1;
    if (setsockopt(sock, SOL_CAN_RAW, CAN_RAW_FD_FRAMES,
                   &enable_fd, sizeof(enable_fd)) < 0) {
        fprintf(stderr, "setsockopt(CAN_RAW_FD_FRAMES,%s): %s\n",
                iface, strerror(errno));
        close(sock);
        return -1;
    }
#endif

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
    fprintf(stderr,
            "Uso: %s [opções]\n"
            "  -i <iface>   interface de entrada (default: vcan0)\n"
            "  -o <iface>   interface de saída  (default: vcan1)\n"
            "  -v           verboso (loga cada frame — NÃO usar durante perf!)\n"
            "  -h           ajuda\n",
            prog);
}

/* Relatório final — mesmo formato textual e ordem de campos do cen2 e cen3 */
static void print_stats(double elapsed_s) {
    fprintf(stderr,
            "\n========================================================\n"
            " Cenário 1 — Passthrough (baseline sem segurança)\n"
            "========================================================\n"
            " Duração de execução .............. %.3f s\n"
            " Frames recebidos em %-6s ....... %" PRIu64 "\n"
            " Frames liberados ................. %" PRIu64 "\n"
            " Frames bloqueados (ID) ........... 0\n"
            " Frames bloqueados (DLC) .......... 0\n"
            " Frames bloqueados (rate) ......... 0\n"
            " Descartes por tamanho de frame ... %" PRIu64 "\n"
            " Falhas em write() ................ %" PRIu64 "\n"
            "--------------------------------------------------------\n",
            elapsed_s, g_iface_in, g_rx_total, g_fwd_total,
            g_drop_fd, g_drop_write);

    if (g_rx_total > 0 && elapsed_s > 0.0) {
        fprintf(stderr,
                " Taxa de bloqueio total ........... 0.00 %%\n"
                " Throughput médio do gateway ...... %.0f frames/s\n"
                "========================================================\n",
                (double)g_rx_total / elapsed_s);
    } else {
        fprintf(stderr,
                "========================================================\n");
    }
}

int main(int argc, char **argv) {
    static struct option long_opts[] = {
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0},
    };

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
            "[passthrough] in=%s out=%s verbose=%d PID=%d\n"
            "[passthrough] sem allowlist, sem MAC — encaminha tudo\n",
            g_iface_in, g_iface_out, g_verbose, (int)getpid());

    struct pollfd pfd = {.fd = sock_in, .events = POLLIN};
    frame_t cf;
    uint64_t t_start_us = now_monotonic_us();

    while (!g_stop) {
        /* Mesmo timeout de poll que gateway.c — garante que o perfil
         * de syscalls e o número de wakeups por segundo seja comparável. */
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
#ifdef FD_MODE
        /* Aceita tanto frame clássico (CAN_MTU) quanto FD (CANFD_MTU). */
        if (n != (ssize_t)CAN_MTU && n != (ssize_t)CANFD_MTU) {
            g_drop_fd++;
            continue;
        }
#else
        if (n != (ssize_t)sizeof(cf)) {
            /* CAN FD vem com sizeof(canfd_frame); descartamos para alinhar
             * com o modelo de ameaça do gateway (apenas CAN 2.0 clássico). */
            g_drop_fd++;
            continue;
        }
#endif

        g_rx_total++;

        /* Encaminhamento incondicional */
        if (write(sock_out, &cf, sizeof(cf)) != (ssize_t)sizeof(cf)) {
            if (!g_stop) {
                /* Não polui o perf com perror aqui; só contabiliza. */
                g_drop_write++;
            }
        } else {
            g_fwd_total++;
        }

        if (g_verbose) {
            fprintf(stderr, "[pt] id=0x%03X len=%u -> FWD\n",
                    cf.can_id & CAN_SFF_MASK, FRAME_LEN(cf));
        }
    }

    double elapsed = (double)(now_monotonic_us() - t_start_us) / 1e6;
    close(sock_in);
    close(sock_out);

    print_stats(elapsed);
    return 0;
}
