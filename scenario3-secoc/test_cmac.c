/* test_cmac.c — validação da Fase 1:
 *   (1) vetores RFC 4493 / NIST SP 800-38B contra aes.c + cmac.c (primitiva);
 *   (2) round-trip SecOC-FD (protect/verify) + rejeições, no sweep de payload.
 * A primitiva não mudou na migração FD; os vetores seguem válidos.
 */
#include "secoc.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(c, msg) do { if (!(c)) { printf("  FALHA: %s\n", msg); g_fail = 1; } } while (0)

/* ---- (1) RFC 4493 -------------------------------------------------------- */
static const uint8_t RFC_KEY[16] = {
    0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
    0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,
};
static const uint8_t RFC_MSG[64] = {
    0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
    0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
    0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
    0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10,
};
static const struct { size_t len; uint8_t exp[16]; } RFC_VEC[] = {
    {0,  {0xbb,0x1d,0x69,0x29,0xe9,0x59,0x37,0x28,0x7f,0xa3,0x7d,0x12,0x9b,0x75,0x67,0x46}},
    {16, {0x07,0x0a,0x16,0xb4,0x6b,0x4d,0x41,0x44,0xf7,0x9b,0xdd,0x9d,0xd0,0x4a,0x28,0x7c}},
    {40, {0xdf,0xa6,0x67,0x47,0xde,0x9a,0xe6,0x30,0x30,0xca,0x32,0x61,0x14,0x97,0xc8,0x27}},
    {64, {0x51,0xf0,0xbe,0xbf,0x7e,0x3b,0x9d,0x92,0xfc,0x49,0x74,0x17,0x79,0x36,0x3c,0xfe}},
};

static void test_rfc4493(void)
{
    printf("[1] Vetores RFC 4493 / NIST SP 800-38B:\n");
    for (size_t i = 0; i < sizeof(RFC_VEC) / sizeof(RFC_VEC[0]); i++) {
        uint8_t tag[16];
        aes_cmac(RFC_KEY, RFC_MSG, RFC_VEC[i].len, tag);
        int ok = memcmp(tag, RFC_VEC[i].exp, 16) == 0;
        printf("  len=%2zu ... %s\n", RFC_VEC[i].len, ok ? "ok" : "FALHA");
        CHECK(ok, "vetor RFC 4493");
    }
}

/* ---- (2) round-trip SecOC-FD -------------------------------------------- */
static void reset_assoc(uint8_t plain_len)
{
    memset(&g_secoc_assocs[0], 0, sizeof(g_secoc_assocs[0]));
    g_secoc_assocs[0].data_id            = 0x244;
    g_secoc_assocs[0].expected_plain_len = plain_len;
    g_secoc_assocs[0].name               = "SPEED";
}

static struct canfd_frame mk_plain(canid_t id, uint8_t len)
{
    struct canfd_frame f;
    memset(&f, 0, sizeof(f));
    f.can_id = id;
    f.len    = len;
    for (uint8_t i = 0; i < len; i++) f.data[i] = (uint8_t)(0xA0 + i);
    return f;
}

static void test_fd_roundtrip(void)
{
    printf("[2] Round-trip SecOC-FD (protect/verify) no sweep:\n");
    secoc_init(SECOC_DEMO_KEY);
    const uint8_t sweep[] = {4, 8, 20, 36, 52};

    for (size_t s = 0; s < sizeof(sweep); s++) {
        uint8_t L = sweep[s];
        struct canfd_frame plain, secured, out;

        reset_assoc(L);
        plain = mk_plain(0x244, L);
        CHECK(secoc_protect(&plain, &secured) == SECOC_OK, "protect OK");
        CHECK(secured.len == (uint8_t)(L + SECOC_OVERHEAD), "secured.len = plain+12");
        CHECK(secoc_verify(&secured, &out) == SECOC_OK, "verify OK");
        CHECK(out.len == L && memcmp(out.data, plain.data, L) == 0, "payload recuperado");
        CHECK(secoc_verify(&secured, &out) == SECOC_ERR_FV, "replay -> ERR_FV");

        reset_assoc(L);
        plain = mk_plain(0x244, L);
        secoc_protect(&plain, &secured);
        secured.data[0] ^= 0xFF;
        CHECK(secoc_verify(&secured, &out) == SECOC_ERR_MAC, "tamper -> ERR_MAC");

        reset_assoc(L);
        plain = mk_plain(0x244, L);
        secoc_protect(&plain, &secured);
        secured.len += 1;
        CHECK(secoc_verify(&secured, &out) == SECOC_ERR_LEN, "len -> ERR_LEN");

        reset_assoc(L);
        plain = mk_plain(0x244, L);
        secoc_protect(&plain, &secured);
        secured.can_id = 0x123;
        CHECK(secoc_verify(&secured, &out) == SECOC_ERR_ID, "id -> ERR_ID");

        reset_assoc(L);
        plain = mk_plain(0x244, L);
        secoc_protect(&plain, &secured);
        secured.can_id = 0x244 | CAN_EFF_FLAG;
        CHECK(secoc_verify(&secured, &out) == SECOC_ERR_FD, "EFF -> ERR_FD");

        printf("  len=%2u blocos=%zu secured=%2u ... ok\n",
               L, (size_t)((8 + L + 15) / 16), (uint8_t)(L + SECOC_OVERHEAD));
    }
}

int main(void)
{
    test_rfc4493();
    test_fd_roundtrip();
    printf(g_fail ? "\nFALHOU\n"
                  : "\nOK — Fase 1 validada (RFC 4493 + round-trip FD)\n");
    return g_fail;
}
