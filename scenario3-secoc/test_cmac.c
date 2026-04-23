/*
 * test_cmac.c - Validação de aes.c + cmac.c pelos vetores normativos.
 *
 * Vetores:
 *   [V1] FIPS 197
 *   [V2] RFC 4493
 *   [V3] NIST SP 800-38B
 * 
 * Validar essas quatro mensagens cobre as duas ramificações do CMAC
 * (mensagem completa → K1; mensagem precisando de padding → K2) e
 * verifica também o encadeamento de blocos.
 */

#include "secoc.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int hex_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

static void dump(const char *label, const uint8_t *x, size_t n)
{
    printf("  %s = ", label);
    for (size_t i = 0; i < n; i++) printf("%02x", x[i]);
    printf("\n");
}

/* Chave comum a FIPS 197 / RFC 4493 / SP 800-38B. */
static const uint8_t K[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

/* Mensagens dos quatro casos da RFC 4493 §4. */
static const uint8_t M16[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
};
static const uint8_t M40[] = {
    0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
    0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
    0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
    0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
    0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
};
static const uint8_t M64[] = {
    0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
    0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
    0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
    0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
    0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
    0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
    0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
    0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10,
};

/* Tags esperados (RFC 4493 §4 / SP 800-38B D.1). */
static const uint8_t T0 [16] = {
    0xbb,0x1d,0x69,0x29,0xe9,0x59,0x37,0x28,
    0x7f,0xa3,0x7d,0x12,0x9b,0x75,0x67,0x46,
};
static const uint8_t T16[16] = {
    0x07,0x0a,0x16,0xb4,0x6b,0x4d,0x41,0x44,
    0xf7,0x9b,0xdd,0x9d,0xd0,0x4a,0x28,0x7c,
};
static const uint8_t T40[16] = {
    0xdf,0xa6,0x67,0x47,0xde,0x9a,0xe6,0x30,
    0x30,0xca,0x32,0x61,0x14,0x97,0xc8,0x27,
};
static const uint8_t T64[16] = {
    0x51,0xf0,0xbe,0xbf,0x7e,0x3b,0x9d,0x92,
    0xfc,0x49,0x74,0x17,0x79,0x36,0x3c,0xfe,
};

/* Vetor FIPS 197 Appendix B: testa só a cifra, não o CMAC. */
static const uint8_t FIPS_PT[16] = {
    0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
    0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34,
};
static const uint8_t FIPS_K [16] = {
    0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
    0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,
};
static const uint8_t FIPS_CT[16] = {
    0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,
    0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32,
};

static int check(const char *name, const uint8_t *got,
                 const uint8_t *want, size_t n)
{
    if (hex_eq(got, want, n)) {
        printf("[ok ] %s\n", name);
        return 0;
    }
    printf("[FAIL] %s\n", name);
    dump("got ", got,  n);
    dump("want", want, n);
    return 1;
}

int main(void)
{
    int fails = 0;

    /* ----- FIPS 197 Appendix B (AES-128) ----- */
    aes128_ctx_t ctx;
    aes128_init(&ctx, FIPS_K);
    uint8_t ct[16];
    aes128_encrypt_block(&ctx, FIPS_PT, ct);
    fails += check("FIPS 197 App. B encrypt", ct, FIPS_CT, 16);

    /* ----- RFC 4493 §4 (quatro casos) ----- */
    uint8_t tag[16];

    aes_cmac(K, NULL, 0, tag);
    fails += check("RFC 4493 §4 — empty msg", tag, T0, 16);

    aes_cmac(K, M16, sizeof(M16), tag);
    fails += check("RFC 4493 §4 — 16-byte msg", tag, T16, 16);

    aes_cmac(K, M40, sizeof(M40), tag);
    fails += check("RFC 4493 §4 — 40-byte msg", tag, T40, 16);

    aes_cmac(K, M64, sizeof(M64), tag);
    fails += check("RFC 4493 §4 — 64-byte msg", tag, T64, 16);

    /* ----- Smoke test: protect/verify são inversos entre si ----- */
    secoc_init(SECOC_DEMO_KEY);

    struct can_frame plain = {0};
    plain.can_id  = 0x244;
    plain.can_dlc = 5;
    uint8_t p[5] = {0x10, 0x20, 0x30, 0x40, 0x50};
    memcpy(plain.data, p, 5);

    /* Zera estado para smoke test reprodutível. */
    for (size_t i = 0; i < g_secoc_assocs_size; i++) {
        g_secoc_assocs[i].fv_tx = 0;
        g_secoc_assocs[i].fv_rx_expected = 0;
    }

    struct can_frame secured = {0};
    struct can_frame plain2  = {0};
    secoc_result_t r;

    r = secoc_protect(&plain, &secured);
    if (r != SECOC_OK) {
        printf("[FAIL] secoc_protect returned %s\n", secoc_result_name(r));
        fails++;
    } else if (secured.can_dlc != 8) {
        printf("[FAIL] secured.can_dlc=%u (esperado 8)\n", secured.can_dlc);
        fails++;
    } else {
        printf("[ok ] secoc_protect: dlc=%u fv=%u\n",
               secured.can_dlc, (unsigned)secured.data[5]);
    }

    r = secoc_verify(&secured, &plain2);
    if (r != SECOC_OK) {
        printf("[FAIL] secoc_verify returned %s\n", secoc_result_name(r));
        fails++;
    } else if (plain2.can_dlc != 5 || memcmp(plain2.data, p, 5) != 0) {
        printf("[FAIL] payload não bateu após verify\n");
        fails++;
    } else {
        printf("[ok ] secoc_verify: payload restaurado corretamente\n");
    }

    /* Tenta um replay idêntico — deve falhar por FV fora da janela inferior. */
    r = secoc_verify(&secured, &plain2);
    if (r != SECOC_ERR_FV) {
        printf("[FAIL] replay deveria falhar por FV, obtive %s\n",
               secoc_result_name(r));
        fails++;
    } else {
        printf("[ok ] replay do mesmo secured PDU bloqueado por FV\n");
    }

    /* Tenta forjar MAC: altera 1 byte do tag. */
    struct can_frame tampered = secured;
    /* Gera novo secured para depois alterar MAC sem poluir estado. */
    g_secoc_assocs[0].fv_tx = 1;
    g_secoc_assocs[0].fv_rx_expected = 1;
    secoc_protect(&plain, &tampered);
    tampered.data[tampered.can_dlc - 1] ^= 0x01;  /* flip 1 bit no MAC */
    r = secoc_verify(&tampered, &plain2);
    if (r != SECOC_ERR_MAC) {
        printf("[FAIL] MAC adulterado deveria falhar, obtive %s\n",
               secoc_result_name(r));
        fails++;
    } else {
        printf("[ok ] MAC adulterado corretamente rejeitado\n");
    }

    if (fails == 0) {
        printf("\n== TODOS OS VETORES OK ==\n");
        return 0;
    }
    printf("\n== %d FALHA(S) ==\n", fails);
    return 1;
}
