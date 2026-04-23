/*
 * cmac.c - AES-128-CMAC conforme RFC 4493 
 *
 * AUTOSAR SecOC especifica CMAC (EAX-MAC ou CMAC, na terminologia da
 * norma) como um dos autenticadores permitidos. É AES-baseado.
 *
 */

#include "secoc.h"

#include <stdint.h>
#include <string.h>

/* 
 * "msb" dobra no GF(2^128) — polinômio irreducível x^128 + x^7 + x^2 + x + 1,
 * cujo literal em big-endian é 0x87
*/
static void gf_double(uint8_t dst[16], const uint8_t src[16])
{
    uint8_t carry = (src[0] & 0x80) ? 1 : 0;
    for (int i = 0; i < 15; i++) {
        dst[i] = (uint8_t)((src[i] << 1) | (src[i + 1] >> 7));
    }
    dst[15] = (uint8_t)(src[15] << 1);
    if (carry) dst[15] ^= 0x87;
}

/* Gera K1 e K2 */
static void derive_subkeys(const aes128_ctx_t *ctx,
                           uint8_t K1[16], uint8_t K2[16])
{
    uint8_t zero[16] = {0};
    uint8_t L[16];

    aes128_encrypt_block(ctx, zero, L);
    gf_double(K1, L);
    gf_double(K2, K1);
}


void aes_cmac_ctx(const aes128_ctx_t *ctx,
                  const uint8_t *msg, size_t msg_len,
                  uint8_t tag[16])
{
    uint8_t K1[16], K2[16];
    derive_subkeys(ctx, K1, K2);

    size_t n = (msg_len + 15) / 16;
    bool   last_complete;

    if (n == 0) {
        n = 1;
        last_complete = false;
    } else {
        last_complete = ((msg_len % 16) == 0);
    }

    /* M_last = M_n XOR K1  (se completo)  ou  padding(M_n) XOR K2. */
    uint8_t M_last[16];
    if (last_complete) {
        for (int i = 0; i < 16; i++) {
            M_last[i] = msg[(n - 1) * 16 + i] ^ K1[i];
        }
    } else {
        /* Padding: copia os bytes restantes, acrescenta 0x80, zera o resto. */
        size_t rest = msg_len - (n - 1) * 16;    /* 0..15 */
        for (size_t i = 0; i < rest; i++) {
            M_last[i] = msg[(n - 1) * 16 + i];
        }
        M_last[rest] = 0x80;
        for (size_t i = rest + 1; i < 16; i++) {
            M_last[i] = 0x00;
        }
        for (int i = 0; i < 16; i++) M_last[i] ^= K2[i];
    }

    /* Cadeia CBC-MAC: X_i = AES(X_{i-1} XOR M_i). */
    uint8_t X[16] = {0};
    uint8_t Y[16];

    for (size_t i = 0; i + 1 < n; i++) {
        for (int j = 0; j < 16; j++) {
            Y[j] = X[j] ^ msg[i * 16 + j];
        }
        aes128_encrypt_block(ctx, Y, X);
    }

    for (int j = 0; j < 16; j++) Y[j] = X[j] ^ M_last[j];
    aes128_encrypt_block(ctx, Y, tag);
}

/* Conveniência: inicializa o contexto e delega. Usado por test_cmac. */
void aes_cmac(const uint8_t key[16],
              const uint8_t *msg, size_t msg_len,
              uint8_t tag[16])
{
    aes128_ctx_t ctx;
    aes128_init(&ctx, key);
    aes_cmac_ctx(&ctx, msg, msg_len, tag);
}
