/*
 * secoc.c - Camada SecOC (CAN FD): protect/verify sobre frames CAN FD.
 *
 * Formato da "authentication input" (entrada do CMAC):
 *
 *     DataID (4B BE)  || FV_full (4B BE)  || payload (plain, até 52B)
 *
 * Formato do frame "secured" no fio:
 *
 *     [payload (até 52B)] [FV_full (4B BE)] [MAC (8B)]   -> len = plain + 12
 */

#include "secoc.h"

#include <stdint.h>
#include <string.h>

/* Contexto AES do processo. secoc_init() deve ser chamado uma vez antes
 * de qualquer protect/verify. Não é thread-safe — cada processo (sender,
 * gateway) tem o seu próprio. Para o TCC, single-thread é suficiente e
 * evita custo de sincronização no hot path. */
static aes128_ctx_t g_ctx;
static bool         g_ctx_ready = false;

void secoc_init(const uint8_t key[SECOC_KEY_LEN])
{
    aes128_init(&g_ctx, key);
    g_ctx_ready = true;
}

/* Funções auxiliares */
secoc_assoc_t *secoc_find(canid_t data_id)
{
    /* Mesmo raciocínio do allowlist.c: N<=8, lookup linear */
    for (size_t i = 0; i < g_secoc_assocs_size; i++) {
        if (g_secoc_assocs[i].data_id == data_id) {
            return &g_secoc_assocs[i];
        }
    }
    return NULL;
}

const char *secoc_result_name(secoc_result_t r)
{
    switch (r) {
    case SECOC_OK:      return "OK";
    case SECOC_ERR_ID:  return "ERR_ID";
    case SECOC_ERR_LEN: return "ERR_LEN";
    case SECOC_ERR_MAC: return "ERR_MAC";
    case SECOC_ERR_FV:  return "ERR_FV";
    case SECOC_ERR_FD:  return "ERR_FD";
    default:            return "UNKNOWN";
    }
}

/* Serializa um uint32 big-endian num buffer (usado na entrada do CMAC). */
static inline void put_be32(uint8_t *out, uint32_t v)
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)(v);
}

/* Lê um uint32 big-endian de um buffer (FV completo vindo do fio). */
static inline uint32_t get_be32(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
         | ((uint32_t)in[2] <<  8) |  (uint32_t)in[3];
}

/* 
 * Monta a "authentication input" e retorna o seu comprimento.
 * O buffer auth_in precisa ter pelo menos 8 + payload_len bytes.
*/
static size_t build_auth_input(uint8_t *auth_in,
                               uint32_t data_id,
                               uint32_t fv_full,
                               const uint8_t *payload,
                               uint8_t payload_len)
{
    put_be32(auth_in + 0, data_id);
    put_be32(auth_in + 4, fv_full);
    memcpy(auth_in + 8, payload, payload_len);
    return 8 + payload_len;
}

/* Transmissor: pega um frame "plain" e monta o frame "secured".*/
secoc_result_t secoc_protect(const struct canfd_frame *plain,
                             struct canfd_frame *secured)
{
    if (plain->can_id & CAN_EFF_FLAG) {
        /* Perfil = ID 11-bit (SFF); IDs estendidos (29-bit) ficam fora. */
        g_secoc_counts[SECOC_ERR_FD]++;
        return SECOC_ERR_FD;
    }

    secoc_assoc_t *a = secoc_find(plain->can_id & CAN_SFF_MASK);
    if (a == NULL) {
        g_secoc_counts[SECOC_ERR_ID]++;
        return SECOC_ERR_ID;
    }

    if (plain->len != a->expected_plain_len) {
        a->rej_len++;
        g_secoc_counts[SECOC_ERR_LEN]++;
        return SECOC_ERR_LEN;
    }

    /* FV a usar = fv_tx atual; incrementa após sucesso. */
    uint32_t fv_full = a->fv_tx;

    /* Monta entrada do CMAC em pilha. 8 bytes de cabeçalho + até 52 de
     * payload = 60 bytes máximo (4 blocos AES). */
    uint8_t auth_in[8 + SECOC_MAX_PLAIN_LEN];
    size_t  auth_len = build_auth_input(auth_in,
                                        plain->can_id & CAN_SFF_MASK,
                                        fv_full,
                                        plain->data,
                                        plain->len);

    uint8_t tag[16];
    aes_cmac_ctx(&g_ctx, auth_in, auth_len, tag);

    /* Monta o frame secured: [payload][FV_full 4B BE][MAC 8B] */
    secured->can_id = plain->can_id;
    secured->flags  = plain->flags;
    secured->len    = (uint8_t)(plain->len + SECOC_OVERHEAD);
    memcpy(secured->data, plain->data, plain->len);
    put_be32(&secured->data[plain->len], fv_full);
    memcpy(&secured->data[plain->len + SECOC_FV_LEN], tag, SECOC_MAC_LEN);

    /* Atualiza estado do transmissor só em caso de sucesso. */
    a->fv_tx++;
    a->sent++;
    g_secoc_counts[SECOC_OK]++;
    return SECOC_OK;
}

/* Receptor: valida um frame secured e, se autenticado, entrega o plain. */
secoc_result_t secoc_verify(const struct canfd_frame *secured,
                            struct canfd_frame *plain)
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

    uint8_t expect_len = (uint8_t)(a->expected_plain_len + SECOC_OVERHEAD);
    if (secured->len != expect_len) {
        a->rej_len++;
        g_secoc_counts[SECOC_ERR_LEN]++;
        return SECOC_ERR_LEN;
    }

    /* FV completo (4B) lido direto do fio — sem reconstrução de rollover.
     * Janela: aceita fv_recv em [expected, expected + WINDOW - 1]. A
     * subtração unsigned trata replay (fv < expected -> delta enorme). */
    uint32_t fv_recv = get_be32(&secured->data[a->expected_plain_len]);
    uint32_t delta   = fv_recv - a->fv_rx_expected;
    if (delta >= SECOC_FRESHNESS_WINDOW) {
        a->rej_fv++;
        g_secoc_counts[SECOC_ERR_FV]++;
        return SECOC_ERR_FV;
    }

    const uint8_t *mac_rx = &secured->data[a->expected_plain_len + SECOC_FV_LEN];

    /* Recalcula o MAC com o FV recebido. */
    uint8_t auth_in[8 + SECOC_MAX_PLAIN_LEN];
    size_t  auth_len = build_auth_input(auth_in,
                                        secured->can_id & CAN_SFF_MASK,
                                        fv_recv,
                                        secured->data,
                                        a->expected_plain_len);

    uint8_t tag[16];
    aes_cmac_ctx(&g_ctx, auth_in, auth_len, tag);

    /* Comparação em tempo constante dos SECOC_MAC_LEN bytes transmitidos. */
    uint8_t diff = 0;
    for (size_t i = 0; i < SECOC_MAC_LEN; i++) {
        diff |= (uint8_t)(mac_rx[i] ^ tag[i]);
    }
    if (diff != 0) {
        a->rej_mac++;
        g_secoc_counts[SECOC_ERR_MAC]++;
        return SECOC_ERR_MAC;
    }

    /* Autenticação OK. Atualiza estado do receptor. */
    a->fv_rx_expected = fv_recv + 1;
    a->accepted++;
    g_secoc_counts[SECOC_OK]++;

    plain->can_id = secured->can_id;
    plain->flags  = secured->flags;
    plain->len    = a->expected_plain_len;
    memcpy(plain->data, secured->data, a->expected_plain_len);
    /* Zera o resto para evitar vazar bytes da parte autenticada. */
    memset(plain->data + a->expected_plain_len, 0,
           CANFD_MAX_DLEN - a->expected_plain_len);

    return SECOC_OK;
}
