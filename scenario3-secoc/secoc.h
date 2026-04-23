#ifndef SECOC_H
#define SECOC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <linux/can.h>

#define SECOC_KEY_LEN            16u    /* AES-128 */
#define SECOC_MAC_LEN             2u    /* 16 bits truncados */
#define SECOC_FV_LEN              1u    /* 8 bits truncados */
#define SECOC_OVERHEAD           (SECOC_FV_LEN + SECOC_MAC_LEN) /* 3 B */
#define SECOC_MAX_PLAIN_LEN      (CAN_MAX_DLEN - SECOC_OVERHEAD) /* 5 B */

#define SECOC_FRESHNESS_WINDOW  128u    /* tolera jitter/perdas no receptor */
#define SECOC_MAX_ASSOCS          8u    /* capacidade estática da tabela */

/* 
 * Chave pré-compartilhada do experimento. Em produção viria de um Key
 * Management System (por exemplo, SHE/SHE+ da Bosch). Aqui é hardcoded
 * porque a medição alvo é o custo de *autenticação*, não o de *provisão*
 * de chaves
*/
extern const uint8_t SECOC_DEMO_KEY[SECOC_KEY_LEN];

/* Estado por DataID (cada entrada cobre um CAN ID protegido) */
typedef struct {
    canid_t  data_id;          /* DataID, corresponde ao CAN ID do payload */
    uint8_t  expected_plain_len; /* comprimento do payload *antes* do SecOC */
    const char *name;          /* rótulo humano para logs */

    /* Estado do transmissor */
    uint32_t fv_tx;            /* próximo contador a ser enviado */

    /* Estado do receptor */
    uint32_t fv_rx_expected;   /* próximo contador esperado */

    /* Contadores de telemetria */
    uint64_t sent;
    uint64_t accepted;
    uint64_t rej_mac;
    uint64_t rej_fv;
    uint64_t rej_len;
} secoc_assoc_t;

/* Verdicts retornados pelo receptor  */
typedef enum {
    SECOC_OK          = 0,
    SECOC_ERR_ID      = 1,    /* DataID não associado (sem rule) */
    SECOC_ERR_LEN     = 2,    /* DLC incompatível com o perfil esperado */
    SECOC_ERR_MAC     = 3,    /* tag MAC inválido (ataque ou corrupção) */
    SECOC_ERR_FV      = 4,    /* FV fora da janela (replay ou dessync) */
    SECOC_ERR_FD      = 5,    /* CAN FD ignorado pelo perfil */
} secoc_result_t;

/* Tabela de associações — definida em secoc_assocs.c */ 
extern secoc_assoc_t  g_secoc_assocs[];
extern const size_t   g_secoc_assocs_size;

/* Contadores globais por motivo (1 slot por secoc_result_t). */
extern uint64_t g_secoc_counts[6];

/* AES-128-CMAC puro (implementado em aes.c + cmac.c) */

/* Estrutura opaca de round keys (16 bytes * 11 rounds AES-128). */
typedef struct {
    uint8_t round_key[176];
} aes128_ctx_t;

void aes128_init(aes128_ctx_t *ctx, const uint8_t key[16]);
void aes128_encrypt_block(const aes128_ctx_t *ctx,
                          const uint8_t in[16], uint8_t out[16]);

/* Calcula o tag CMAC de 128 bits. Suporta mensagem vazia. */
void aes_cmac(const uint8_t key[16],
              const uint8_t *msg, size_t msg_len,
              uint8_t tag[16]);

/* Variante com contexto pré-inicializado — usada no caminho quente do
 * gateway para não reexpandir a key-schedule a cada frame. */
void aes_cmac_ctx(const aes128_ctx_t *ctx,
                  const uint8_t *msg, size_t msg_len,
                  uint8_t tag[16]);

/* API SecOC (camada principal) */

/* Inicializa o contexto criptográfico a partir da chave. Deve ser chamado
 * uma única vez por processo antes do loop de I/O. */
void secoc_init(const uint8_t key[SECOC_KEY_LEN]);

/* Procura a associação para um DataID (linear, N<=8). */
secoc_assoc_t *secoc_find(canid_t data_id);

/* Nome humano de um verdict (para logs e estatísticas). */
const char *secoc_result_name(secoc_result_t r);

/* --- Transmissor -------------------------------------------------------
 *
 * Recebe um frame CAN "plain" (o que o controls.c envia hoje) e produz
 * o frame "secured" correspondente, com FV e MAC anexados. Incrementa
 * a->fv_tx.
 *
 * Retorno: SECOC_OK ou SECOC_ERR_LEN
 */
secoc_result_t secoc_protect(const struct can_frame *plain,
                             struct can_frame *secured);

/* --- Receptor ----------------------------------------------------------
 *
 * Recebe um frame CAN "secured" da rede e, se todas as verificações
 * passarem, preenche `plain` com o payload original. Atualiza a->fv_rx_
 * expected e contadores correspondentes.
 *
 * Em caso de falha retorna o verdict apropriado; `plain` permanece em
 * estado indefinido.
 */
secoc_result_t secoc_verify(const struct can_frame *secured,
                            struct can_frame *plain);

#endif 
