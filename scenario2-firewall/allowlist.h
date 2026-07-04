#ifndef ALLOWLIST_H
#define ALLOWLIST_H

#include <linux/can.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ALLOWLIST_MAX_ENTRIES 256

/* Tipo de frame conforme o barramento: CAN FD sob -DFD_MODE,
 * CAN 2.0 clássico caso contrário. O campo can_id existe nas duas structs;
 * o comprimento muda de nome (len vs can_dlc) */
#ifdef FD_MODE
typedef struct canfd_frame policy_frame_t;
#  define POLICY_FRAME_LEN(cf) ((cf)->len)
#else
typedef struct can_frame policy_frame_t;
#  define POLICY_FRAME_LEN(cf) ((cf)->can_dlc)
#endif

/* Motivos de bloqueio */
typedef enum {
    POLICY_PASS = 0,        /* liberado */
    POLICY_REJECT_ID = 1,   /* ID fora da allowlist */
    POLICY_REJECT_DLC = 2,  /* DLC diferente do esperado para este ID */
    POLICY_REJECT_RATE = 3, /* taxa acima do limite do rate-limiter */
    POLICY_REJECT_FD = 4,   /* frame com tamanho fora do perfil do barramento */
} policy_verdict_t;

/* Entrada da política para um ID permitido. */
typedef struct {
    canid_t can_id;         /* ID permitido (11 ou 29 bits) */
    uint8_t expected_dlc;   /* DLC exato esperado */
    uint32_t min_period_us; /* período mínimo entre dois frames */
    const char *name;       /* rótulo (para logs) */
    uint64_t last_ts_us; /* último timestamp aceito (µs monotônicos) */
    uint64_t pass_count; /* quadros aceitos */
    uint64_t drop_count; /* quadros descartados (por qualquer motivo) */
} policy_rule_t;

extern policy_rule_t g_allowlist[];
extern size_t g_allowlist_size;  /* populável em tamanho N para o sweep */

extern uint64_t g_drops_by_reason[5];

policy_verdict_t policy_evaluate(const policy_frame_t *cf, uint64_t now_us);

/* Popula g_allowlist[0..n) a partir de um array de IDs (g_micro_ids/g_macro_ids
   do allowlist_sweep.h). Chamar policy_lookup_init() logo depois. */
void policy_load_ids(const canid_t *ids, size_t n);

/* Prepara o backend de busca (ordena/indexa). Chamar uma vez após popular a
   allowlist e antes do primeiro policy_evaluate. No-op no linear. */
void policy_lookup_init(void);

/* Helpers utilitários */
policy_rule_t *policy_find_rule(canid_t can_id);
const char *policy_verdict_name(policy_verdict_t v);

/* Backends expostos para o teste diferencial */
policy_rule_t *policy_find_linear(canid_t can_id);
policy_rule_t *policy_find_binary(canid_t can_id);
policy_rule_t *policy_find_direct(canid_t can_id);
void policy_sort_allowlist(void); /* ordena por can_id (prep da binária) */
void policy_build_index(void);    /* preenche o índice direto */

/* Hooks de configuração de runtime (flags de linha de comando). */
extern bool g_enforce_dlc;
extern bool g_enforce_rate;

#endif
