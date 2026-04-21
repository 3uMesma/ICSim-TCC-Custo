#ifndef ALLOWLIST_H
#define ALLOWLIST_H

#include <linux/can.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ALLOWLIST_MAX_ENTRIES 32

/* Motivos de bloqueio */
typedef enum {
    POLICY_PASS = 0,        /* liberado */
    POLICY_REJECT_ID = 1,   /* ID fora da allowlist */
    POLICY_REJECT_DLC = 2,  /* DLC diferente do esperado para este ID */
    POLICY_REJECT_RATE = 3, /* taxa acima do limite do rate-limiter */
    POLICY_REJECT_FD = 4,   /* CAN FD desabilitado pela política */
} policy_verdict_t;

/* Entrada da política para um ID permitido. */
typedef struct {
    canid_t can_id;         /* ID permitido (11 ou 29 bits) */
    uint8_t expected_dlc;   /* DLC exato esperado */
    uint32_t min_period_us; /* período mínimo entre dois frames */
    const char *name;       /* rótulo (para logs) */
    /* Estado interno do rate-limiter — NÃO mexer nisso em configuração. */
    uint64_t last_ts_us; /* último timestamp aceito (µs monotônicos) */
    uint64_t pass_count; /* quadros aceitos */
    uint64_t drop_count; /* quadros descartados (por qualquer motivo) */
} policy_rule_t;

extern policy_rule_t g_allowlist[];
extern const size_t g_allowlist_size;

extern uint64_t g_drops_by_reason[5];

policy_verdict_t policy_evaluate(const struct can_frame *cf, uint64_t now_us);

/* Helpers utilitários */
policy_rule_t *policy_find_rule(canid_t can_id);
const char *policy_verdict_name(policy_verdict_t v);

/* Hooks de configuração de runtime (flags de linha de comando). */
extern bool g_enforce_dlc;
extern bool g_enforce_rate;

#endif
