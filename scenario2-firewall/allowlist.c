/*
 * Os três IDs abaixo foram extraídos de ICSim-TCC-Custo/controls.c:
 *   - DEFAULT_SPEED_ID   = 0x244
 *   - DEFAULT_SIGNAL_ID  = 0x188
 *   - DEFAULT_DOOR_ID    = 0x19B
 */

#include "allowlist.h"
#include "can_ids.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>  /* qsort, bsearch */
#include <assert.h>

#define ICSIM_RULES                                                          \
    {.can_id = CAN_ID_SPEED,  .expected_dlc = 5, .min_period_us = 8000,   .name = "SPEED"},       \
    {.can_id = CAN_ID_SIGNAL, .expected_dlc = 3, .min_period_us = 400000, .name = "TURN_SIGNAL"}, \
    {.can_id = CAN_ID_DOORS,  .expected_dlc = 3, .min_period_us = 50000,  .name = "DOORS"}

policy_rule_t g_allowlist[ALLOWLIST_MAX_ENTRIES] = {ICSIM_RULES};
static const policy_rule_t g_icsim_rules[] = {ICSIM_RULES};

size_t g_allowlist_size = 3;

uint64_t g_drops_by_reason[5] = {0};

bool g_enforce_dlc  = true;
bool g_enforce_rate = true;

/* ---- Seleção do backend em tempo de compilação -------------------------- */
#define LOOKUP_LINEAR 0
#define LOOKUP_BINARY 1
#define LOOKUP_DIRECT 2
#ifndef LOOKUP
#define LOOKUP LOOKUP_LINEAR  /* default: comportamento atual */
#endif

/* ---- Backends ----------------------------------------------------------- */

policy_rule_t *policy_find_linear(canid_t can_id)
{
    for (size_t i = 0; i < g_allowlist_size; i++)
        if (g_allowlist[i].can_id == can_id)
            return &g_allowlist[i];
    return NULL;
}

static int cmp_rule_id(const void *a, const void *b)
{
    canid_t x = ((const policy_rule_t *)a)->can_id;
    canid_t y = ((const policy_rule_t *)b)->can_id;
    return (x > y) - (x < y);
}

void policy_sort_allowlist(void)
{
    qsort(g_allowlist, g_allowlist_size, sizeof(policy_rule_t), cmp_rule_id);
}

policy_rule_t *policy_find_binary(canid_t can_id)
{
    policy_rule_t key = {.can_id = can_id};
    return bsearch(&key, g_allowlist, g_allowlist_size,
                   sizeof(policy_rule_t), cmp_rule_id);
}

/* Índice direto: 2048 ponteiros (16 KiB), um slot por ID de 11 bits. */
static policy_rule_t *g_id_index[1u << 11];

void policy_build_index(void)
{
    for (size_t i = 0; i < (1u << 11); i++)
        g_id_index[i] = NULL;
    for (size_t i = 0; i < g_allowlist_size; i++)
        g_id_index[g_allowlist[i].can_id & CAN_SFF_MASK] = &g_allowlist[i];
}

policy_rule_t *policy_find_direct(canid_t can_id)
{
    if (can_id > CAN_SFF_MASK) /* fora de 11 bits: não casa, como no linear */
        return NULL;
    return g_id_index[can_id];
}

/* ---- Despacho e init ---------------------------------------------------- */

policy_rule_t *policy_find_rule(canid_t can_id)
{
#if   LOOKUP == LOOKUP_BINARY
    return policy_find_binary(can_id);
#elif LOOKUP == LOOKUP_DIRECT
    return policy_find_direct(can_id);
#else
    return policy_find_linear(can_id);
#endif
}

void policy_lookup_init(void)
{
#if   LOOKUP == LOOKUP_BINARY
    policy_sort_allowlist();
#elif LOOKUP == LOOKUP_DIRECT
    policy_build_index();
#endif
    /* LINEAR: nada a preparar. */
}

/* Popula g_allowlist[0..n) a partir de um array de IDs (g_micro_ids/g_macro_ids
   do allowlist_sweep.h). Os IDs do ICSim recebem a metadata real; o resto é
   padding com metadata neutra. Chamar policy_lookup_init() depois. */
void policy_load_ids(const canid_t *ids, size_t n)
{
    assert(n <= ALLOWLIST_MAX_ENTRIES);
    const size_t n_known = sizeof(g_icsim_rules) / sizeof(g_icsim_rules[0]);
    for (size_t i = 0; i < n; i++) {
        policy_rule_t r = {.can_id = ids[i], .name = "PAD"};
        for (size_t k = 0; k < n_known; k++)
            if (ids[i] == g_icsim_rules[k].can_id) { r = g_icsim_rules[k]; break; }
        g_allowlist[i] = r;  /* estado (last_ts/pass/drop) zerado pelo initializer */
    }
    g_allowlist_size = n;
}

/* ------------------------------------------------------------------------ */

const char *policy_verdict_name(policy_verdict_t v)
{
    switch (v) {
    case POLICY_PASS:        return "PASS";
    case POLICY_REJECT_ID:   return "REJECT_ID";
    case POLICY_REJECT_DLC:  return "REJECT_DLC";
    case POLICY_REJECT_RATE: return "REJECT_RATE";
    case POLICY_REJECT_FD:   return "REJECT_FD";
    default:                 return "UNKNOWN";
    }
}

policy_verdict_t policy_evaluate(const struct can_frame *cf, uint64_t now_us)
{
    /* Camada 1 — Allowlist de IDs. */
    policy_rule_t *rule = policy_find_rule(cf->can_id);
    if (rule == NULL) {
        g_drops_by_reason[POLICY_REJECT_ID]++;
        return POLICY_REJECT_ID;
    }

    /* Camada 2 — DLC esperado. */
    if (g_enforce_dlc && cf->can_dlc != rule->expected_dlc) {
        rule->drop_count++;
        g_drops_by_reason[POLICY_REJECT_DLC]++;
        return POLICY_REJECT_DLC;
    }

    /* Camada 3 — Rate limit por ID (janela deslizante de 1 quadro). */
    if (g_enforce_rate && rule->last_ts_us != 0) {
        uint64_t delta = now_us - rule->last_ts_us;
        if (delta < rule->min_period_us) {
            rule->drop_count++;
            g_drops_by_reason[POLICY_REJECT_RATE]++;
            return POLICY_REJECT_RATE;
        }
    }
    rule->last_ts_us = now_us;
    rule->pass_count++;
    g_drops_by_reason[POLICY_PASS]++;
    return POLICY_PASS;
}