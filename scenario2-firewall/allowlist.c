/*
 * Os três IDs abaixo foram extraídos de ICSim-TCC-Custo/controls.c:
 *   - DEFAULT_SPEED_ID   = 0x244   (send_speed,   cf.len = speed_pos + 2 = 5)
 *   - DEFAULT_SIGNAL_ID  = 0x188   (send_turn_signal, cf.len = 3)
 *   - DEFAULT_DOOR_ID    = 0x19B   (send_lock/send_unlock, cf.len = 3)
 *
 * Outros ids medidos na prática:
 *   - 0x244: enviado em checkAccel(), guarda de 10 ms -> P_min = 8000 µs
 *   - 0x188: enviado em checkTurn(),   guarda de 500 ms -> P_min = 400000 µs
 *   - 0x19B: send_lock/send_unlock é *event-driven* (apertos de tecla).
 *            Não há período nominal; adota-se P_min = 50000 µs como
 *            proteção contra *burst* de spoofing 
 *
 * Observação: em um firewall produtivo o P_min costuma ser
 * derivado da matriz DBC do fabricante. Como o ICSim não fornece DBC,
 * P_min foi obtido empiricamente a partir da leitura do código
 */


#include "allowlist.h"

#include <stddef.h>
#include <stdio.h>

policy_rule_t g_allowlist[ALLOWLIST_MAX_ENTRIES] = {
    {
        .can_id         = 0x244,
        .expected_dlc   = 5,
        .min_period_us  = 8000,       /* ~125 Hz teto; ICSim envia a ~100 Hz */
        .name           = "SPEED",
        .last_ts_us     = 0,
        .pass_count     = 0,
        .drop_count     = 0,
    },
    {
        .can_id         = 0x188,
        .expected_dlc   = 3,
        .min_period_us  = 400000,     /* ICSim envia a cada ~500 ms */
        .name           = "TURN_SIGNAL",
        .last_ts_us     = 0,
        .pass_count     = 0,
        .drop_count     = 0,
    },
    {
        .can_id         = 0x19B,
        .expected_dlc   = 3,
        .min_period_us  = 50000,      /* evento esporádico; tolera 20 Hz */
        .name           = "DOORS",
        .last_ts_us     = 0,
        .pass_count     = 0,
        .drop_count     = 0,
    },
    /* obs.: can_id = 0 indica fim da tabela válida. O DoS usa ID 0x000 
     * exatamente, então o gateway deve rejeitar 0x000 por
     * ausência na allowlist *antes* de chegar aqui (ver lógica em
     * policy_find_rule). 
    */
};

const size_t g_allowlist_size = 3;

uint64_t g_drops_by_reason[5] = {0};

bool g_enforce_dlc  = true;
bool g_enforce_rate = true;

/* ------------------------------------------------------------------------ */

policy_rule_t *policy_find_rule(canid_t can_id)
{
    /* Lookup linear e fica inteiro em cache L1.*/
    for (size_t i = 0; i < g_allowlist_size; i++) {
        if (g_allowlist[i].can_id == can_id) {
            return &g_allowlist[i];
        }
    }
    return NULL;
}

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
    /* Camada 1 — Allowlist de IDs.
     * Rejeita DoS (ID 0x000) e parte substancial do fuzzing. 
    */
    policy_rule_t *rule = policy_find_rule(cf->can_id);
    if (rule == NULL) {
        g_drops_by_reason[POLICY_REJECT_ID]++;
        return POLICY_REJECT_ID;
    }

    /* Camada 2 — DLC esperado.
     * Rejeita fuzzing com DLC extraordinário e a versão atual do spoofing
     * (que sempre emite 8 bytes enquanto o ICSim real envia 3 ou 5).
    */
    if (g_enforce_dlc && cf->can_dlc != rule->expected_dlc) {
        rule->drop_count++;
        g_drops_by_reason[POLICY_REJECT_DLC]++;
        return POLICY_REJECT_DLC;
    }

    /* Camada 3 — Rate limit por ID (janela deslizante de 1 quadro).
     * Rejeita replay 10x acelerado e spoofing em alta frequência. 
    */
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
