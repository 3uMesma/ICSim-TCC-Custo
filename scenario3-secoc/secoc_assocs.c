/*
 * secoc_assocs.c - Tabela de associações SecOC (uma entrada por DataID).
 *
 * A tabela abaixo é o análogo direto do g_allowlist[] do Cenário 2, mas
 * define associações criptográficas em vez de regras de filtragem. Os
 * três DataIDs são os mesmos extraídos de ICSim-TCC-Custo/controls.c.
 * Os contadores(fv_tx, fv_rx_expected e telemetria) começam zerados e 
 * evoluem durante a execução — o processo sender e o processo gateway 
 * mantêm cópias independentes desta tabela.
 */

#include "secoc.h"

#include <stddef.h>

secoc_assoc_t g_secoc_assocs[SECOC_MAX_ASSOCS] = {
    {
        .data_id            = 0x244,
        .expected_plain_len = 5,      /* SPEED: 5 bytes úteis no ICSim */
        .name               = "SPEED",
        .fv_tx              = 0,
        .fv_rx_expected     = 0,
        .sent               = 0,
        .accepted           = 0,
        .rej_mac            = 0,
        .rej_fv             = 0,
        .rej_len            = 0,
    },
    {
        .data_id            = 0x188,
        .expected_plain_len = 3,      /* TURN_SIGNAL: 3 bytes úteis */
        .name               = "TURN_SIGNAL",
        .fv_tx              = 0,
        .fv_rx_expected     = 0,
        .sent               = 0,
        .accepted           = 0,
        .rej_mac            = 0,
        .rej_fv             = 0,
        .rej_len            = 0,
    },
    {
        .data_id            = 0x19B,
        .expected_plain_len = 3,      /* DOORS: 3 bytes úteis */
        .name               = "DOORS",
        .fv_tx              = 0,
        .fv_rx_expected     = 0,
        .sent               = 0,
        .accepted           = 0,
        .rej_mac            = 0,
        .rej_fv             = 0,
        .rej_len            = 0,
    },
};

const size_t g_secoc_assocs_size = 3;

uint64_t g_secoc_counts[6] = {0};

/* Chave de demonstração — 128 bits pseudoaleatórios gerados off-line e
 * fixados para reprodutibilidade dos experimentos. Em um sistema real o
 * equivalente seria provisionado por um KMS (HSM, SHE+ etc.). */
const uint8_t SECOC_DEMO_KEY[SECOC_KEY_LEN] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};
/* Observação : esta é a chave do "Key = ..." dos vetores de teste da RFC 
 * 4493 e da NIST SP 800-38B
 */
