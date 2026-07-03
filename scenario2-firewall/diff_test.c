/* Teste diferencial da Fase 1.
   Para cada N do sweep, os três backends (linear/binária/índice-direto) devem
   devolver o MESMO ponteiro para todo ID — hit e miss */
#include "allowlist.h"
#include "allowlist_sweep.h"
#include <stdio.h>

int main(void)
{
    size_t total_diver = 0;
    printf("%-6s %8s %8s %8s\n", "N", "hits", "misses", "diverg");
    for (int s = 0; s < SWEEP_COUNT; s++) {
        size_t N = (size_t)g_sweep_sizes[s];
        policy_load_ids(g_micro_ids, N);
        policy_sort_allowlist();  /* prep binária */
        policy_build_index();     /* prep índice direto (após ordenar) */

        size_t hits = 0, misses = 0, diver = 0;
        for (canid_t id = 0; id <= 0x8FF; id++) { /* 11 bits + faixa EFF/RTR */
            policy_rule_t *a = policy_find_linear(id);
            policy_rule_t *b = policy_find_binary(id);
            policy_rule_t *c = policy_find_direct(id);
            if (a != b || a != c) {
                if (diver < 3)
                    printf("  DIVERGE N=%zu id=0x%X lin=%p bin=%p dir=%p\n",
                           N, id, (void *)a, (void *)b, (void *)c);
                diver++;
            }
            if (a) hits++; else misses++;
        }
        printf("%-6zu %8zu %8zu %8zu\n", N, hits, misses, diver);
        total_diver += diver;
    }
    printf(total_diver ? "\nFALHA: %zu divergencia(s)\n"
                       : "\nOK — backends equivalentes em todo o sweep\n",
           total_diver);
    return total_diver ? 1 : 0;
}
