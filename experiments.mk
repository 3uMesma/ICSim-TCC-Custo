# experiments.mk — Build agregador dos cenários de TCC (cen2 + cen3).
#
# Mantém o Makefile base do ICSim intacto
#
#     make all                  # icsim + controls (Makefile original)
#     make -f experiments.mk    # só os componentes dos cenários
#     make -f experiments.mk all-with-base    # tudo via delegação

.PHONY: cen2 cen3 cen-all clean-cen all-with-base

cen2:
	$(MAKE) -C scenario2-firewall

cen3:
	$(MAKE) -C scenario3-secoc

# Constrói só os componentes dos cenários (sem mexer no Makefile base).
cen-all: cen2 cen3

# Delega ao Makefile base + cenários — atalho conveniente.
all-with-base:
	$(MAKE) all                              # icsim, controls
	$(MAKE) -f experiments.mk cen-all        # gateway, secoc_*

clean-cen:
	$(MAKE) -C scenario2-firewall clean
	$(MAKE) -C scenario3-secoc clean
