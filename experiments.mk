# Mantém o Makefile base do ICSim intacto.
#
#     make all                              # icsim + controls (Makefile original)
#     make -f experiments.mk cen-all        # passthrough + gateway + secoc_*
#     make -f experiments.mk all-with-base  # tudo via delegação

.PHONY: cen1 cen2 cen3 cen-all clean-cen all-with-base

cen1:
	$(MAKE) -C scenario1-baseline

cen2:
	$(MAKE) -C scenario2-firewall

cen3:
	$(MAKE) -C scenario3-secoc

# Constrói os três binários dos cenários (sem mexer no Makefile base).
cen-all: cen1 cen2 cen3

# Delega ao Makefile base + cenários — atalho conveniente.
all-with-base:
	$(MAKE) all                              # icsim, controls
	$(MAKE) -f experiments.mk cen-all        # passthrough, gateway, secoc_*

clean-cen:
	$(MAKE) -C scenario1-baseline clean
	$(MAKE) -C scenario2-firewall clean
	$(MAKE) -C scenario3-secoc clean
