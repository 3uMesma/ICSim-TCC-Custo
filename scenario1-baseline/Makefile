include ../make.inc

BIN := passthrough
BIN_FD := passthrough-fd
SRC := passthrough.c
OBJ := passthrough.o

.PHONY: all clean clean-logs format

all: $(BIN) $(BIN_FD)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

passthrough.o: passthrough.c
	$(CC) $(CFLAGS) -c passthrough.c -o passthrough.o

# Variante CAN FD (D0): mesmo fonte, -DFD_MODE. Compilada direto do .c
# para a flag alcançar todo o código.
$(BIN_FD): passthrough.c
	$(CC) $(CFLAGS) -DFD_MODE -o $@ passthrough.c $(LDFLAGS)

clean:
	rm -f $(BIN) $(BIN_FD) $(OBJ)

clean-logs:
	sudo rm -rf results/ results-sw/

format:
	clang-format -i *.c
