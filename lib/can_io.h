/*
 * lib/can_io.h — wrappers de I/O CAN comuns aos gateways/sender em C.
*/
#ifndef CAN_IO_H
#define CAN_IO_H

#include <stdint.h>
#include <linux/can.h>

/*
 * Abre socket CAN e bind em `iface`. Retorna fd>=0 ou -1 em erro
 * (errno preservado). Tratamento de erro fica no caller.
 */
int can_io_open(const char *iface);

/*
 * Retorna CLOCK_MONOTONIC em microssegundos.
 */
uint64_t can_io_now_monotonic_us(void);

#endif /* CAN_IO_H */
