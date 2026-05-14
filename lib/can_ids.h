#ifndef CAN_IDS_H
#define CAN_IDS_H

/* IDs CAN do ICSim usados pelos cenarios de defesa do TCC.
 *
 * Os valores espelham DEFAULT_SPEED_ID/SIGNAL_ID/DOOR_ID em icsim.c
 * (upstream OpenGarages/ICSim). O icsim.c nao inclui esta header
 * para preservar o codigo original. */

#define CAN_ID_SPEED   0x244
#define CAN_ID_SIGNAL  0x188
#define CAN_ID_DOORS   0x19B

#endif /* CAN_IDS_H */
