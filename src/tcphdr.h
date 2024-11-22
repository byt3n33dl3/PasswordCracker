#ifndef TCPHDR_H
#define TCPHDR_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_TCPHDR) || defined(th_off)
/* Use the system's e.g. on AIX to avoid clashing with their field macros */
#define tcp_hdr tcphdr
#else

#include "arch.h"
#include <stdint.h>

struct tcp_hdr {
	uint16_t th_sport;
	uint16_t th_dport;
	uint32_t th_seq;
	uint32_t th_ack;
#if ARCH_LITTLE_ENDIAN
	uint8_t th_x2:4;
	uint8_t th_off:4;
#else
	uint8_t th_off:4;
	uint8_t th_x2:4;
#endif
	uint8_t th_flags;
	uint16_t th_win;
	uint16_t th_sum;
	uint16_t th_urp;
};

#endif

#ifdef __cplusplus
}
#endif

#endif
