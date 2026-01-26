#pragma once

/*
 * sp is reduced by this offset in glibc due to patching. Before executing
 * relocated instructions, sp is increased by this constant to restore the
 * original value. All other offsets refer to this sp.
 */
#define PATCH_SP_OFF	128
/*
 * Low offsets to maximize headroom for application stack frames.
 */
#define ORIG_RA_OFF	0
#define MID_ORIG_RA_OFF	8
#define RET_ADDR_OFF	16
#define RELOC_ADDR_OFF	24
#define UNUSED_OFF1	32
#define UNUSED_OFF2	40
#define UNUSED_OFF3	48
#define UNUSED_OFF4	56
#define UNUSED_OFF3	48
#define UNUSED_OFF4	56
// t1 and t2 preservation slots
#define T1_SAVE_OFF     64
#define T2_SAVE_OFF     72
