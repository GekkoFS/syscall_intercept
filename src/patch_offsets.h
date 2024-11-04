#pragma once

/*
 * sp is reduced by this offset in glibc due to patching. Before executing
 * relocated instructions, sp is increased by this constant to restore the
 * original value. All other offsets refer to this sp.
 */
#define PATCH_SP_OFF	48
/*
 * At this offset, all patches store the original ra value while in
 * intercept_irq_entry.S. This offset is also used by TYPE_GW to store its ra.
 */
#define ORIG_RA_OFF	0
/*
 * Reserved spot for the TYPE_GW original ra value offset. Used in patcher.c, but
 * not in intercept_irq_entry.S. Mostly a placeholder.
 */
#define MID_ORIG_RA_OFF	8
/*
 * At this offset, the return address is stored (address of the instruction in glibc
 * after the jump). This is used in intercept_irq_entry.S to identify the patch (aside
 * from being the address to return to)
 */
#define RET_ADDR_OFF	16
/*
 * Used only by intercept_irq_entry.S to jump back and forth between relocated
 * instructions. These instructions are generated at runtime by patcher.c.
 */
#define RELOC_ADDR_OFF	24
/* 
 * Free to use after detect_cur_patch_wrapper() in intercept_irq_entry.S;
 * the trampoline uses it to store ra before overwriting it.
 */
#define UNUSED_OFF1	32
// Free to use, typically for a fake prologue/epilogue.
#define UNUSED_OFF2	40
