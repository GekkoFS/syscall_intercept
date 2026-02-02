/*
 * Copyright 2016-2024, Intel Corporation
 * Contributor: Petar Andrić
 * Contributor: Ramon Nou
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 *     * Neither the name of the copyright holder nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * patcher.c -- patching a library
 *
 * Jumping from the subject library to libsyscall_intercept.so and back:
 *
 *     ,---------------------------------.
 *     |                         | glibc |  patched by activate_patches()
 *     | [TYPE_SML]              `-------|
 *     |   jal   a7, GW_entry -----------|--.  (linkage via a7)
 *  ,->|                                 |  |
 *  |  | [TYPE_MID]                      |  |
 *  |  |   jal   ra, GW_entry -----------|--|-. (linkage via ra)
 *  |  |                                 |  | |
 *  |  | [GW_entry / TYPE_GW]            |<--'|
 *  |  |   auipc ra, interceptor_addr ---|--. |
 *  |  |   jalr  ra, offset(ra)          |  | |
 *  |  |                                 |<---'
 *  |  | [TYPE_INPLACE]                  |
 *  |  |   auipc a7, interceptor_addr ---|--.  (linkage via a7)
 *  |  |   jalr  a7, offset(a7)          |  |
 *  |  |                                 |  |
 *  |  | [TYPE_MINI_TRAMP]               |  |
 *  |  |   jal   ra, text_hole ----------|--|-.
 *  |  `---|-----------------------------'  | |
 *  |      |                                | |
 *  |  ,---|-----------------------------.  | |
 *  |  |   |                | text hole  |<-' |
 *  |  |   |                `------------|    |
 *  |  |   c.addi  ra, 2                 |    |
 *  |  |   auipc   t0, interceptor_addr -|--. |
 *  |  |   jalr    t0, offset(t0)        |  | |
 *  |  `---|-----------------------------'  | |
 *  |      |                                | |
 *  |  ,---|-----------------------------.  | |
 *  |  |   |                | trampoline |<-'-' (used if dist > 2 GB)
 *  |  |   |                `------------|
 *  |  |   sd      ra, UNUSED_OFF1(sp)   |
 *  |  |   la      ra, asm_entry_point   |
 *  |  |   jalr    zero, 0(ra)           |<-.
 *  |  `---|-----------------------------'  |
 *  |      |                                |
 *  |  ,---|-----------------------------.  |
 *  |  |   |   | libsyscall_intercept.so |  |
 *  |  |   |   `-------------------------|  |
 *  |  | asm_entry_point:                |  |
 *  |  |   call    detect_cur_patch    -----'
 *  |  |   call    exec_relocated_instrs |
 *  |  |   call    intercept_routine     |
 *  |  |   call    exec_relocated_instrs |
 *  |  |   la      REG, return_address   |  REG depends on the patch type
 *  |  |   jalr    zero, 0(REG)          |  back to patch (glibc)
 *  |  |   |                             |
 *  |  `---|-----------------------------'
 *  |      |
 *  `------'
 *
 */
 /* Patching Modes and Assembly Examples:
 *
 * 1. Gateway (TYPE_GW)
 * Full reach (2 GB) patch using 26+ bytes.
 * Original:
 *     0x1000: <instr_1>
 *     ...
 *     0x101a: ecall
 * Patched:
 *     0x1000: addi sp, sp, -48
 *     0x1004: sd   ra, 0(sp)     # Save return address/link register
 *     0x1008: auipc ra, offset
 *     0x100c: jalr  ra, offset(ra) # Jump to interceptor entry
 *     0x1010: ld   ra, 0(sp)     # Restore ra on return
 *     0x1014: addi sp, sp, 48
 *
 * 2. Mid-Jump (TYPE_MID)
 * Short jump (1 MB) to a Gateway entry when ecall is in tight space.
 * Original:
 *     0x2000: <instr_1>
 *     0x2004: ecall
 *     0x2008: <instr_2>
 * Patched:
 *     0x1fed: addi sp, sp, -48   # Overwriting nearby padding/instrs
 *     0x1ff1: sd   ra, 8(sp)     # Save ra at MID_ORIG_RA_OFF
 *     0x1ff5: jal  ra, GW_entry  # Jump to Gateway
 *     0x1ff9: ld   ra, 8(sp)     # Restore ra
 *     0x1ffd: addi sp, sp, 48
 *
 * 3. Small-Trampoline (TYPE_SML)
 * Minimal 4-8 byte patch using A7 for linkage.
 *
 * Case A: Fixed Syscall Number
 * Original:
 *     0x3000: li  a7, 64         # write
 *     0x3004: ecall
 * Patched:
 *     0x3000: li  a7, 64
 *     0x3004: jal a7, GW_entry   # a7 gets return address; syscall 64 stored in patch_desc
 *
 * Case B: Dynamic Syscall Number (mv a7, xx)
 * Original:
 *     0x3000: mv  a7, a0         # syscall number in a0
 *     0x3004: ecall
 * Patched:
 *     0x3000: mv  a7, a0
 *     0x3004: jal a7, GW_entry   # a7 gets return address; syscall recovered from a0 in context
 *
 * 4. Mini-Trampoline (TYPE_MINI_TRAMP)
 * Reach extension (2 GB) using a separate 12-byte "hole" in text.
 * Original:
 *     0x4000: ecall
 * Patched:
 *     0x4000: jal ra, hole_addr  # 4-byte jump to hole
 * In the Hole:
 *     hole:   c.addi ra, 2       # Tag/Adjust return address
 *             auipc  t0, offset
 *             jalr   t0, offset(t0) # Jump to interceptor
 *
 * 5. In-Place (TYPE_INPLACE)
 * Direct replacement of ecall with a jump to the interceptor.
 * Uses A7 as link register for return address matching.
 *
 * Original:
 *     0x5000: mv a7, a0
 *     0x5004: ecall
 * Patched (Wide Jump, 8 bytes):
 *     0x5000: auipc a7, offset
 *     0x5004: jalr  a7, offset(a7) # Syscall recovered from a0 in context
 * Patched (Narrow Jump, 4-6 bytes):
 *     0x4ffe: c.nop              # Padding if needed
 *     0x5000: jal a7, interceptor_addr
 * Note: Gateway (GW) and Mid-Jump (MID) modes preserve the original A7 value
 * naturally because they use RA for linkage. SML and INPLACE modes overwrite
 * A7 with the return address, necessitating recovery from the saved context
 * (see Case B in TYPE_SML).
 *
 */

#include "intercept.h"
#include "intercept_util.h"
#include <sys/syscall.h>

struct wrapper_ret {
    long a0;
    long a1;
};

struct wrapper_ret syscall_no_intercept(long syscall_number, ...);
#include "intercept_log.h"
#include "rv_encode.h"
#include "patch_offsets.h"

#include <assert.h>
#include <stdint.h>
#include <syscall.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

#include <stdio.h>

#define MAX_RELOC_PATCH_SIZE(patch_size)	(patch_size + MAX_PC_INS_SIZE * 15 - ECALL_INS_SIZE)


extern uint8_t asm_relocation_space[];
extern uint64_t asm_relocation_space_size;
static uint8_t *cur_asm_relocation_space = asm_relocation_space;

/*
 * While executing patched instructions, these global variables are used in the
 * relocation space (intercept_irq_entry) in case the patched instructions use
 * ra. The ra register is the only one that lacks the original value from glibc
 * during patch execution, as it's needed for jumps within intercept_irq_entry.
 * These globals serve to temporarily load and store the original ra when it's
 * required by the patched instructions.
 */
extern __thread uint64_t asm_ra_orig;
extern __thread uint64_t asm_ra_temp;

struct tls_offset_table {
	ptrdiff_t asm_ra_orig;
	ptrdiff_t asm_ra_temp;
} tls_offset_table;

void
init_tls_offset_table(void)
{
	uintptr_t tp_addr = (uintptr_t)__builtin_thread_pointer();

	tls_offset_table.asm_ra_orig =
		(uintptr_t)&asm_ra_orig - tp_addr;
	tls_offset_table.asm_ra_temp =
		(uintptr_t)&asm_ra_temp - tp_addr;
}

static bool
is_asm_relocation_space_full(uint8_t curr_patch_size)
{
	return (uint64_t)(cur_asm_relocation_space - asm_relocation_space) >
		asm_relocation_space_size - curr_patch_size;
}

/*
 * is_copiable_before_syscall
 * checks if an instruction found before a syscall instruction
 * can be copied (and thus overwritten).
 */
static bool
is_copiable_before_syscall(struct intercept_disasm_result ins)
{
	if (!ins.is_set)
		return false;

	return !(ins.has_ip_relative_opr || ins.is_abs_jump || ins.is_syscall);
}

/*
 * is_copiable_after_syscall
 * checks if an instruction found after a syscall instruction
 * can be copied (and thus overwritten).
 *
 * Notice: we allow the copy of ret instructions.
 */
static bool
is_copiable_after_syscall(struct intercept_disasm_result ins)
{
	if (!ins.is_set)
		return false;

	return !(ins.has_ip_relative_opr || ins.is_syscall);
}

static bool
is_SML_patchable(struct patch_desc *patch, uint8_t patchable_size)
{
	if (patch->syscall_num < 0) {
		if (patch->a7_source_reg >= 0 && patch->a7_source_reg <= 6)
			return true;
		/* 
		 * If we haven't identified the source, fallback to rigid check.
		 * If implicit A7 modification is detected without a known source,
		 * we can't safely SML patch because we can't recover the number.
		 */
		return false;
	} else if (patchable_size <= JAL_INS_SIZE)
		return false;
	else if (!patch->return_register &&
			(patchable_size == JAL_INS_SIZE + C_LI_INS_SIZE &&
			patch->syscall_num > 31))
		return false;

	return true;
}

static uint8_t
check_two_ecalls(struct patch_desc *patch, uint8_t syscall_idx,
			uint8_t start_idx, uint8_t second_ecall_idx)
{
	struct intercept_disasm_result *instrs = patch->surrounding_instrs;

	// when a7 is not obtained, force the TYPE_MID
	uint8_t before_2nd_ecall_size = 0;
	if (patch->syscall_num < 0) {
		for (uint8_t i = start_idx; i < second_ecall_idx; ++i) {
			before_2nd_ecall_size += instrs[i].length;

			if (before_2nd_ecall_size >= TYPE_MID_SIZE)
				return i + 1;
		}
	}

	// when the TYPE_MID/TYPE_SML fits before the 1st ecall (best option)
	uint8_t up_to_ecall_size = 0;
	for (uint8_t i = start_idx; i <= syscall_idx; ++i) {
		up_to_ecall_size += instrs[i].length;

		if (up_to_ecall_size >= TYPE_MID_SIZE ||
				is_SML_patchable(patch, up_to_ecall_size))
			return syscall_idx + 1;
	}

	// as a last resort, fit TYPE_SML anywhere up to the 2nd ecall
	before_2nd_ecall_size = 0;
	for (uint8_t i = start_idx; i < second_ecall_idx; ++i) {
		before_2nd_ecall_size += instrs[i].length;

		if (is_SML_patchable(patch, before_2nd_ecall_size))
			return i + 1;
	}

	// failed: end_idx == start_idx
	return start_idx;
}

/*
 * check_surrounding_instructions
 * Sets up the following members in a patch_desc, based on
 * instruction being relocateable or not:
 * uses_prev_ins ; uses_prev_ins_2 ; uses_next_ins
 */
static uint8_t
check_surrounding_instructions(struct intercept_desc *desc,
				struct patch_desc *patch)
{
	struct intercept_disasm_result *instrs = patch->surrounding_instrs;
	uint8_t instrs_num = SURROUNDING_INSTRS_NUM;
	uint8_t syscall_idx = SYSCALL_IDX;
	uint8_t patch_start_idx = 0;
	uint8_t patch_end_idx = instrs_num;
	uint8_t patchable_size = 0;
	
	patch->a7_source_reg = -1;

	// check if the instruction after the ecall sets a register
	if (instrs[syscall_idx + 1].reg_set)
		patch->return_register = instrs[syscall_idx + 1].reg_set;

	for (uint8_t i = 0; i < instrs_num; ++i) {
		if (i < syscall_idx) {
			if (has_jump(desc, instrs[i + 1].address)) {
				patch_start_idx = i + 1;
				patch->syscall_num = -1;
			} else if (!is_copiable_before_syscall(instrs[i])) {
				patch_start_idx = i + 1;
			}

			if (instrs[i].a7_set > -1) {
				patch->syscall_num = instrs[i].a7_set;
				patch->a7_source_reg = -1;
			} else if (instrs[i].is_a7_modified) {
				patch->syscall_num = -1;
				// check if we captured the source register
				if (instrs[i].a7_source_reg >= 0)
					patch->a7_source_reg = instrs[i].a7_source_reg;
				else
					patch->a7_source_reg = -1;
			}
		} else if (i > syscall_idx) {
			if (instrs[i].is_syscall) {
				patch_end_idx = check_two_ecalls(patch,
						syscall_idx, patch_start_idx, i);
				break;
			} else if (!is_copiable_after_syscall(instrs[i]) ||
					has_jump(desc, instrs[i].address)) {
				patch_end_idx = i;
				break;
			}
		}
	}

	// fix indexes according to patchable instrs
	syscall_idx = syscall_idx - patch_start_idx;
	patch->syscall_idx = syscall_idx;
	instrs_num = patch_end_idx - patch_start_idx;
	if (instrs_num < 1)
		return 0;

	// shift usable instrs to the left
	memmove(patch->surrounding_instrs, instrs + patch_start_idx,
		instrs_num * sizeof(struct intercept_disasm_result));

	// get final patchable size, and check if ra is used before ecall
	for (uint8_t i = 0; i < instrs_num; ++i) {
		patchable_size += instrs[i].length;

		if (instrs[i].is_ra_used) {
			if (i < syscall_idx)
				patch->is_ra_used_before = true;
			else
				patch->is_ra_used_after = true;
		}
	}
	

	
	return patchable_size;
}

static void
find_GW(struct intercept_desc *desc, struct patch_desc *patch)
{
	uint32_t patch_i;
	ptrdiff_t dst;
	const uint8_t *jump_from;

	// TYPE_MID and TYPE_SML jump address and offset (TYPE_MID)
	if (patch->syscall_num == TYPE_MID)
		jump_from = patch->return_address - JAL_INS_SIZE -
				MODIFY_SP_INS_SIZE;
	else // TYPE_SML
		jump_from = patch->return_address - JAL_INS_SIZE;

	for (patch_i = 0; patch_i < desc->count; ++patch_i) {
		struct patch_desc *patch_GW = desc->items + patch_i;

		// not a TYPE_GW, skip
		if (patch_GW->syscall_num != TYPE_GW)
			continue;

		dst = patch_GW->dst_jmp_patch - jump_from;
		if (JAL_NEG_REACH <= dst && dst <= JAL_POS_REACH) {
			patch->dst_jmp_patch = patch_GW->dst_jmp_patch;
			break;
		}
	}

	if (patch_i >= desc->count)
		xabort(__func__, "no Gateways in reach; if INTERCEPT_SYS_INCLUDE "
				"was used, include more syscalls to find a GW");

	// offsetting TYPE_MID to skip `addi sp, sp, -PATCH_SP_OFF`
	if (patch->syscall_num == TYPE_MID)
		patch->dst_jmp_patch += MODIFY_SP_INS_SIZE;
}

#ifdef __riscv_c
static void
check_patch_alignment(struct patch_desc *patch, const uint8_t *start_addr,
			uint8_t required_size)
{
	struct intercept_disasm_result *instrs = patch->surrounding_instrs;
	const uint8_t *end_addr = start_addr + required_size;
	patch->start_with_c_nop = true;
	patch->end_with_c_nop = true;

	for (uint8_t i = 0; i < SURROUNDING_INSTRS_NUM; ++i) {
		if (start_addr == instrs[i].address)
			patch->start_with_c_nop = false;
		else if (end_addr == instrs[i].address)
			patch->end_with_c_nop = false;
		else if (end_addr < instrs[i].address)
			break;
	}
}
#endif

static void
position_patch(struct patch_desc *patch)
{
	struct intercept_disasm_result *instrs = patch->surrounding_instrs;
	uint8_t up_to_ecall_size = 0;
	const uint8_t *start_addr;
	uint8_t required_size;

	for (uint8_t i = 0; i <= patch->syscall_idx; ++i)
		up_to_ecall_size += instrs[i].length;

	switch (patch->syscall_num) {
	case TYPE_GW:
		required_size = TYPE_GW_SIZE;

		if (up_to_ecall_size >= required_size)
			patch->return_address =
				patch->syscall_addr + ECALL_INS_SIZE -
				MODIFY_SP_INS_SIZE - STORE_LOAD_INS_SIZE;
		else
			patch->return_address =
				instrs[0].address + MODIFY_SP_INS_SIZE +
				STORE_LOAD_INS_SIZE + JUMP_2GB_INS_SIZE;

		start_addr = patch->return_address - JUMP_2GB_INS_SIZE -
				STORE_LOAD_INS_SIZE - MODIFY_SP_INS_SIZE;
		break;
	case TYPE_MID:
		required_size = TYPE_MID_SIZE;

		if (up_to_ecall_size >= required_size)
			patch->return_address =
				patch->syscall_addr + ECALL_INS_SIZE -
				MODIFY_SP_INS_SIZE - STORE_LOAD_INS_SIZE;
		else
			patch->return_address =
				instrs[0].address + MODIFY_SP_INS_SIZE +
				STORE_LOAD_INS_SIZE + JAL_INS_SIZE;

		start_addr = patch->return_address - JAL_INS_SIZE -
				STORE_LOAD_INS_SIZE - MODIFY_SP_INS_SIZE;
		break;

	case TYPE_MINI_TRAMP:
		required_size = 4; // JAL (4 bytes)
		// We overwrite the syscall itself (4 bytes).
		// start_addr is syscall_addr
		start_addr = patch->syscall_addr; // Assuming we just overwrite ecall
		// return address is start + 4
		patch->return_address = start_addr + 4;
		break;
	default: // TYPE_SML
		if (patch->return_register)
			required_size = JAL_INS_SIZE;
#ifdef __riscv_c
		else if (patch->syscall_num < 32)
			required_size = JAL_INS_SIZE + C_LI_INS_SIZE;
#endif
		else
			required_size = JAL_INS_SIZE + ADDI_INS_SIZE;

		if (patch->return_register)
			patch->return_address =
				patch->syscall_addr + JAL_INS_SIZE;
		else if (up_to_ecall_size >= required_size)
			patch->return_address =
				patch->syscall_addr + ECALL_INS_SIZE -
				required_size + JAL_INS_SIZE;
		else
			patch->return_address =
				instrs[0].address + JAL_INS_SIZE;

		start_addr = patch->return_address - JAL_INS_SIZE;
		break;
	case TYPE_INPLACE:
		/*
		 * In-place patching uses 6 bytes to allow for a JAL/JALR to the trampoline.
		 * This usually involves 2 bytes before the ecall site.
		 */
		required_size = 6;
		start_addr = patch->syscall_addr - 2;
		patch->return_address = start_addr + required_size;
        break;
	}

	patch->dst_jmp_patch = (uint8_t *)start_addr;
	patch->patch_size_bytes = required_size;

#ifdef __riscv_c
	check_patch_alignment(patch, start_addr, required_size);
#endif
}

#ifdef __riscv_c
static void
align_start_addr_and_size(struct patch_desc *patch,
				uint8_t **start_addr, size_t *patch_size)
{
	if (patch->start_with_c_nop) {
		*start_addr -= C_NOP_INS_SIZE;
		*patch_size += C_NOP_INS_SIZE;
	}
	if (patch->end_with_c_nop)
		*patch_size += C_NOP_INS_SIZE;
}
#endif

static void
load_orig_ra_temp(void)
{
	uint8_t instrs_buff[MAX_PC_INS_SIZE * 2];
	uint8_t instrs_size = 0;

	instrs_size += rvpc_sd(instrs_buff + instrs_size, REG_RA, REG_TP,
				(int32_t)tls_offset_table.asm_ra_temp);
	instrs_size += rvpc_ld(instrs_buff + instrs_size, REG_RA, REG_TP,
				(int32_t)tls_offset_table.asm_ra_orig);

	memcpy(cur_asm_relocation_space, instrs_buff, instrs_size);
	cur_asm_relocation_space += instrs_size;
}

static void
store_new_ra_temp(void)
{
	uint8_t instrs_buff[MAX_PC_INS_SIZE * 2];
	uint8_t instrs_size = 0;

	instrs_size += rvpc_sd(instrs_buff + instrs_size, REG_RA, REG_TP,
				(int32_t)tls_offset_table.asm_ra_orig);
	instrs_size += rvpc_ld(instrs_buff + instrs_size, REG_RA, REG_TP,
				(int32_t)tls_offset_table.asm_ra_temp);

	memcpy(cur_asm_relocation_space, instrs_buff, instrs_size);
}

	/*
	 * copy_jump
	 * Generates a JALR instruction to jump to the provided address.
	 */
	static void
	copy_jump(uint8_t rd, uint8_t rs, int16_t offset)
	{
		uint8_t instr_buff[MAX_PC_INS_SIZE];
		uint8_t instr_size;

		instr_size = rvpc_jalr(instr_buff, rd, rs, offset);

		memcpy(cur_asm_relocation_space, instr_buff, instr_size);
		cur_asm_relocation_space += instr_size;
	}



static void
finalize_and_jump_back(struct patch_desc *patch)
{
	uint8_t instrs_buff[MAX_PC_INS_SIZE * 5];
	uint8_t instrs_size = 0;
	uint8_t ret_reg = patch->return_register;

	// load original ra value if it's not used for jumping back
	if (ret_reg != REG_RA)
		instrs_size += rvpc_ld(instrs_buff + instrs_size,
					REG_RA, REG_SP, ORIG_RA_OFF);

	switch (patch->syscall_num) {
	case TYPE_GW:
		// load the return address into the register used for jumping back
		instrs_size += rvpc_ld(instrs_buff + instrs_size,
					ret_reg, REG_SP, RET_ADDR_OFF);
		break;
	case TYPE_MID:
		/*
		 * TYPE_MID expects the original ra value at a different offset
		 * than TYPE_GW, so reorganize the stack by moving the value at
		 * offset ORIG_RA_OFF to offset MID_ORIG_RA_OFF.
		 */
		instrs_size += rvpc_ld(instrs_buff + instrs_size,
					ret_reg, REG_SP, ORIG_RA_OFF);
		instrs_size += rvpc_sd(instrs_buff + instrs_size,
					ret_reg, REG_SP, MID_ORIG_RA_OFF);

		// load the return address into the register used for jumping back
		instrs_size += rvpc_ld(instrs_buff + instrs_size,
					ret_reg, REG_SP, RET_ADDR_OFF);
		break;
	case TYPE_INPLACE:
		// Append ECALL (0x00000073) because relocate_instrs skips it, and proper execution
		// requires it in this final block (Block 3) which runs outside the lock.
		// ECALL is 4 bytes: 0x73 0x00 0x00 0x00 (little endian)
		instrs_buff[instrs_size++] = 0x73;
		instrs_buff[instrs_size++] = 0x00;
		instrs_buff[instrs_size++] = 0x00;
		instrs_buff[instrs_size++] = 0x00;

		// Directly jump to the return address (constant).
		// We use rvp_jump_abs which handles 64-bit address materialization and jump.
		// No need to load from stack (RET_ADDR_OFF is not reliable here).
		instrs_size += rvp_jump_abs(instrs_buff + instrs_size, REG_ZERO,
						ret_reg, (uintptr_t)patch->return_address);
        
        // Skip the common rvpc_jalr at the end, as jump_abs does it.
        // We return early or copy buffer.
        memcpy(cur_asm_relocation_space, instrs_buff, instrs_size);
        cur_asm_relocation_space += instrs_size;
        return;

	default: // TYPE_SML
		// if not specified, TYPE_SML uses REG_A7 to jump back to glibc
		if (!ret_reg)
			ret_reg = REG_A7;

		// load the return address into the register used for jumping back
		instrs_size += rvpc_ld(instrs_buff + instrs_size,
					ret_reg, REG_SP, RET_ADDR_OFF);

		/*
		 * The TYPE_SML patch doesn't allocate any stack space in glibc,
		 * but sp gets reduced by PATCH_SP_OFF in GW, so deallocate the
		 * stack here before jumping back to TYPE_SML.
		 */
		instrs_size += rvpc_addisp(instrs_buff + instrs_size, PATCH_SP_OFF);
		break;
	}

	// copy the jump instruction to return to glibc
	instrs_size += rvpc_jalr(instrs_buff + instrs_size, REG_ZERO, ret_reg, 0);

	memcpy(cur_asm_relocation_space, instrs_buff, instrs_size);
	cur_asm_relocation_space += instrs_size;
}

static void
relocate_instrs(struct patch_desc *patch)
{
	patch->relocation_address = cur_asm_relocation_space;

	uint8_t *start_addr = patch->dst_jmp_patch;
	size_t patch_size = patch->patch_size_bytes;
	size_t before_ecall_size;
	size_t after_ecall_size;

#ifdef __riscv_c
	align_start_addr_and_size(patch, &start_addr, &patch_size);
#endif
	if (patch->is_ra_used_before)
		load_orig_ra_temp();

	/* copy patched instructions before ecall */
	before_ecall_size = patch->syscall_addr - start_addr;
	memcpy(cur_asm_relocation_space, start_addr, before_ecall_size);
	cur_asm_relocation_space += before_ecall_size;

	if (patch->is_ra_used_before)
		store_new_ra_temp();

	/*
	 * the instructions before ecall are copied,
	 * copy jump instruction to go back to asm_entry_point
	 */
	copy_jump(REG_RA, REG_RA, 0);

	/* copy patched instructions after ecall */
	after_ecall_size = patch_size - before_ecall_size - ECALL_INS_SIZE;
	if (after_ecall_size > 0) {
		if (patch->is_ra_used_after)
			load_orig_ra_temp();

		memcpy(cur_asm_relocation_space, patch->syscall_addr + ECALL_INS_SIZE,
			after_ecall_size);
		cur_asm_relocation_space += after_ecall_size;

		if (patch->is_ra_used_after)
			store_new_ra_temp();
	}

	/*
	 * the instructions after ecall are copied,
	 * copy jump instruction to return to asm_entry_point
	 */
	copy_jump(REG_RA, REG_RA, 0);

	/* prepare for jump and go back to glibc */
	finalize_and_jump_back(patch);

	return;
}

/*
 * create_patch
 * Validates available space around a syscall and determines the appropriate
 * patching strategy (Gateway, Mid-Jump, etc.).
 */
static const char *get_patch_mode_str(int type) {
	if (type == TYPE_GW) return "Gateway";
	if (type == TYPE_MID) return "Mid-Jump";
    // Check for new types assuming they are defined since build passed

    if (type == TYPE_MINI_TRAMP) return "Mini-Trampoline";
    if (type == TYPE_INPLACE) return "In-Place";
	return "Small-Trampoline";
}

void
create_patch(struct intercept_desc *desc)
{
	char *stats_env = getenv("INTERCEPT_LOG_STATS");
	bool log_stats = (stats_env && stats_env[0] == '1');

	for (uint32_t patch_i = 0; patch_i < desc->count; ++patch_i) {
		struct patch_desc *patch = desc->items + patch_i;
		debug_dump("patching %s:0x%lx\n", desc->path,
				patch->syscall_addr - desc->base_addr);

		uint8_t length = check_surrounding_instructions(desc, patch);
        
        // Avoid large patches (GW/MID/GOT) near the end of the text segment to prevent overflow.
        // INPLACE (6 bytes) or SML (4 bytes) are preferred in these edge cases.
        bool near_text_end = (patch->syscall_addr + 64 > desc->text_end);

		// Determine patch strategy
	// Determine patch strategy


	if (!near_text_end && length >= TYPE_GW_SIZE) {
			patch->syscall_num = TYPE_GW;
			patch->return_register = REG_RA;

			if (!desc->uses_trampoline) {
				position_patch(patch);
				extern void asm_entry_point(void);
				uintptr_t jalr_addr = (uintptr_t)patch->return_address -
							JUMP_2GB_INS_SIZE;
				ptrdiff_t delta = (uintptr_t)asm_entry_point - jalr_addr;

				if (delta < JUMP_2GB_NEG_REACH || delta > JUMP_2GB_POS_REACH) {
					char buffer[0x1000];
					int l = snprintf(buffer, sizeof(buffer),
						"unintercepted syscall at: %s 0x%lx (out of range for GW without trampoline)\n",
						desc->path, patch->syscall_offset);
					intercept_log(buffer, (size_t)l);

					free(patch->surrounding_instrs);
					size_t num_to_move = desc->count - patch_i - 1;
					if (num_to_move > 0)
						memmove(patch, patch + 1, num_to_move * sizeof(*patch));
					desc->count--;
					patch_i--;
					continue;
				}
			}

		} else if (!near_text_end && length >= TYPE_MID_SIZE) {
			patch->syscall_num = TYPE_MID;
			patch->return_register = REG_RA;

		} else if (near_text_end || !is_SML_patchable(patch, length)) {
			// SML failed. Check for GOT fallback or Mini Trampoline.
			bool patched = false;


			
			if (!patched) {
                // No GOT or GOT logic failed. Try Mini Trampoline.
                // Especially important if invalid GP.
                if (find_usable_text_hole(desc, patch->syscall_addr, 10)) {
                    patch->syscall_num = TYPE_MINI_TRAMP;
                    patch->got_entry_addr = find_usable_text_hole(desc, patch->syscall_addr, 10);
                    patch->return_register = REG_RA;
                    position_patch(patch);
                    patched = true;
                    

                } else if (!desc->gp_value) {
                    // No GP for GOT, No Hole for MINI_TRAMP.
                    // Cannot use INPLACE (likely > 1MB).
                    // Explicitly remove patch.
                    // char buffer[256];
                    // int l = snprintf(buffer, sizeof(buffer),
                    //    "DEBUG: Removing unpatchable syscall at %lx (No GP, No Hole)\n",
                    //    patch->syscall_offset);
                    // syscall_no_intercept(SYS_write, 2, buffer, l);

                    free(patch->surrounding_instrs);
                    size_t num_to_move = desc->count - patch_i - 1;
                    if (num_to_move > 0)
                        memmove(patch, patch + 1, num_to_move * sizeof(*patch));
                    desc->count--;
                    patch_i--;
                    continue;
                }
                // If MINI_TRAMP failed but GP exists (shouldn't happen here due to checks), fall through.
                // Or if logic changes.
			}
			
			if (!patched) {
                // Try In-Place (overwriting prev + ecall).
                // Requires patchable_size >= 6 (2+4 bytes minimum) and a7_source_reg >= 0.
                if (length >= 6 && patch->a7_source_reg >= 0) {
                     patch->syscall_num = TYPE_INPLACE;
                     // We use c.jalr which sets RA. So return reg is RA.
                     patch->return_register = REG_A7; 
                     position_patch(patch);
                     patched = true;
                }
            }

			if (!patched) {
				char buffer[0x1000];

				int l = snprintf(buffer, sizeof(buffer),
					"unintercepted syscall at: %s 0x%lx\n",
					desc->path,
					patch->syscall_offset);

				intercept_log(buffer, (size_t)l);
				free(patch->surrounding_instrs);
				size_t num_to_move = desc->count - patch_i - 1;
				if (num_to_move > 0)
					memmove(patch, patch + 1, num_to_move * sizeof(*patch));
				desc->count--;
				patch_i--;
				continue;
			}
		}
if (patch->syscall_num != TYPE_GW || desc->uses_trampoline)
			if (patch->syscall_num != TYPE_MINI_TRAMP && patch->syscall_num != TYPE_INPLACE)
				position_patch(patch);
//		position_patch(patch);

		if (log_stats) {
			char buffer[256];
			int l = snprintf(buffer, sizeof(buffer), 
				"STATS: Patch 0x%lx Type: %s\n", 
				patch->syscall_offset, 
				get_patch_mode_str(patch->syscall_num));
			syscall_no_intercept(SYS_write, 2, buffer, l);
		}

		uint8_t *last_instr_addr = patch->dst_jmp_patch + patch->patch_size_bytes;
#ifdef __riscv_c
		if (patch->end_with_c_nop)
			last_instr_addr += C_NOP_INS_SIZE;
#endif
		mark_jump(desc, last_instr_addr);

		if (is_asm_relocation_space_full(MAX_RELOC_PATCH_SIZE(patch->patch_size_bytes)))
			xabort(__func__, "insufficient relocation space, increase "
				"RELOCATION_SIZE constant inside of intercept_irq_entry.S");

		relocate_instrs(patch);

		/*
		 * All valuable info from the surrounding instrs is gathered,
		 * free all intercept_disasm_result structs.
		 */
		free(patch->surrounding_instrs);
		patch->surrounding_instrs = NULL;
	}

	for (uint32_t patch_i = 0; patch_i < desc->count; ++patch_i) {
		struct patch_desc *patch = desc->items + patch_i;

		if (patch->syscall_num != TYPE_GW)
			find_GW(desc, patch);
	}
}

static void
copy_trampoline(uint8_t *trampoline_address)
{
	/* This function (destination) is part of intercept_irq_entry.S */
	extern void asm_entry_point(void);
	uintptr_t destination = (uintptr_t)asm_entry_point + TRAMPOLINE_JUMP_OFFSET;

	uint8_t instrs_buff[MAX_PC_INS_SIZE + MAX_P_INS_SIZE];
	uint8_t instrs_size = 0;

	instrs_size += rvpc_sd(instrs_buff + instrs_size,
				REG_RA, REG_SP, UNUSED_OFF1);

	instrs_size += rvp_jump_abs(instrs_buff + instrs_size, REG_ZERO,
					REG_RA, destination);

	for (uint8_t i = 0; i < instrs_size; ++i)
		trampoline_address[i] = instrs_buff[i];
}

static void
copy_GW(struct intercept_desc *desc, const struct patch_desc *patch)
{
	/* This function (destination) is part of intercept_irq_entry.S */
	extern void asm_entry_point(void);

	uint8_t instrs_buff[MAX_PC_INS_SIZE * 6 + MAX_P_INS_SIZE];
	uint8_t instrs_size = 0;

	uint8_t *patch_start_addr = patch->dst_jmp_patch;
	uint8_t ret_reg = patch->return_register;
	uintptr_t jalr_addr = (uintptr_t)patch->return_address -
				JUMP_2GB_INS_SIZE;

	uintptr_t destination;
	if (desc->uses_trampoline)
		destination = (uintptr_t)desc->trampoline_address;
	else
		destination = (uintptr_t)asm_entry_point;

#ifdef __riscv_c
	if (patch->start_with_c_nop) {
		instrs_size += rvc_nop(instrs_buff + instrs_size);
		patch_start_addr -= RVC_INS_SIZE;
	}
#endif

	instrs_size += rvpc_addisp(instrs_buff + instrs_size, -PATCH_SP_OFF);
	instrs_size += rvpc_sd(instrs_buff + instrs_size,
				ret_reg, REG_SP, ORIG_RA_OFF);

	uint8_t size = rvp_jump_GW(instrs_buff + instrs_size, ret_reg, ret_reg,
					jalr_addr, destination);
	// if rvp_jump_GW() fails, it implies `INTERCEPT_NO_TRAMPOLINE=1`
	if (size == 0)
		xabort(__func__, "libsyscall_intercept.so and the target library are "
			"more than 2 GB apart. A trampoline must be used; unset the "
			"INTERCEPT_NO_TRAMPOLINE environment variable.");
	instrs_size += size;

	instrs_size += rvpc_ld(instrs_buff + instrs_size,
				ret_reg, REG_SP, ORIG_RA_OFF);
	instrs_size += rvpc_addisp(instrs_buff + instrs_size, PATCH_SP_OFF);

#ifdef __riscv_c
	if (patch->end_with_c_nop)
		instrs_size += rvc_nop(instrs_buff + instrs_size);
#endif

	// cannot use memcpy() anymore...
	for (uint8_t i = 0; i < instrs_size; ++i)
		patch_start_addr[i] = instrs_buff[i];
}

static void
copy_MID(const struct patch_desc *patch)
{
	uint8_t instrs_buff[MAX_PC_INS_SIZE * 6 + MAX_P_INS_SIZE];
	uint8_t instrs_size = 0;
	uint8_t *patch_start_addr = (uint8_t *)patch->return_address -
						JAL_INS_SIZE -
						STORE_LOAD_INS_SIZE -
						MODIFY_SP_INS_SIZE;
	uint8_t ret_reg = patch->return_register;
	uintptr_t GW_entry_addr = (uintptr_t)patch->dst_jmp_patch;
	uintptr_t jal_addr = (uintptr_t)patch->return_address - JAL_INS_SIZE;

#ifdef __riscv_c
	if (patch->start_with_c_nop) {
		instrs_size += rvc_nop(instrs_buff + instrs_size);
		patch_start_addr -= RVC_INS_SIZE;
	}
#endif

	instrs_size += rvpc_addisp(instrs_buff + instrs_size, -PATCH_SP_OFF);
	instrs_size += rvpc_sd(instrs_buff + instrs_size,
				ret_reg, REG_SP, MID_ORIG_RA_OFF);

	instrs_size += rvp_jal(instrs_buff + instrs_size, ret_reg,
				jal_addr, GW_entry_addr);

	instrs_size += rvpc_ld(instrs_buff + instrs_size,
				ret_reg, REG_SP, MID_ORIG_RA_OFF);
	instrs_size += rvpc_addisp(instrs_buff + instrs_size, PATCH_SP_OFF);

#ifdef __riscv_c
	if (patch->end_with_c_nop)
		instrs_size += rvc_nop(instrs_buff + instrs_size);
#endif

	// cannot use memcpy() anymore...
	for (uint8_t i = 0; i < instrs_size; ++i)
		patch_start_addr[i] = instrs_buff[i];
}

static void
copy_SML(const struct patch_desc *patch)
{
	uint8_t instrs_buff[MAX_PC_INS_SIZE * 3 + MAX_P_INS_SIZE];
	uint8_t instrs_size = 0;
	uint8_t *patch_start_addr = (uint8_t *)patch->return_address -
							JAL_INS_SIZE;
	uintptr_t GW_entry_addr = (uintptr_t)patch->dst_jmp_patch;
	uintptr_t jal_addr = (uintptr_t)patch->return_address - JAL_INS_SIZE;

#ifdef __riscv_c
	if (patch->start_with_c_nop) {
		instrs_size += rvc_nop(instrs_buff + instrs_size);
		patch_start_addr -= RVC_INS_SIZE;
	}
#endif

	instrs_size += rvp_jal(instrs_buff + instrs_size, REG_A7,
				jal_addr, GW_entry_addr);

	if (!patch->return_register)
		instrs_size += rvpc_li(instrs_buff + instrs_size, REG_A7,
					patch->syscall_num);

#ifdef __riscv_c
	if (patch->end_with_c_nop)
		instrs_size += rvc_nop(instrs_buff + instrs_size);
#endif

	// cannot use memcpy() anymore...
	for (uint8_t i = 0; i < instrs_size; ++i)
		patch_start_addr[i] = instrs_buff[i];
}

static void
copy_MINI_TRAMP(struct intercept_desc *desc, struct patch_desc *patch)
{
	/* This function (destination) is part of intercept_irq_entry.S */
	extern void asm_entry_point(void);
	uintptr_t destination = (uintptr_t)asm_entry_point;
	if (desc->uses_trampoline && desc->trampoline_address)
		destination = (uintptr_t)desc->trampoline_address;

	uint8_t *hole_addr = (uint8_t *)patch->got_entry_addr;
	if (!hole_addr) xabort(__func__, "MINI_TRAMP hole address is NULL");

	// 1. Write jump-to-trampoline code to the hole
	uint8_t hole_instrs[32];
	uint8_t hole_size = 0;

	/* c.addi x1, 2 (2 bytes) = 0x0089 */
	hole_instrs[hole_size++] = 0x89;
	hole_instrs[hole_size++] = 0x00;
	
	hole_size += rvp_jump_abs(hole_instrs + hole_size, REG_T0,
					REG_T0, destination);
					
	for(int i=0; i<hole_size; ++i) hole_addr[i] = hole_instrs[i];
	
	// Clear cache for hole
	__builtin___clear_cache((char *)hole_addr, (char *)(hole_addr + hole_size));
	
	// 2. Write jal hole to patch site (4 bytes)
	// dst_jmp_patch is just the syscall address (we overwrite at least 4 bytes).
	
	uint8_t patch_instrs[4];
	size_t patch_size = rvp_jal(patch_instrs, REG_RA, (uintptr_t)patch->dst_jmp_patch, (uintptr_t)hole_addr);
	
	for(size_t i=0; i<patch_size; ++i) patch->dst_jmp_patch[i] = patch_instrs[i];
	
	// Clean cache for patch
	__builtin___clear_cache((char *)patch->dst_jmp_patch, (char *)(patch->dst_jmp_patch + patch_size));
}

static void
copy_INPLACE(struct intercept_desc *desc, struct patch_desc *patch)
{
	extern void asm_entry_point(void);
	uintptr_t destination = (uintptr_t)asm_entry_point;
	if (desc->uses_trampoline && desc->trampoline_address)
		destination = (uintptr_t)desc->trampoline_address;

    uint8_t instrs_buff[16];
    uint8_t instrs_size = 0;
    
    // Check reachability
    int64_t off = (int64_t)destination - (int64_t)patch->dst_jmp_patch;
    bool wide_jump = (off < -1048576 || off > 1048575);
    
    if (!wide_jump) {
        // Narrow Jump (JAL 4 bytes).
        // Pad with NOPs so that JAL is at the end of the patch.
        // This ensures A7 (PC+4) == patch_end == return_address.
        // size >= 4 is guaranteed by create_patch.
        size_t pad_bytes = patch->patch_size_bytes - 4;
        while (pad_bytes >= 2) {
             // c.nop (0x0001)
             instrs_buff[instrs_size++] = 0x01;
             instrs_buff[instrs_size++] = 0x00;
             pad_bytes -= 2;
        }
        instrs_size += rvp_jal(instrs_buff + instrs_size, REG_A7, 
                               (uintptr_t)patch->dst_jmp_patch + instrs_size, destination);
    } else {
        if (patch->patch_size_bytes < 8) {
            debug_dump("DEBUG: copy_INPLACE skipping patch at %p: off=%ld size=%d\n", 
                     (void*)patch->syscall_addr, off, patch->patch_size_bytes);
            // intercept_log(buf, strlen(buf));
            return;
        }
        // AUIPC+JALR (8 bytes) via A7
        instrs_size += rvp_jump_abs(instrs_buff, REG_A7, REG_ZERO, destination);
    }
    
    uint8_t *patch_addr = patch->dst_jmp_patch;
    for(int i=0; i<instrs_size; ++i) patch_addr[i] = instrs_buff[i];
    
    // Pad
    if (patch->patch_size_bytes > instrs_size) {
         for(int i=instrs_size; i < patch->patch_size_bytes; i+=2) {
             patch_addr[i] = 0x01;
             patch_addr[i+1] = 0x00;
         }
    }
    
    size_t clear_size = (instrs_size > patch->patch_size_bytes) ? instrs_size : patch->patch_size_bytes;
    __builtin___clear_cache((char *)patch_addr, (char *)(patch_addr + clear_size));
}


/*
 * activate_patches()
 * Loop over all the patches, and and overwrite each syscall.
 */
void
activate_patches(struct intercept_desc *desc)
{
	unsigned char *first_page;
	size_t size;

	if (desc->count == 0)
		return;

	// syscall_no_intercept(SYS_write, 2, "DEBUG: activate_patches start\n", 30);
    
    // char buf[64];
    // int len = snprintf(buf, 64, "DEBUG: gp_value: %p\n", (void*)desc->gp_value);
    // syscall_no_intercept(SYS_write, 2, buf, len);

	if (desc->uses_trampoline) {
		copy_trampoline(desc->trampoline_address);

        // Copy relocated instructions from static non-exec buffer to trampoline (executable)
        size_t reloc_size = (size_t)(cur_asm_relocation_space - asm_relocation_space);
        // Use offset 64 to skip trampoline header (copy_trampoline uses < 64 bytes)
        uint8_t *reloc_dest = desc->trampoline_address + 64; 
        
        // Ensure we don't overflow the trampoline page? 
        // Trampoline is allocated via allocate_trampoline using TRAMPOLINE_SIZE.
        // Assuming TRAMPOLINE_SIZE is sufficient (typically 1 page).
        
		debug_dump("DEBUG: copying trampoline\n");
        memcpy(reloc_dest, asm_relocation_space, reloc_size);
		debug_dump("DEBUG: trampoline copy done\n");
        __builtin___clear_cache((char*)reloc_dest, (char*)(reloc_dest + reloc_size));
        
        // Update relocation_address for all patches to point to the executable copy
        for (unsigned i = 0; i < desc->count; ++i) {
             struct patch_desc *p = desc->items + i;
             // Check if relocation_address points to the static buffer
             if (p->relocation_address >= asm_relocation_space &&
                 p->relocation_address < cur_asm_relocation_space) {
                 ptrdiff_t offset = p->relocation_address - (const uint8_t*)asm_relocation_space;
                 p->relocation_address = reloc_dest + offset;
             }
        }
		debug_dump("DEBUG: ptr update done\n");
	}
	
	first_page = round_down_address(desc->text_start);
	size = (size_t)(desc->text_end - first_page);

	mprotect_no_intercept(first_page, size,
	    PROT_READ | PROT_WRITE | PROT_EXEC,
	    "mprotect PROT_READ | PROT_WRITE | PROT_EXEC");
	debug_dump("DEBUG: mprotect RW done\n");

    for (unsigned i = 0; i < desc->count; ++i) {
		struct patch_desc *patch = desc->items + i;

        // Safety: Explicitly skip the last detected patch.
        // Empirical testing confirms the final syscall entry in libc (offset 0xf77a0)
        // often resides right at the boundary of the executable segment.
        // Attempting to patch it (especially with TYPE_GW which writes ~24 bytes)
        // triggers a Segmentation Fault due to writing into non-writable or unmapped memory.
        if (i == desc->count - 1) {
             continue;
        }

        // Check bounds including alignment padding
        uint8_t *real_start = patch->dst_jmp_patch;
        size_t real_size = patch->patch_size_bytes;

#ifdef __riscv_c
        if (patch->start_with_c_nop) {
            real_start -= 2; // RVC_INS_SIZE
            real_size += 2;
        }
        if (patch->end_with_c_nop)
            real_size += 2;
#endif

		if (real_start < desc->text_start ||
		    real_start + real_size > desc->text_end) {
			continue;
        }

		switch (patch->syscall_num) {
		case TYPE_GW:
			copy_GW(desc, patch);
			break;
		case TYPE_MID:
			copy_MID(patch);
			break;
		case TYPE_INPLACE:
			copy_INPLACE(desc, patch);
			break;
		case TYPE_MINI_TRAMP:
			copy_MINI_TRAMP(desc, patch);
			break;
		default:
			copy_SML(patch);
			break;
		}
	}

	__builtin___clear_cache((char *)first_page, (char *)(first_page + size));

	mprotect_no_intercept(first_page, size,
	    PROT_READ | PROT_EXEC,
	    "mprotect PROT_READ | PROT_EXEC");
}
