/*
 * Copyright 2016-2024, Intel Corporation
 * Contributor: Petar Andrić
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
 * (Updated: Supports GP-based and JAL-based patches)
 */

#include "intercept.h"
#include "intercept_util.h"
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

long syscall_no_intercept(long number, ...);

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

	/*
	 * Reject instructions that modify syscall arguments (a0-a6).
	 * Reg set is 1-based index shifted by -1.
	 * REG_A0=10 (index 9), REG_A6=16 (index 15).
	 */
	if (ins.reg_set >= (REG_A0 - 1) && ins.reg_set <= (16 - 1))
		return false;

	return !(ins.has_ip_relative_opr || ins.is_abs_jump || ins.is_syscall || ins.is_ret);
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

	return !(ins.has_ip_relative_opr || ins.is_syscall || ins.is_ret);
}


static uint8_t
check_two_ecalls(struct patch_desc *patch, uint8_t syscall_idx,
			uint8_t start_idx, uint8_t second_ecall_idx)
{
	struct intercept_disasm_result *instrs = patch->surrounding_instrs;
    
    // Check if we can fit TYPE_GP_COMPLETE (implicit max size) before the second ecall.
    // If not, we must stop BEFORE the second ecall.
    
	uint8_t before_2nd_ecall_size = 0;
	for (uint8_t i = start_idx; i < second_ecall_idx; ++i) {
		before_2nd_ecall_size += instrs[i].length;
	}
    
    // If TOTAL space before 2nd ecall is less than required, we can't do a GP patch 
    // that uses all that space. But GP logic determines patch size dynamically.
    // If GP logic sees 24 bytes available, it takes them.
    // If we return 'second_ecall_idx', the patcher thinks it can use instructions up to that point.
    // If 'before_2nd_ecall_size' < 24, but we say "go ahead", GP logic might try to scan backwards 
    // from Ecall1. If Ecall1 is close to Ecall2, "backwards" is away from Ecall2?
    // Wait.
    // Ecall1 is at syscall_idx. Ecall2 is at second_ecall_idx.
    // Ecall2 is AFTER Ecall1 (i > syscall_idx).
    // GP patch writes at Ecall1 and AFTER/BEFORE?
    // GP patch writes at dst_jmp_patch.
    // dst_jmp_patch is determined by scanning BACKWARDS from Ecall1.
    // So dst_jmp_patch <= Ecall1.
    // The patch overwrites from dst_jmp_patch for 'patch_size'.
    // 'patch_size' could extend beyond Ecall1 if we aren't careful?
    // In my 'position_patch': "available = (size_t)(ecall_end - start_addr); patch->patch_size_bytes = (uint8_t)available;"
    // It sets patch range from start_addr (<= Ecall1) to ecall_end (Just after Ecall1).
    // So GP patch (in my logical implementation) NEVER overwrites past Ecall1 + 4.
    // So it never overwrites Ecall2 (which is later).
    
    // So check_two_ecalls returning 'second_ecall_idx' (allowing scanning up to Ecall2) 
    // is fine, because our position_patch only cares largely about space *ending* at Ecall1.
    // BUT!
    // Original check_surrounding logic:
    // It seems to determine the 'window' of available instructions.
    // The 'patch->surrounding_instrs' list is truncated/moved based on this window.
    // If we include Ecall2 in the window, 'patcher' could theoretically see it.
    // But since my GP logic stops at Ecall1_end, Ecall2 is safe.
    // The only risk is if we accidentally overwrite Ecall2 if it is IMMEDIATELY after Ecall1?
    // GP patch overwrites [start_addr, Ecall1_end].
    // Ecall1_end is Ecall1 + 4.
    // Ecall2 is >= Ecall1 + 4.
    // So we assume patches don't exceed 4 bytes after Ecall1 start?
    // YES. My GP logic overwrites up to Ecall1 End.
    
    // So checking check_two_ecalls might be superfluous for my GP, but let's be safe.
    // I'll just return 'second_ecall_idx' to allow full visibility (or loop break),
    // OR return 'syscall_idx + 1' to say "Stop after Ecall1".
    
    return syscall_idx + 1;
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

			if (instrs[i].a7_set > -1)
				patch->syscall_num = instrs[i].a7_set;
			else if (instrs[i].is_a7_modified)
				patch->syscall_num = -1;
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
    if (patch->syscall_num == TYPE_IGNORE) {
        return;
    }
	struct intercept_disasm_result *instrs = patch->surrounding_instrs;
	uint8_t up_to_ecall_size = 0;
	const uint8_t *start_addr;
	uint8_t required_size;

	for (uint8_t i = 0; i <= patch->syscall_idx; ++i)
		up_to_ecall_size += instrs[i].length;

	switch (patch->syscall_num) {
	default: // TYPE_GP or TYPE_JAL
		if (patch->syscall_num == TYPE_GP_COMPLETE) {
			required_size = 16;
			#ifndef __riscv_c
			required_size = 24;
			#endif
			
			// Scan backwards from ECALL
			int found_idx = -1;
			size_t accum_size = 0;
			for (int i = patch->syscall_idx; i >= 0; --i) {
				accum_size += instrs[i].length;
				if (accum_size >= required_size) {
					found_idx = i;
					break;
				}
			}
			
			if (found_idx == -1) {
				found_idx = 0; 
			}
			
			start_addr = instrs[found_idx].address;
            patch->return_register = REG_RA;
		} else if (patch->syscall_num == TYPE_JAL) {
             start_addr = patch->syscall_addr;
             patch->return_register = REG_T0;
        } else {
			patch->syscall_num = TYPE_IGNORE;
            start_addr = patch->syscall_addr;
		}
		break;
	}

	patch->dst_jmp_patch = (uint8_t *)start_addr;
	
	// Legacy alignment check (for C_NOP padding hint)
#ifdef __riscv_c
	check_patch_alignment(patch, start_addr, patch->patch_size_bytes);
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
	cur_asm_relocation_space += instrs_size;
}

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
	uint8_t instrs_buff[MAX_PC_INS_SIZE * 8];
	uint8_t instrs_size = 0;
	uint8_t ret_reg = patch->return_register;

	if (ret_reg != REG_RA) {
        // Load return address from the end of this block using PC-relative addressing
        // Use fixed-size instructions (rv_*) to guarantee offsets
        
        // 1. auipc ret_reg, 0  (ret_reg = PC)
        instrs_size += rv_auipc(instrs_buff + instrs_size, ret_reg, 0);
        
        // 2. ld ret_reg, 20(ret_reg) (Load address from PC+20)
        // Fixed Sizes: auipc(4) + ld(4) + ld(4) + addi(4) + jalr(4) = 20 bytes
        instrs_size += rv_ld(instrs_buff + instrs_size, ret_reg, ret_reg, 20);
        
        // 3. Restore original RA (as we used it for scratch or need to restore it)
		instrs_size += rv_ld(instrs_buff + instrs_size,
					REG_RA, REG_SP, ORIG_RA_OFF);
        
        // 4. Restore Stack Pointer (48 bytes: 16 patch + 32 trampoline)
        instrs_size += rv_addi(instrs_buff + instrs_size, REG_SP, REG_SP, 48);
        
        // 5. Jump to return address
        instrs_size += rv_jalr(instrs_buff + instrs_size, REG_ZERO, ret_reg, 0);
        
        // 6. Data: 64-bit return address
        uint64_t addr = (uintptr_t)patch->return_address;
        memcpy(instrs_buff + instrs_size, &addr, sizeof(addr));
        instrs_size += sizeof(addr);
        
	} else {
        // copy the jump instruction to return to glibc (ra already holds address or logic is implicit)
        // For TYPE_GP, ra holds return address. We must restore stack too!
        // TYPE_GP also uses 48 bytes (16 patch + 32 global trampoline).
        
        instrs_size += rv_addi(instrs_buff + instrs_size, REG_SP, REG_SP, 48);
	    instrs_size += rvpc_jalr(instrs_buff + instrs_size, REG_ZERO, ret_reg, 0);
    }

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
 * create_patch - create the custom assembly wrappers
 * around each syscall to be intercepted.
 */
void
create_patch(struct intercept_desc *desc)
{
	for (uint32_t patch_i = 0; patch_i < desc->count; ++patch_i) {
		struct patch_desc *patch = desc->items + patch_i;
		
		uint8_t length = check_surrounding_instructions(desc, patch);
		
		// GPoline Logic:
        int required_complete = 16;
        #ifndef __riscv_c
        required_complete = 24;
        #endif

		if (length >= required_complete) {
			patch->syscall_num = TYPE_GP_COMPLETE;
			patch->patch_size_bytes = required_complete;
			// Return Address logic:
			// Logical Return is after ECALL.
            uint8_t *ecall_end = (uint8_t*)patch->syscall_addr + ECALL_INS_SIZE;
			patch->return_address = ecall_end;
        } else if (length >= 4) {
             // Check distance
             if (desc->trampoline_address) {
                 int64_t diff = (int64_t)((unsigned char*)desc->trampoline_address - (unsigned char*)patch->syscall_addr);
                 
                 if (diff >= -0x100000 && diff <= 0xFFFFF) {
                      patch->syscall_num = TYPE_JAL;
                      patch->patch_size_bytes = 4;
                      patch->return_address = (uint8_t*)patch->syscall_addr + 4;
                 } else {
                      patch->syscall_num = TYPE_IGNORE;
                 }
             } else {
                  patch->syscall_num = TYPE_IGNORE;
             }
        } else {
			patch->syscall_num = TYPE_IGNORE;
		}

		position_patch(patch);

        if (patch->syscall_num != TYPE_IGNORE) {
            // Mark Jump
            uint8_t *last_instr_addr = patch->dst_jmp_patch + patch->patch_size_bytes;
    #ifdef __riscv_c
            if (patch->end_with_c_nop) last_instr_addr += C_NOP_INS_SIZE;
    #endif
            mark_jump(desc, last_instr_addr);

            if (is_asm_relocation_space_full(MAX_RELOC_PATCH_SIZE(patch->patch_size_bytes)))
                xabort(__func__, "insufficient relocation space");

            relocate_instrs(patch);
        }

		free(patch->surrounding_instrs);
		patch->surrounding_instrs = NULL;
	}
}

static void
copy_GP_COMPLETE(struct patch_desc *patch, uint8_t *trampoline_addr)
{
	uint8_t instrs_buff[32];
	volatile uint8_t instrs_size;
    instrs_size = 0; // Explicit set
	uint8_t *patch_start_addr = patch->dst_jmp_patch;
    
	size_t total_size = patch->patch_size_bytes;
	size_t core_size = 16;
#ifndef __riscv_c
	core_size = 24;
#endif

    if (total_size < core_size) {
        // Skip patching if too small - prevents stack smash
        return;
    }

	// Stack adjustment
	uint8_t sz1 = rvpc_addisp(instrs_buff + instrs_size, -16);
    instrs_size += sz1;
    
    uint8_t sz2 = rvpc_sd(instrs_buff + instrs_size, REG_RA, REG_SP, 0);
	instrs_size += sz2;

	// Jump to Trampoline using AUIPC + JALR (PC-relative call)
    
    if (!trampoline_addr) {
         return; 
    }
    uint8_t *src_addr = patch->dst_jmp_patch + instrs_size;
    
    // Calculate 64-bit offset
    int64_t offset = (int64_t)trampoline_addr - (int64_t)src_addr;
    
    int32_t imm_hi = (offset + 0x800) >> 12;
    int32_t imm_lo = (int32_t)offset - (imm_hi << 12);

    int sz_auipc = rv_auipc(instrs_buff + instrs_size, REG_RA, imm_hi);
    instrs_size += sz_auipc;
    
    int sz_jalr = rv_jalr(instrs_buff + instrs_size, REG_RA, REG_RA, imm_lo);
    instrs_size += sz_jalr;

    // Update return address so detect_cur_patch can find this patch
    patch->return_address = patch->dst_jmp_patch + instrs_size;

	// Restore logic
	instrs_size += rvpc_ld(instrs_buff + instrs_size, REG_RA, REG_SP, 0);
	instrs_size += rvpc_addisp(instrs_buff + instrs_size, 16);

	for(uint8_t i=0; i<instrs_size; ++i) 
		patch_start_addr[i] = instrs_buff[i];
        
    // Pad with NOPs
    for(uint8_t i=instrs_size; i<patch->patch_size_bytes; ++i) {
        patch_start_addr[i] = 0x01; // C.NOP is 0x0001 (addi x0, x0, 0)
        if (i+1 < patch->patch_size_bytes) {
             patch_start_addr[i+1] = 0x00;
             i++;
        }
    }
}

static void
copy_GP_FAILSAFE(struct patch_desc *patch)
{
	uint8_t instrs_buff[32];
	uint8_t instrs_size = 0;
	uint8_t *patch_start_addr = patch->dst_jmp_patch;

	// 1. Allocate Slot and Write Slot Code
	uint32_t slot_offset = allocate_gpoline_slot();
	uint8_t *slot_addr = gpoline_table + slot_offset;
	
	/*
	 * Slot Code:
	 * addi sp, sp, -16
	 * sd ra, 0(sp)
	 * jalr ra, 0(gp)       <-- Jump to trampoline. RA points to next instruction (Slot+8)
	 * ld ra, 0(sp)
	 * addi sp, sp, 16
	 * ld t0, 16(slot_base) <-- Load Logical Return Address
	 * jr t0
	 */
	
	uintptr_t ret_addr = (uintptr_t)patch->return_address;
	// Update patch->return_address to point to Slot+8 (for detection)
	// Assuming compact encoding
#ifdef __riscv_c
	patch->return_address = (uint8_t*)slot_addr + 6;
#else
	// Uncompressed: 4+4+4 = 12.
	patch->return_address = (uint8_t*)slot_addr + 12;
#endif

	uint8_t slot_buff[64];
	uint8_t s_size = 0;
	s_size += rvpc_addisp(slot_buff + s_size, -16); // 2
	s_size += rvpc_sd(slot_buff + s_size, REG_RA, REG_SP, 0); // 2
	
	s_size += rvpc_jalr(slot_buff + s_size, REG_RA, REG_GP, 0); // 2
	
	// Restore logic
	s_size += rvpc_ld(slot_buff + s_size, REG_RA, REG_SP, 0); // 2
	s_size += rvpc_addisp(slot_buff + s_size, 16); // 2
	
	*(uint64_t*)(slot_addr + 24) = (uint64_t)ret_addr;
	
	int32_t ld_offset = (int32_t)slot_offset + 24 - GP_OFFSET;
	s_size += rvpc_ld(slot_buff + s_size, REG_T0, REG_GP, ld_offset);
	
	// jr t0 (c.jr t0)
	s_size += rvpc_jalr(slot_buff + s_size, REG_ZERO, REG_T0, 0);
	
	for(int i=0; i<s_size; ++i) slot_addr[i] = slot_buff[i];


	// 2. Write Patch Site Code: jalr zero, slot_offset(gp)
#ifdef __riscv_c
	if (patch->start_with_c_nop) {
		instrs_size += rvc_nop(instrs_buff + instrs_size);
		patch_start_addr -= RVC_INS_SIZE;
	}
#endif

	int32_t jump_offset = (int32_t)slot_offset - GP_OFFSET;
	instrs_size += rvpc_jalr(instrs_buff + instrs_size, REG_ZERO, REG_GP, jump_offset);

#ifdef __riscv_c
	if (patch->end_with_c_nop)
		instrs_size += rvc_nop(instrs_buff + instrs_size);
#endif

	for(int i=0; i<instrs_size; ++i) 
		patch_start_addr[i] = instrs_buff[i];
}

static void
copy_JAL(struct patch_desc *patch, uint8_t *trampoline_addr)
{
    if (patch->patch_size_bytes < 4) xabort(__func__, "Patch size too small for JAL");

    int instrs_size = 0;
    unsigned char instrs_buff[32]; 

    unsigned char *patch_start_addr = patch->dst_jmp_patch;
    
    int64_t jump_offset = (int64_t)(trampoline_addr - patch_start_addr);
    
    // JAL range is +/- 1MB (20 bits signed: -1048576 to 1048575)
    if (jump_offset > 0xFFFFF || jump_offset < -0x100000) {
          xabort(__func__, "Trampoline too far for JAL patch");
    }

    // Write JAL t0, offset
    instrs_size += rv_jal(instrs_buff + instrs_size, REG_T0, (int32_t)jump_offset);

    // Verify JAL was written (size incremented)
    if (instrs_size == 0) xabort(__func__, "rv_jal failed");

    // Pad with NOPs
    while (instrs_size < patch->patch_size_bytes) {
         if (patch->patch_size_bytes - instrs_size >= 4) {
             // nop (addi x0, x0, 0)
             uint32_t nop = 0x00000013;
             *(uint32_t*)(instrs_buff + instrs_size) = nop;
             instrs_size += 4;
         } else if (patch->patch_size_bytes - instrs_size >= 2) {
             // c.nop
             uint16_t cnop = 0x0001;
             *(uint16_t*)(instrs_buff + instrs_size) = cnop;
             instrs_size += 2;
         } else {
             break; 
         }
    }

    for(int i=0; i<instrs_size; ++i) 
          patch_start_addr[i] = instrs_buff[i];
}

/*
 * activate_patches()
 * Loop over all the patches, and overwrite each syscall.
 */
void
activate_patches(struct intercept_desc *desc)
{

	if (desc->count == 0)
		return;

	// Enable write on code
	// Align start down to page size
	uintptr_t start_aligned = (uintptr_t)desc->text_start & ~(PAGE_SIZE - 1);
	// Align end up (or just ensure size covers everything)
	uintptr_t end_raw = (uintptr_t)desc->text_end;
	size_t size_aligned = end_raw - start_aligned;
	
	mprotect_no_intercept((void *)start_aligned, size_aligned,
		PROT_READ | PROT_WRITE | PROT_EXEC, "activate_patches");

	for (size_t i = 0; i < desc->count; ++i) {
		struct patch_desc *patch = desc->items + i;
        
        long sys = patch->syscall_num;
        if (sys == TYPE_IGNORE) {
            continue;
        }
        
        // Handle positive syscall numbers (actual syscalls)
        if (sys >= 0) {
             if (sys > 500) continue;
             
             // Exclude rt_sigreturn (139)
             if (sys == 139) continue;
        }

		if (patch->dst_jmp_patch < desc->text_start ||
		    patch->dst_jmp_patch > desc->text_end)
			xabort(__func__, "dst_jmp_patch outside text");

		// Assign global trampoline offset to the patch
		patch->trampoline_offset = gpoline_trampoline_offset;

        if (patch->syscall_num == TYPE_GP_COMPLETE) {
			copy_GP_COMPLETE(patch, desc->trampoline_address);
        } else if (patch->syscall_num == TYPE_GP_FAILSAFE) {
            copy_GP_FAILSAFE(patch);
        } else if (patch->syscall_num == TYPE_JAL) {
            copy_JAL(patch, desc->trampoline_address);
        } else {
            // Unexpected type
            xabort("activate_patches", "Unknown patch type");
        }
	}

	// Restore protections and flush cache
	mprotect_no_intercept((void *)start_aligned, size_aligned,
		PROT_READ | PROT_EXEC, "activate_patches done");
	__builtin___clear_cache((char *)desc->text_start, (char *)desc->text_end);
}
