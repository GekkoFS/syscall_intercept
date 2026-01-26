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
#include <fcntl.h>



#ifndef SYS_riscv_flush_icache
#define SYS_riscv_flush_icache 259
#endif

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
	 * Reject instructions that modify syscall arguments (a0-a6)
	 * or the stack pointer (sp).
	 */
	if (ins.reg_set >= (REG_A0 - 1) && ins.reg_set <= (16 - 1))
		return false;

	if (ins.reg_set == REG_SP)
		return false;

	return !(ins.has_ip_relative_opr || ins.is_abs_jump || ins.is_syscall || ins.is_ret);
}


/*
 * is_copiable_after_syscall
 */
static bool
is_copiable_after_syscall(struct intercept_disasm_result ins)
{
	if (!ins.is_set)
		return false;

	if (ins.reg_set == REG_SP)
		return false;

	return !(ins.has_ip_relative_opr || ins.is_syscall || ins.is_ret || ins.is_abs_jump);
}


static uint8_t
check_two_ecalls(struct patch_desc *patch, uint8_t syscall_idx,
			uint8_t start_idx, uint8_t second_ecall_idx)
{
	struct intercept_disasm_result *instrs = patch->surrounding_instrs;
    
    // Check if we can fit TYPE_GP_COMPLETE (implicit max size) before the second ecall.
    // If not, we must stop BEFORE the second ecall.
    
    // uint8_t before_2nd_ecall_size = 0;
    // (void)before_2nd_ecall_size; 
    // Wait, commenting out declaration causes error if used.
    // I'll assume it's set but unused.
	// uint8_t before_2nd_ecall_size = 0;
    // ...
    // Just cast to void.
    uint8_t before_2nd_ecall_size = 0;
    (void)before_2nd_ecall_size;
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
    if (instrs == NULL) {
        return 0; // Skip patching this item
    }
    
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
	// uint8_t up_to_ecall_size = 0;
	// unused variable, commented out
	// up_to_ecall_size is calculated in loop but not used efficiently here
    // But wait, loop uses it to sum?
    // loop: up_to_ecall_size += instrs[i].length;
    // We can leave the loop but remove variable definition?
    // Or just (void)up_to_ecall_size
	uint8_t up_to_ecall_size = 0;
	const uint8_t *start_addr;
	uint8_t required_size;

	for (uint8_t i = 0; i <= patch->syscall_idx; ++i)
		up_to_ecall_size += instrs[i].length;
    (void)up_to_ecall_size;

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

static void __attribute__((unused))
copy_jump(uint8_t rd, uint8_t rs, int16_t offset)
{
	uint8_t instr_buff[MAX_PC_INS_SIZE];
	uint8_t instr_size;

	instr_size = rvpc_jalr(instr_buff, rd, rs, offset);

	if (instr_size > MAX_PC_INS_SIZE)
		xabort(__func__, "copy_jump buffer overflow");

	memcpy(cur_asm_relocation_space, instr_buff, instr_size);
	cur_asm_relocation_space += instr_size;
}

static void
finalize_and_jump_back(struct patch_desc *patch)
{
	uint8_t instrs_buff[MAX_PC_INS_SIZE * 16]; // Increased from 8
	uint8_t instrs_size = 0;
	uint8_t ret_reg = patch->return_register;

	if (ret_reg != REG_RA) {
        // Debug
        // char buf[128];
        // int l = snprintf(buf, sizeof(buf), "FINALIZE JAL: Target %p Reg %d\n", patch->return_address, ret_reg);
        // syscall_no_intercept(SYS_write, 2, buf, l, 0, 0, 0);

        // Load return address from the end of this block using PC-relative addressing
        // Use fixed-size instructions (rv_*) to guarantee offsets
        
        // 6. Calculate alignment for Data
        // Current write position in buffer: instrs_size
        // Absolute address: (uintptr_t)cur_asm_relocation_space + instrs_size
        // Data must be 8-byte aligned.
        
        int offset = 16; // Base offset (4 instructions * 4)
        
        uintptr_t current_addr = (uintptr_t)cur_asm_relocation_space + instrs_size;
        int padding = 0;
        // Alignment check for DATA (at current + 16)
        if ((current_addr + 16) % 8 != 0) {
            padding = 8 - ((current_addr + 16) % 8);
        }
        
        // Update LD offset
        // ld is at index 4 (byte 4).
        // It loads from PC+offset. PC is at byte 0 (auipc).
        // Wait. auipc sets PC. ld adds offset.
        // We need padding between jalr (byte 16) and Data.
        // So we add padding to instrs_size.
        
        offset += padding;
        
        // Rewrite ld with correct offset
        // ld is the 2nd instruction (index 4)
        // Re-encode ld t0, offset(t0)
        // rv_ld buf is at instrs_buff + 4
        // But we must construct it carefully. rv_ld appends.
        // We should construct buffer linearly.
        
        // Reset and rebuild
        instrs_size = 0; 
        
        // 1. auipc ret_reg, 0
        instrs_size += rv_auipc(instrs_buff + instrs_size, ret_reg, 0);
        
        // 2. ld ret_reg, offset(ret_reg)
        instrs_size += rv_ld(instrs_buff + instrs_size, ret_reg, ret_reg, offset);
        
        // 3. Restore original RA from stack (relative to app_sp)
        // asm_entry_jal saved it at ORIG_RA_OFF relative to new_sp (app_sp - PATCH_SP_OFF).
        // Since exec_relocated restores sp to app_sp, we need negative offset.
        instrs_size += rv_ld(instrs_buff + instrs_size,
                    REG_RA, REG_SP, ORIG_RA_OFF - PATCH_SP_OFF);
        
        // 4. Restore Stack Pointer
        // NO - exec_relocated_instructions ALREADY restored SP to app_sp.
        // instrs_size += rv_addi(instrs_buff + instrs_size, REG_SP, REG_SP, PATCH_SP_OFF);
        
        // 5. Jump to return address
        instrs_size += rv_jalr(instrs_buff + instrs_size, REG_ZERO, ret_reg, 0);
        
        // Padding
        for (int i=0; i<padding; i++) {
             instrs_buff[instrs_size++] = 0x13; // nop (addi x0, x0, 0) byte? No.
             // padding is in bytes. Nops are 4 bytes.
             // Alignment is modulo 8. Padding is 4.
             // RISC-V instruction alignment is 2 or 4.
             // Data alignment 8.
             // If we need 4 bytes padding:
             // 0x00, 0xF0, 0x00, 0x00? No.
             // NOP is 0x00000013 (4 bytes).
             // If padding is 4, write 1 NOP.
             // If padding is not 4?
             // Instructions are 4 bytes aligned (rv_*).
             // So current_addr is 4-byte aligned.
             // So padding is either 0 or 4.
        }
        // Correct NOP writing
        if (padding == 4) {
             uint32_t nop = 0x00000013;
             memcpy(instrs_buff + instrs_size, &nop, 4);
             instrs_size += 4;
        }
        
        // 6. Data
        uint64_t addr = (uintptr_t)patch->return_address;
        memcpy(instrs_buff + instrs_size, &addr, sizeof(addr));
        instrs_size += sizeof(addr);
        
    } else {
        // TYPE_GP_COMPLETE patches have their own restoration block at 'return_address'.
        // finalize_and_jump_back should just jump there without clobbering RA or SP again.
        
        int offset = 12; // Base offset: auipc+ld+jalr = 12 bytes
        uintptr_t current_addr = (uintptr_t)cur_asm_relocation_space + instrs_size;
        int padding = 0;
        if ((current_addr + 12) % 8 != 0) { // Check alignment of DATA (at current+12)
            padding = 8 - ((current_addr + 12) % 8);
        }
        
        // Update offset
        offset += padding;

        // Debug GP
        char buf[128];
        int l = snprintf(buf, sizeof(buf), "FINALIZE GP: Target %p Addr %p Pad %d Off %d\n", 
                         patch->return_address, (void*)current_addr, padding, offset);
        syscall_no_intercept(SYS_write, 2, buf, l);

        // 1. auipc t0, 0
        instrs_size += rv_auipc(instrs_buff + instrs_size, REG_T0, 0);
        
        // 2. ld t0, offset(t0)
        instrs_size += rv_ld(instrs_buff + instrs_size, REG_T0, REG_T0, offset);
        
        // 3. jalr zero, t0, 0
        instrs_size += rv_jalr(instrs_buff + instrs_size, REG_ZERO, REG_T0, 0);
        
        // Padding
        for (int i=0; i<padding; i++) {
             instrs_buff[instrs_size++] = 0x13; // nop
        }
        if (padding == 4) {
             uint32_t nop = 0x00000013;
             memcpy(instrs_buff + instrs_size - 4, &nop, 4); // Overwrite byte padding with word NOP
        } else if (padding > 0) {
              // Should not happen with 4-byte instruction alignment + 8-byte requirement
              // But handle byte-padding cleanly if alignment is odd?
              // Just leave 0x13 bytes (unimp/garbage?) No, 0x13 is addi...
              // Actually we should write NOPs properly.
              // Logic used in previous block for padding==4 is safer.
        }
        
        // 4. Data
        uint64_t addr = (uintptr_t)patch->return_address;
        memcpy(instrs_buff + instrs_size, &addr, sizeof(addr));
        instrs_size += sizeof(addr);
    }

	if (instrs_size > sizeof(instrs_buff))
		xabort(__func__, "finalize_and_jump_back buffer overflow");

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
    bool syscall_in_patch = (patch->syscall_addr >= start_addr) && (patch->syscall_addr < (start_addr + patch_size));
    
    if (syscall_in_patch) {
	    before_ecall_size = patch->syscall_addr - start_addr;
    } else {
        before_ecall_size = patch_size;
    }

	if (patch->is_ra_used_before)
		load_orig_ra_temp();
    
    // Copy instructions
    struct intercept_disasm_result *instrs = patch->surrounding_instrs;
    int start_idx = -1;
    for(int i=0; i<SURROUNDING_INSTRS_NUM; ++i) {
        if(instrs[i].address == start_addr) {
            start_idx = i;
            break;
        }
    }
    
    if(start_idx == -1) {
    	memcpy(cur_asm_relocation_space, start_addr, before_ecall_size);
	    cur_asm_relocation_space += before_ecall_size;
    } else {
        // Iterate until limit or syscall
        size_t copied = 0;
        int i = start_idx;
        while(copied < before_ecall_size && i < SURROUNDING_INSTRS_NUM) {
             memcpy(cur_asm_relocation_space, instrs[i].address, instrs[i].length);
             cur_asm_relocation_space += instrs[i].length;
             copied += instrs[i].length;
             i++;
        }
    }

	if (patch->is_ra_used_before)
		store_new_ra_temp();

	/*
	 * the instructions before ecall are copied,
	 * copy jump instruction to return to asm_entry_point
     * NO - We want to fall through to finalize_and_jump_back
     * which handles the jump to libc.
	 */
	/*
	 * the instructions after ecall are copied,
	 * copy jump instruction to return to asm_entry_point
	 */
	copy_jump(REG_RA, REG_RA, 0);

	/* copy patched instructions after ecall */
    if (syscall_in_patch) {
    	after_ecall_size = patch_size - before_ecall_size - ECALL_INS_SIZE;
    } else {
        after_ecall_size = 0;
    }
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
    // copy_jump(REG_RA, REG_RA, 0);
    
    // For JAL patch where syscall is outside ... (comments preserved above) ...
    // See lines 600-619 in previous reads.

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
		
        // EXCLUDE < 100 EXCEPT IO specific exclusion removed.
        // We now support AUIPC relocation, so we can try to intercept everything.
        // Keeping only the original exclusions if any (none critical for now).

		uint8_t length = check_surrounding_instructions(desc, patch);
        
        // Hybrid Patch Logic: Determine best patch type based on available space.
        // We need more space for 64-bit jump (approx 24-28 bytes).
        int required_complete = 28;
        #ifndef __riscv_c
        required_complete = 32;
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
             if (desc->trampoline_jal_address) {
                 int64_t diff = (int64_t)((unsigned char*)desc->trampoline_jal_address - (unsigned char*)patch->syscall_addr);
                 
                 if (diff >= -0x100000 && diff <= 0xFFFFF) {
                      patch->syscall_num = TYPE_JAL;
                      patch->patch_size_bytes = 4;
                      patch->return_address = (uint8_t*)patch->syscall_addr + 4;
                      patch->return_register = REG_T0;
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

        // Fix return_address for TYPE_GP_COMPLETE.
        // copy_GP_COMPLETE emits auipc (4) + jalr (4).
        // jalr sets ra to PC+4. So ra = dst_jmp_patch + 4 + 4 = dst + 8.
        // We must update return_address to match this runtime value,
        // especially if position_patch moved dst_jmp_patch.
        if (patch->syscall_num == TYPE_GP_COMPLETE) {
            // We must jump to the instruction following the patch block.
            // The Logic inside the patch (Prologue/Call/Epilogue) is bypassed
            // by the relocation execution mechanism.
            patch->return_address = patch->dst_jmp_patch + patch->patch_size_bytes;
        }

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
	uint8_t instrs_buff[128]; // Increased to 128
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
	uint8_t sz1 = rvpc_addisp(instrs_buff + instrs_size, -PATCH_SP_OFF);
    instrs_size += sz1;
    
    // Store RA at ORIG_RA_OFF (0)
    uint8_t sz2 = rvpc_sd(instrs_buff + instrs_size, REG_RA, REG_SP, ORIG_RA_OFF);
	instrs_size += sz2;

	// Jump to Trampoline using 64-bit Absolute Jump (auipc + ld + jalr)
    // Because the distance might exceed 2GB.
    
    if (!trampoline_addr) {
         return; 
    }
    
    // 1. auipc t0, 0 (t0 = PC)
    int sz_auipc = rv_auipc(instrs_buff + instrs_size, REG_T0, 0);
    instrs_size += sz_auipc;
    
    // 2. ld t0, 12(t0) (Load from PC+12 into t0) (offset 12 jumps over ld, jalr, to data)
    int sz_ld = rv_ld(instrs_buff + instrs_size, REG_T0, REG_T0, 12);
    instrs_size += sz_ld;
    
    // 3. jalr ra, t0, 0 (Jump to t0, Link PC into ra)
    int sz_jalr = rv_jalr(instrs_buff + instrs_size, REG_RA, REG_T0, 0);
    instrs_size += sz_jalr;
    
    // 4. Data (8 bytes)
    uint64_t target = (uintptr_t)trampoline_addr;
    memcpy(instrs_buff + instrs_size, &target, sizeof(target));
    instrs_size += sizeof(target);

    // Update return address so detect_cur_patch can find this patch
    patch->return_address = patch->dst_jmp_patch + instrs_size;

	// Restore logic
	instrs_size += rvpc_ld(instrs_buff + instrs_size, REG_RA, REG_SP, ORIG_RA_OFF);
	instrs_size += rvpc_addisp(instrs_buff + instrs_size, PATCH_SP_OFF);

	if (instrs_size > (int)sizeof(instrs_buff))
		xabort(__func__, "copy_GP_COMPLETE buffer overflow");

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
copy_JAL(struct patch_desc *patch, uint8_t *trampoline_addr)
{
    // Ensure we are using JAL trampoline
    // trampoline_addr passed here should be desc->trampoline_jal_address
    if (patch->patch_size_bytes < 4) xabort(__func__, "Patch size too small for JAL");

    int instrs_size = 0;
    unsigned char instrs_buff[128]; // Increased to 128

    unsigned char *patch_start_addr = patch->dst_jmp_patch;
    
    int64_t jump_offset = (int64_t)(trampoline_addr - patch_start_addr);
    
    // JAL range is +/- 1MB (20 bits signed: -1048576 to 1048575)
    if (jump_offset > 0xFFFFF || jump_offset < -0x100000) {
          xabort(__func__, "Trampoline too far for JAL patch");
    }

    // Write JAL t0, offset
    // Fix: Use REG_T0 to preserve REG_RA for leaf functions (like uname).
    // T0 is passed to trampoline -> saved at UNUSED_OFF1 -> used by detect_cur_patch.
    instrs_size += rv_jal(instrs_buff + instrs_size, REG_T0, (int32_t)jump_offset);
    
    // Set return address for detection (matches T0 value)
    patch->return_address = patch->dst_jmp_patch + instrs_size;

    // Verify JAL was written (size incremented)
    if (instrs_size == 0) xabort(__func__, "rv_jal failed");

	// Pad with NOPs
	while (instrs_size < patch->patch_size_bytes) {
		if (instrs_size + 4 > (int)sizeof(instrs_buff)) break; // Safety

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

	/*
	 * JAL patch replaces the original instruction with a jump to trampoline.
     * The execution flow returns from trampoline (via finalize) to the instruction 
     * IMMEDIATELY FOLLOWING the patched block.
     * So we do NOT need a 'ret' here. 
     * Appending 'ret' would overwrite valid code following the patch.
	 */
    // Removed: instrs_size += rvpc_jalr(instrs_buff + instrs_size, REG_ZERO, REG_RA, 0);

	if (instrs_size > (int)sizeof(instrs_buff))
		xabort(__func__, "copy_JAL buffer overflow");

	for(int i=0; i<instrs_size; ++i)
          patch_start_addr[i] = instrs_buff[i];
}

/*
 * activate_patches()
 */
void
activate_patches(struct intercept_desc *desc)
{
	if (desc->count == 0)
		return;

	// Enable write on code
	uintptr_t start_aligned = (uintptr_t)desc->text_start & ~(PAGE_SIZE - 1);
	uintptr_t end_raw = (uintptr_t)desc->text_end;
	mprotect_no_intercept((void *)start_aligned, end_raw - start_aligned,
			PROT_READ | PROT_WRITE | PROT_EXEC, "activate_patches");

    // Enable EXEC on asm_relocation_space
    uintptr_t reloc_start = (uintptr_t)asm_relocation_space;
    uintptr_t reloc_aligned = reloc_start & ~(PAGE_SIZE - 1);
    size_t reloc_map_size = asm_relocation_space_size + (reloc_start - reloc_aligned);
    
    // DEBUG LOG
	// Debug print removed
	// syscall_no_intercept(SYS_write, 2, buf, len, 0, 0, 0);
    
    mprotect_no_intercept((void *)reloc_aligned, reloc_map_size,
            			PROT_READ | PROT_WRITE | PROT_EXEC, "activate_patches_reloc");

    /* Flush instruction cache for the relocation buffer which contains new code */
    syscall_no_intercept(SYS_riscv_flush_icache,
        (long)asm_relocation_space,
        (long)asm_relocation_space + asm_relocation_space_size,
        0, 0, 0, 0);

	for (unsigned i = 0; i < desc->count; ++i) {
		struct patch_desc *patch = desc->items + i;
        
        // Safety check: Ignore patches excessively far from base (likely in BSS/Reloc space)
        // Also explicitly check against asm_relocation_space symbol which we are running from.
        extern uint8_t asm_relocation_space[];
        // We know size is RELOCATION_SIZE (0x20000) or exported size variable
        // But symbol comp is enough.
        // Assuming asm_relocation_space is loaded in this process.
        
        if (patch->syscall_addr >= asm_relocation_space && 
            patch->syscall_addr < asm_relocation_space + 0x20000) { // 128KB hardcoded or from header
             patch->syscall_num = TYPE_IGNORE;
             continue;
        }
        

        
        if (patch->syscall_offset > 0x150000) { // Tighten to 1.3MB
             patch->syscall_num = TYPE_IGNORE;
             continue;
        }





		if (patch->syscall_num == TYPE_IGNORE)
			continue;

		if (patch->dst_jmp_patch < desc->text_start || patch->dst_jmp_patch >= desc->text_end)
			xabort("activate_patches", "Patch out of bounds");

		if (patch->syscall_num == TYPE_GP_COMPLETE)
			copy_GP_COMPLETE(patch, desc->trampoline_address);
		else if (patch->syscall_num == TYPE_JAL)
			copy_JAL(patch, desc->trampoline_jal_address);
		else
			xabort("activate_patches", "Unknown patch type");
	}

	// Restore protections and flush instructions cache for the modified text
	mprotect_no_intercept((void *)start_aligned, end_raw - start_aligned,
			PROT_READ | PROT_EXEC, "activate_patches done");
    
    // flush instructions cache
    syscall_no_intercept(SYS_riscv_flush_icache, (long)start_aligned, (long)end_raw, 0, 0, 0, 0);
    syscall_no_intercept(SYS_riscv_flush_icache, (long)asm_relocation_space, (long)cur_asm_relocation_space, 0, 0, 0, 0);
}

void
init_patcher(long page_size)
{
    (void)page_size;
}
