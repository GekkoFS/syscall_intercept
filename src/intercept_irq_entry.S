/*
 * Copyright 2024, Petar Andrić
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
 * intercept_irq_entry.S -- see doc/RV_doc.md
 */

// offsets (constants) common to both patcher.c and this TU
#include "patch_offsets.h"

	/* Constants */
	// relocation space size, increase it if needed
	.equ	RELOCATION_SIZE, 0x20000
	// NOTE: align this to 16, (NR_GPR + NR_FPR) * 8 % 16 == 0
	.equ	NR_GPR, 32
#ifdef __riscv_f
	.equ	NR_FPR, 32
#else
	.equ	NR_FPR, 0
#endif
	.equ	CONTEXT_SIZE, (NR_GPR + NR_FPR) * 8


	/* Macros */
	// load TLS symbol address into \reg
	.macro LASYMT reg, sym
	999999:	auipc	\reg, %tls_ie_pcrel_hi(\sym)
		ld	\reg, %pcrel_lo(999999b)(\reg)	// get the offset from GOT
		add	\reg, \reg, tp			// add the offset to tp
	.endm
	// store a register in the TLS symbol using \tmp_reg to hold the address
	.macro SDSYMT reg, sym, tmp_reg
		LASYMT	\tmp_reg, \sym
		sd	\reg, (\tmp_reg)
	.endm
	// load a register from the TLS symbol
	.macro LDSYMT reg, sym
		LASYMT	\reg, \sym
		ld	\reg, (\reg)
	.endm

	// replace the value from STORE_CONTEXT_PROLOGUE with a new value
	.macro SDSP_G rs, rd_num
		sd	\rs, (\rd_num - 1) * 8(sp)
	.endm

	// helper macro for general purpose registers
	.macro STORE_G reg_num
		sd	x\reg_num, (\reg_num - 1) * 8(sp)
	.endm
	.macro LOAD_G reg_num
		ld	x\reg_num, (\reg_num - 1) * 8(sp)
	.endm

	// FP registers macro, prioritizing `__riscv_d`
#if defined(__riscv_d)
	.macro STORE_F reg_num
		fsd	f\reg_num, (NR_GPR + \reg_num - 1) * 8(sp)
	.endm
	.macro LOAD_F reg_num
		fld	f\reg_num, (NR_GPR + \reg_num - 1) * 8(sp)
	.endm
#elif defined(__riscv_f)
	.macro STORE_F reg_num
		fsw	f\reg_num, (NR_GPR + \reg_num - 1) * 8(sp)
	.endm
	.macro LOAD_F reg_num
		flw	f\reg_num, (NR_GPR + \reg_num - 1) * 8(sp)
	.endm
#endif

	.macro STORE_CONTEXT_PROLOGUE
		addi	sp, sp, -CONTEXT_SIZE

		/*
		 * Store all caller-saved GPRs. s0 and s1 are the only callee-saved GPRs stored
		 * to allow their use inside the wrapper functions without concern.
		 * Technically, any temporary register (t0–t6) could be used instead of s0/s1,
		 * but doing so would prevent many memory-related instructions from being
		 * compressed. Additionally, s0 and s1 conveniently preserve values of interest
		 * when calling C functions.
		 */
		STORE_G	1
		STORE_G	5
		STORE_G	6
		STORE_G	7
		STORE_G	8
		STORE_G	9
		STORE_G	10
		STORE_G	11
		STORE_G	12
		STORE_G	13
		STORE_G	14
		STORE_G	15
		STORE_G	16
		STORE_G	17
		STORE_G	28
		STORE_G	29
		STORE_G	30
		STORE_G	31

		/*
		 * FP registers are not used in this TU, so
		 * store only caller-saved registers.
		 */
#ifdef __riscv_f
		STORE_F	0
		STORE_F	1
		STORE_F	2
		STORE_F	3
		STORE_F	4
		STORE_F	5
		STORE_F	6
		STORE_F	7
		STORE_F	10
		STORE_F	11
		STORE_F	12
		STORE_F	13
		STORE_F	14
		STORE_F	15
		STORE_F	16
		STORE_F	17
		STORE_F	28
		STORE_F	29
		STORE_F	30
		STORE_F	31
#endif
	.endm
	.macro LOAD_CONTEXT_EPILOGUE
		LOAD_G	1
		LOAD_G	5
		LOAD_G	6
		LOAD_G	7
		LOAD_G	8
		LOAD_G	9
		LOAD_G	10
		LOAD_G	11
		LOAD_G	12
		LOAD_G	13
		LOAD_G	14
		LOAD_G	15
		LOAD_G	16
		LOAD_G	17
		LOAD_G	28
		LOAD_G	29
		LOAD_G	30
		LOAD_G	31

#ifdef __riscv_f
		LOAD_F	0
		LOAD_F	1
		LOAD_F	2
		LOAD_F	3
		LOAD_F	4
		LOAD_F	5
		LOAD_F	6
		LOAD_F	7
		LOAD_F	10
		LOAD_F	11
		LOAD_F	12
		LOAD_F	13
		LOAD_F	14
		LOAD_F	15
		LOAD_F	16
		LOAD_F	17
		LOAD_F	28
		LOAD_F	29
		LOAD_F	30
		LOAD_F	31
#endif
		addi	sp, sp, CONTEXT_SIZE
	.endm

	/*
	 * Before executing the relocated instructions, use MV_STACK_TO_TLS to
	 * save the return address and the original ra from a patch.
	 * MV_TLS_TO_STACK just does the opposite after the execution is done.
	 */
	/*
	 * Before executing the relocated instructions, use MV_STACK_TO_TLS to
	 * save the return address and the original ra from a patch.
	 * MV_TLS_TO_STACK just does the opposite after the execution is done.
	 */
	.macro MV_STACK_TO_TLS
		ld	t1, ORIG_RA_OFF(sp)
		SDSYMT	t1, asm_ra_orig, t2
		ld	t1, RET_ADDR_OFF(sp)
		SDSYMT	t1, return_address, t2
		addi	sp, sp, PATCH_SP_OFF
	.endm

	.macro MV_TLS_TO_STACK
		addi	sp, sp, -PATCH_SP_OFF
		LDSYMT	t1, asm_ra_orig
		sd	t1, ORIG_RA_OFF(sp)
		LDSYMT	t1, return_address
		sd	t1, RET_ADDR_OFF(sp)
	.endm

	/*
	 * For threads that do not share global symbols (TLS) like pthread or
	 * thread (child) with a separate stack, these important addresses for
	 * the child process have to be ready immediately after creation.
	 */
	.macro MV_STACK_TO_SHR
		sd	s0, UNUSED_OFF3(sp)
		sd	s1, UNUSED_OFF4(sp)

		ld	s0, ORIG_RA_OFF(sp)
		sd	s0, asm_ra_orig_shr, s1
		ld	s0, RET_ADDR_OFF(sp)
		sd	s0, return_address_shr, s1
		ld	s0, RELOC_ADDR_OFF(sp)
		sd	s0, reloc_instrs_addr_shr, s1

		ld	s0, UNUSED_OFF3(sp)
		ld	s1, UNUSED_OFF4(sp)
		addi	sp, sp, PATCH_SP_OFF
	.endm
	.macro MV_SHR_TO_STACK
		addi	sp, sp, -PATCH_SP_OFF
		sd	s0, UNUSED_OFF3(sp)

		ld	s0, asm_ra_orig_shr
		sd	s0, ORIG_RA_OFF(sp)
		ld	s0, return_address_shr
		sd	s0, RET_ADDR_OFF(sp)
		ld	s0, reloc_instrs_addr_shr
		sd	s0, RELOC_ADDR_OFF(sp)

		ld	s0, UNUSED_OFF3(sp)
	.endm


	/* The function where patches jump to */
	.global	asm_entry_point
	.hidden	asm_entry_point
	.type	asm_entry_point, @function

	/* The function that executes the preceding/following patched instructions */
	.local	exec_relocated_instructions
	.type	exec_relocated_instructions, @function

	/* Spinlock functions */
	.local	spinlock_aq
	.type	spinlock_aq, @function
	.local	spinlock_rl
	.type	spinlock_rl, @function

	/* Wrapper functions that safely execute C functions */
	.local	detect_cur_patch_wrapper
	.type	detect_cur_patch_wrapper, @function
	.local	intercept_routine_wrapper
	.type	intercept_routine_wrapper, @function

	/* The C function in intercept.c */
	.global	detect_cur_patch
	.hidden	detect_cur_patch
	.type	detect_cur_patch, @function

	/* The C function in intercept.c */
	.global	intercept_routine
	.hidden	intercept_routine
	.type	intercept_routine, @function

	/* The C function in intercept.c */
	.global	intercept_post_clone_log_syscall
	.hidden	intercept_post_clone_log_syscall
	.type	intercept_post_clone_log_syscall, @function

	/* The C function called right after cloning a thread */
	.global	intercept_routine_post_clone
	.hidden	intercept_routine_post_clone
	.type	intercept_routine_post_clone, @function

	/* Patched instruction space */
	.global	asm_relocation_space
	.hidden	asm_relocation_space


	/* The function where JAL patches jump to */
	.global	asm_entry_point_jal
	.hidden	asm_entry_point_jal
	.type	asm_entry_point_jal, @function

	.section .text.irqentry, "ax"
asm_entry_point_jal:
	.cfi_startproc
	/*
	 * JAL patches jump here. The return address to the syscall wrapper (PC+4)
	 * is in ra (or t0, depending on patch).
	 * GP logic expects ra to be stored in UNUSED_OFF1.
     * Logic:
     * 1. Save ra (original return to caller) to ORIG_RA_OFF?
     *    Wait, JAL does not clobber ra unless we used jalr ra.
     *    Our JAL patch uses `jal t0` (if we want to save RA?).
     *    No, `rv_jal` uses a register. `rvp_jump_abs` uses `jalr`.
     *    Our JAL patch (TYPE_JAL) uses `jal`?
     *    `create_patch` (Step 18097):
     *    If JAL: `rvp_jump_GW`? No.
     *    In `patcher.c` we did NOT see the JAL generation logic?
     *    Ah, I viewed `create_patch` logic.
     *    `relocate_instrs` calls `position_patch` then `mark_jump` then `relocate_instrs`.
     *    `relocate_instrs` calculates `instrs_size`.
     *    We need to check HOW JAL is generated.
     *    If it uses `jal zero, trampoline`, then RA is preserved.
     *    So RA = Wrapper Caller.
     *    So `ORIG_RA_OFF` should hold valid RA.
     *    Trampoline (Step 17976 of old trace):
     *    `asm_entry_point_jal` was:
     *    `addi sp, -48`. `sd ra, ORIG_RA_OFF`. `sd t0, RET_ADDR_OFF`. `mv ra, t0`.
     *    This assumes `t0` holds "Return Address inside Wrapper".
     *    Does `jal` set `t0`?
     *    If `jal t0, trampoline`. Yes.
     *    We need to verify if JAL patch uses `jal t0`.
     *    In `patcher.c` set `patch->return_register = REG_T0`.
     *    This implies `jal t0`.
     *    So `t0` holds Wrapper Return Address.
     */
	addi	sp, sp, -PATCH_SP_OFF
	sd	ra, ORIG_RA_OFF(sp)
    sd  t0, RET_ADDR_OFF(sp)
	mv	ra, t0
	j	asm_entry_point
	.cfi_endproc
	.size	asm_entry_point_jal, . - asm_entry_point_jal

asm_entry_point:
	.cfi_startproc
	/*********************************************************************
	 * This is the entry point for direct jumps when the trampoline is   *
	 * not used (INTERCEPT_NO_TRAMPOLINE=1). ra (the return address of   *
	 * a GW) must be stored on the stack before detect_cur_patch_wrapper *
	 * overwrites it. If the trampoline had been used, it would have     *
	 * already stored ra on the stack at offset UNUSED_OFF1.             *
	 *********************************************************************/
	sd	ra, UNUSED_OFF1(sp)
	/* This is the entry point for a trampoline jump (library default) */

	// gather patch information and mostly restore the original context
	call	detect_cur_patch_wrapper

	/*********************************************************************
	 * Excluding ra and sp, the original context from glibc is restored  *
	 * by detect_cur_patch_wrapper:                                      *
	 * - ra will be (ab)used more for jumping back and forth between     *
	 *   here and the patched instructions, and to call the C functions. *
	 * - the stack (sp) holds important adresses: the overwritten ra     *
	 *   from glibc, the address to jump back to glibc, and the address  *
	 *   of the relocated instructions (the one that precedes ecall).    *
	 *********************************************************************/

	// execute the instructions that precede the ecall in glibc
	call	exec_relocated_instructions

	// ecall is executed here or not, depending on the hooks created by the user
	call	intercept_routine_wrapper

	// execute the instructions that follow the ecall in glibc
	call	exec_relocated_instructions

	/*********************************************************************
	 * Finished! The final part of the relocation space prepares the     *
	 * patch to return to glibc. The patcher.c prepared relocation       *
	 * instructions at runtime; for this final part, see                 *
	 * finalize_and_jump_back(). Bye-bye, patch! Good luck out there!    *
	 *********************************************************************/
	ld	ra, RELOC_ADDR_OFF(sp)
	ret
	.cfi_endproc
	.size	asm_entry_point, . - asm_entry_point


exec_relocated_instructions:
	.cfi_startproc
    // Save t3 (scratch) and metadata on our stack
    sd  t3, UNUSED_OFF3(sp)
    sd	ra, UNUSED_OFF1(sp)
    sd	a0, UNUSED_OFF2(sp)

    // 1. Save t1, t2, and current sp to TLS (using t3 as scratch)
    SDSYMT  t1, asm_t1_orig, t3
    SDSYMT  t2, asm_t2_orig, t3
    SDSYMT  sp, asm_sp_save, t3
    
	/*
	 * TLS is used here to save data while executing patched instructions;
	 * lock it to avoid race conditions or data corruption.
	 */
	LASYMT	a0, lock_TLS
	call	spinlock_aq

	// now ra can be stored in reloc_ra_temp before the stack gets deallocated
	ld	ra, UNUSED_OFF1(sp)
	SDSYMT	ra, reloc_ra_temp, t3

	// used as an argument with the spinlock, restore to the original value
	ld	a0, UNUSED_OFF2(sp)

	MV_STACK_TO_TLS
    
    // 2. Restore t1, t2 for the relocated code (sp is now sp_orig)
    LDSYMT  t1, asm_t1_orig
    LDSYMT  t2, asm_t2_orig

	ld	ra, RELOC_ADDR_OFF(sp)
	jalr	ra

	/*
	 * After executing the relocated instructions, ra holds the address of
	 * the next block of relocated instructions. That address will be stored
	 * on the stack at offset RELOC_ADDR_OFF.
	 */
    
    // 3. Recover our sp_new from TLS
    SDSYMT  ra, asm_ra_temp, t1 // t1 is now scratch
    LDSYMT  sp, asm_sp_save
    LDSYMT  ra, asm_ra_temp
    
    // Now sp is sp_new again.
	sd	ra, RELOC_ADDR_OFF(sp)

	MV_TLS_TO_STACK

	// Restore ra, a0 for spinlock release
	ld	ra, UNUSED_OFF1(sp)
	SDSYMT	ra, reloc_ra_temp, t3
	ld	a0, UNUSED_OFF2(sp)

	LASYMT	a3, lock_TLS  // Use a3 as scratch for lock address
    mv      a2, a0        // Save a0 to a2 (using a2 as temp)
    mv      a0, a3
	call	spinlock_rl
    mv      a0, a2        // Restore a0
    ld      ra, UNUSED_OFF1(sp)

    // 4. Final restore of t1, t2, t3 for the caller
    LDSYMT  t1, asm_t1_orig
    LDSYMT  t2, asm_t2_orig
    ld      t3, UNUSED_OFF3(sp)
	ret

	.cfi_endproc
	.size	exec_relocated_instructions, . - exec_relocated_instructions


/*
 * Function: spinlock_aq(int *a0)
 * The parameter a0 holds the address of the lock to be utilized.
 * Typically, amoswap is used for spinlocks; however, amomax is used instead to
 * reduce pressure on the memory bus. While amoswap always performs a load/store
 * cycle, amomax will only perform a store if necessary (when the lock is open,
 * i.e., 0). At least, in theory (e.g., microarchitecture implements silent stores)...
 */
spinlock_aq:
	.cfi_startproc
	addi	sp, sp, -16
	sd	s0, 0(sp)
	sd	s1, 8(sp)

	li	s1, 1
.Lwait:
#ifdef __riscv_a
	/*
	 * AMO instructions have the .aq bit set, which simplifies synchronization
	 * in out-of-order execution. The .aq bit functions similarly to
	 * `fence 0, rw`; the '0' signifies that prior i/o/r/w operations are not
	 * affected, making it more optimized than software-based spinlocks (below).
	 */
	amomax.w.aq	s1, s1, (a0)
	bnez		s1, .Lwait
#else
	lw	s0, (a0)
	/*
	 * In this non-atomic spinlock, prior loads (specifically the lw above)
	 * must be executed before the bnez and sw instructions below. `fence r, rw`
	 * should make every thread to observe the most recent value stored in the
	 * lock. This software-based spinlock is not reliable under high contention.
	 */
	fence	r, rw
	bnez	s0, .Lwait
	sw	s1, (a0)
#endif

	ld	s0, 0(sp)
	ld	s1, 8(sp)
	addi	sp, sp, 16
	ret
	.cfi_endproc
	.size	spinlock_aq, . - spinlock_aq


/*
 * Function: spinlock_rl(int *a0)
 * The parameter a0 holds the address of the lock to be utilized.
 */
spinlock_rl:
	.cfi_startproc
#ifdef __riscv_a
	amoswap.w.rl	zero, zero, (a0)
#else
	/*
	 * Prior stores and loads must be completed before the subsequent store
	 * (sw below). fence.tso ensures that all prior loads are ordered
	 * before any memory operation that follows, while all prior stores are
	 * ordered only before successor stores (not loads). It functions
	 * similarly to: fence r, rw + fence w, w.
	 */
	fence.tso
	sw	zero, (a0)
#endif
	ret
	.cfi_endproc
	.size	spinlock_rl, . - spinlock_rl


detect_cur_patch_wrapper:
	.cfi_startproc
	STORE_CONTEXT_PROLOGUE
	// use frame buffer to simplify offsetting
	addi	s0, sp, CONTEXT_SIZE
	// place a7 in a callee-saved register to preserve it after the call, important to TYPE_SML
	mv	s1, a7

	/* The table shows where important values are stored by patch types
	 *********************************************************************
	 *      *    return address    * original ra *   a7 (ecall) value    *
	 *********************************************************************
	 * GW   *   UNUSED_OFF1(sp)    *    0(sp)    *    a7 (unchanged)     *
	 * MID  *   ORIG_RA_OFF(sp)    *    8(sp)    *    a7 (unchanged)     *
	 * SML  *         a7           *    0(sp)    *  patch->syscall_num   *
	 *********************************************************************/

	// a0 will hold TYPE_MID ret addr
	ld	a0, ORIG_RA_OFF(s0)
	// a1 will hold TYPE_SML ret addr
	mv	a1, a7
	// a2 will hold TYPE_GW ret addr
	ld	a2, UNUSED_OFF1(s0)
    // a3 will hold TYPE_JAL ret addr (stored at RET_ADDR_OFF by asm_entry_point_jal)
    ld  a3, RET_ADDR_OFF(s0)

	call	detect_cur_patch
	/*
	 * Returns:
	 * a0 = patch type/syscall_num
	 * a1 = addr of relocated instrs
	 */

	// store results (a0 is only relevant to TYPE_SML):
	sd	a1, RELOC_ADDR_OFF(s0)

    // Dispatch based on identified patch type (a0)
    li  t0, -6 // TYPE_JAL
    beq a0, t0, .Ldone_final
    
    // Generic (GP) patch: Return address is what was in ra upon entry (saved in UNUSED_OFF1)
    ld  a0, UNUSED_OFF1(s0)
    sd  a0, RET_ADDR_OFF(s0)

.Ldone_final:
	LOAD_CONTEXT_EPILOGUE
	ret
	.cfi_endproc
	.size	detect_cur_patch_wrapper, . - detect_cur_patch_wrapper


	// check intercept.c for this macro description
	.equ	UNH_SYSCALL, -0x1000
intercept_routine_wrapper:
	.cfi_startproc
	STORE_CONTEXT_PROLOGUE
	addi	s0, sp, CONTEXT_SIZE

	// pass return address to intercept_routine to detect patch_desc
	ld	a6, RET_ADDR_OFF(s0)

	call	intercept_routine
	/*
	 * Returns one of these two options:
	 * 1. when ecall was executed, a0/a1 hold the results of ecall
	 * 2. unhandled syscalls, a0 = -0x1000; a1 = unhandled type num
	 */

	li	t0, UNH_SYSCALL
	bne	a0, t0, .Lhandled

	addi	t0, t0, -1
	beq	a1, t0, .Lunh_generic
	addi	t0, t0, -1
	beq	a1, t0, .Lunh_clone
	/*
	 * Execution falls through to .Lhandled because unmatched values in a0/a1 imply that the
	 * kernel executed a syscall. See intercept.c for descriptions of the UNH_* macros.
	 * intercept_routine() indicates that syscall execution was skipped by setting a0 to
	 * UNH_SYSCALL and a1 to either UNH_GENERIC or UNH_CLONE. Any other values indicate
	 * that a syscall was executed by the kernel.
	 * NOTE: No instructions should be placed between the branches above and the
	 *       .Lhandled symbol, as this gap is treated as a fallthrough. Or, uncomment
	 *       the j instruction below before adding any new instructions.
	 */
	//j	.Lhandled

.Lhandled:
	// store results of ecall by replacing old a0/a1 on the stack
	SDSP_G	a0, 10
	SDSP_G	a1, 11
	LOAD_CONTEXT_EPILOGUE
	ret

.Lunh_generic:	// SYS_rt_sigreturn
	LOAD_CONTEXT_EPILOGUE
	ecall
	ret

.Lunh_clone:	// clones with separate stack space and vfork()
	// restore original context before cloning
	LOAD_CONTEXT_EPILOGUE

	/*
	 * Execute spinlock_aq before MV_STACK_TO_SHR because multiple threads can
	 * create new threads, which may lead to contention in the SHR .bss. Being
	 * outside of LOAD_CONTEXT_EPILOGUE and STORE_CONTEXT_PROLOGUE forces the
	 * use of extra space available on the stack to store and load ra and a0.
	 */
	sd	ra, UNUSED_OFF1(sp)
	sd	a0, UNUSED_OFF2(sp)
	la	a0, lock_SHR
	call	spinlock_aq
	ld	ra, UNUSED_OFF1(sp)
	ld	a0, UNUSED_OFF2(sp)
	// move stack data to SHR .bss for a very independent child (CLONE_SETTLS)
	MV_STACK_TO_SHR

	ecall

	// move data back from SHR to the stack
	MV_SHR_TO_STACK
	// release lock
	sd	ra, UNUSED_OFF1(sp)
	sd	a0, UNUSED_OFF2(sp)
	la	a0, lock_SHR
	call	spinlock_rl
	ld	ra, UNUSED_OFF1(sp)
	ld	a0, UNUSED_OFF2(sp)

	// save again context for each thread before going into C again
	STORE_CONTEXT_PROLOGUE
	// save a0 for intercept_routine_post_clone
	mv	s0, a0

	call	intercept_post_clone_log_syscall

	mv	a0, s0
	call	intercept_routine_post_clone

	// restore context after C functions
	LOAD_CONTEXT_EPILOGUE
	ret
	.cfi_endproc
	.size	intercept_routine_wrapper, . - intercept_routine_wrapper


asm_relocation_space:
	.space	RELOCATION_SIZE, 0
	.size	asm_relocation_space, . - asm_relocation_space


	.section .data
	.align	3
	.global	asm_relocation_space_size
	.hidden	asm_relocation_space_size
asm_relocation_space_size:
	.8byte	RELOCATION_SIZE
	/*
	 * Natural alignment (alignment follows the symbol size) is crucial for
	 * atomic instructions. Misalignment causes the address-misaligned or
	 * access-fault exception. Also, misaligned LR/SC sequences also raise
	 * the possibility of accessing multiple reservation sets at once.
	 */
	.align	2
	.local	lock_SHR
lock_SHR:
	.4byte	0


	/* .bss is the shared space for multithreading in case of CLONE_SETTLS */
	.align	3
	.section .bss
	.local	asm_ra_orig_shr
	.local	return_address_shr
	.local	reloc_instrs_addr_shr
asm_ra_orig_shr:
	.zero	8
return_address_shr:
	.zero	8
reloc_instrs_addr_shr:
	.zero	8


	.section .tdata
	.align	2
	.local	lock_TLS
lock_TLS:
	.4byte	0


	/* .tbss is used for multithreading */
	.align	3
	.section .tbss
	.global	asm_ra_orig
	.hidden	asm_ra_orig
	.global	asm_ra_temp
	.hidden	asm_ra_temp
	.local	return_address
	.local	reloc_ra_temp
asm_ra_orig:
	.zero	8
asm_t1_orig:
	.zero	8
asm_t2_orig:
	.zero	8
asm_sp_save:
	.zero	8
	.global	asm_t1_orig
	.hidden	asm_t1_orig
	.global	asm_t2_orig
	.hidden	asm_t2_orig
	.global	asm_sp_save
	.hidden	asm_sp_save
asm_ra_temp:
	.zero	8
return_address:
	.zero	8
reloc_ra_temp:
	.zero	8
