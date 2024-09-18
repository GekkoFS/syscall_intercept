/*
 * Copyright 2016-2017, Intel Corporation
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
 * intercept_irq_entry.S -- see asm_wrapper.md
 */

	/* Constants */
	// the final size is determined in runtime, but this is the minimum size
	.equ	RELOCATION_SIZE, 0x80000
	/*
	 * This offset already exists due to patching. To restore the original
	 * sp of a patch, this gets added to sp before executing patch instrs.
	 */
	.equ	GLIBC_SP_OFF, 16
	// sp offset done on the trampoline, add to sp if the trampoline is used
	.equ	TRAMPOLINE_SP_OFF, 16
	// NOTE: align this to 16, (NR_GPR + NR_FPR) * 8 % 16 == 0
	.equ	NR_GPR, 32
	.equ	NR_FPR, 32
	.equ	CONTEXT_SIZE, (NR_GPR + NR_FPR - 1) * 8


	/* Macros */
	// store a register in the TLS symbol using tmp_reg to hold the address
	.macro SDSYMT reg, sym, tmp_reg
	0:	auipc	\tmp_reg, %tls_ie_pcrel_hi(\sym)
		ld	\tmp_reg, %pcrel_lo(0b)(\tmp_reg)
		add	\tmp_reg, \tmp_reg, tp

		sd	\reg, 0(\tmp_reg)
	.endm
	// load a register from the TLS symbol
	.macro LDSYMT reg, sym
	0:	auipc	\reg, %tls_ie_pcrel_hi(\sym)
		ld	\reg, %pcrel_lo(0b)(\reg)
		add	\reg, \reg, tp

		ld	\reg, 0(\reg)
	.endm
	// store safely (without clobbering) a register to the TLS symbol
	.macro SDSYMTS reg, sym
		addi	sp, sp, -16
		sd	t0, 0(sp)

		SDSYMT	\reg, \sym, t0

		ld	t0, 0(sp)
		addi	sp, sp, 16
	.endm

	// replace the value from STORE_CONTEXT if a register should be modified
	.macro SDSP rs, rd_num
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

	.macro STORE_CONTEXT
		addi	sp, sp, -CONTEXT_SIZE

		/*
		 * Store almost all GPRs to be able to use callee/caller saved
		 * registers inside of the wrapper functions without worries.
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
		STORE_G	18
		STORE_G	19
		STORE_G	20
		STORE_G	21
		STORE_G	22
		STORE_G	23
		STORE_G	24
		STORE_G	25
		STORE_G	26
		STORE_G	27
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
	.macro LOAD_CONTEXT
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
		LOAD_G	18
		LOAD_G	19
		LOAD_G	20
		LOAD_G	21
		LOAD_G	22
		LOAD_G	23
		LOAD_G	24
		LOAD_G	25
		LOAD_G	26
		LOAD_G	27
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
	 * While processing one ecall, another ecall can be executed from
	 * the user's callback functions. That's why we need to store these
	 * shared global variables. These clobber registers, use inside
	 * STORE_CONTEXT and LOAD_CONTEXT.
	 */
	.macro STORE_GLOBALS
		addi	sp, sp, -32
		LDSYMT	t0, asm_return_address
		sd	t0, 0(sp)
		LDSYMT	t0, asm_ra_orig
		sd	t0, 8(sp)
		LDSYMT	t0, following_ins_addr
		sd	t0, 16(sp)
	.endm
	.macro LOAD_GLOBALS
		ld	t0, 0(sp)
		SDSYMT	t0, asm_return_address, t1
		ld	t0, 8(sp)
		SDSYMT	t0, asm_ra_orig, t1
		ld	t0, 16(sp)
		SDSYMT	t0, following_ins_addr, t1
		addi	sp, sp, 32
	.endm

	/*
	 * For threads that do not share global symbols (TLS) like pthread,
	 * it is needed to prepare these important variables for the child
	 * process immediately after creation. These also clobber registers,
	 * use inside STORE_CONTEXT and LOAD_CONTEXT.
	 */
	.macro STORE_SHR
		LDSYMT	t0, asm_return_address
		sd	t0, asm_return_address_shr, t1
		LDSYMT	t0, asm_ra_orig
		sd	t0, asm_ra_orig_shr, t1
		LDSYMT	t0, following_ins_addr
		sd	t0, following_ins_addr_shr, t1
	.endm
	.macro LOAD_SHR
		ld	t0, asm_return_address_shr
		SDSYMT	t0, asm_return_address, t1
		ld	t0, asm_ra_orig_shr
		SDSYMT	t0, asm_ra_orig, t1
		ld	t0, following_ins_addr_shr
		SDSYMT	t0, following_ins_addr, t1
	.endm


	/* Patched instructions space */
	.global	asm_relocation_space
	.hidden	asm_relocation_space

	/* The function where patches jump to */
	.global	asm_entry_point
	.hidden	asm_entry_point
	.type	asm_entry_point, @function

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

	/* The C function called right after cloning a thread */
	.global	intercept_routine_post_clone
	.hidden	intercept_routine_post_clone
	.type	intercept_routine_post_clone, @function


	.section .text.relocation, "ax"

	.align	12, 0
asm_relocation_space:
	.space	RELOCATION_SIZE, 0
	.size	asm_relocation_space, . - asm_relocation_space


	.section .text.irqentry, "ax"

	.align	12, 0
asm_entry_point:
	.cfi_startproc
	/* Trampoline jumps here */
	ld	ra, 0(sp)
	addi	sp, sp, TRAMPOLINE_SP_OFF

	/* INTERCEPT_NO_TRAMPOLINE=true, GW jumps here */
	/*
	 * ra is the only reg that is certainly clobbered due to patching, and
	 * it holds the return address of a GW.
	 * a7 is clobbered only when the patch is TYPE_SML.
	 */
	SDSYMTS	ra, asm_ra_temp

	call	detect_cur_patch_wrapper

	addi	sp, sp, GLIBC_SP_OFF
	/*********************************************************************
	 * The original context before patching is restored, exluding ra,    *
	 * which will be (ab)used more for jumping back and forth between    *
	 * here and the patched instructions, and also to call C functions.  *
	 *********************************************************************/
	/*
	 * Execute preceding ecall instructions, jump using ra because it is
	 * unlikely that it will be modified or used there. In case it is,
	 * a block of instructions will be there to aid that (patcher.c).
	 */
	LDSYMT	ra, preceding_ins_addr
	jalr	ra, ra

	// store ra, used for executing the following ecall instructions
	SDSYMTS	ra, following_ins_addr

	call	intercept_routine_wrapper

	/*
	 * All done, except the following instructions. patcher.c prepared
	 * everything necessary to go back to the patch origin.
	 * sp and ra are restored, and asm_return_address gets loaded into the
	 * register which is used for jumping back (patch->return_register).
	 * For dynamic types (GW/MID) sp gets reduced and the original ra (with
	 * potential modifications) gets stored on the expected offset - 0(sp)
	 * for GW, 8(sp) for MID.
	 */
	LDSYMT	ra, following_ins_addr
	jalr	zero, ra
	.cfi_endproc
	.size	asm_entry_point, . - asm_entry_point


detect_cur_patch_wrapper:
	.cfi_startproc
	STORE_CONTEXT
	// use frame buffer to simplify offsetting
	addi	s0, sp, CONTEXT_SIZE
	// place a7 in a callee-saved register to preserve it after the call
	mv	s1, a7

	/* The table shows what the clobbered registers hold for each patch type
	 *********************************************************************
	 *      * return address   *  original ra   *   a7 (ecall) value     *
	 *********************************************************************
	 * GW   *      ra          *     0(sp)      *    a7 (unchanged)      *
	 * MID  *      0(sp)       *     8(sp)      *    a7 (unchanged)      *
	 * SML  *      a7          *     0(sp)      *    patch->syscall_num  *
	 *********************************************************************/

	// a0 will hold TYPE_MID ret addr
	ld	a0, 0(s0)
	// a1 will hold TYPE_SML ret addr
	mv	a1, a7
	// a2 will hold TYPE_GW ret addr
	LDSYMT	a2, asm_ra_temp

	call	detect_cur_patch
	/*
	 * Returns:
	 * a0 = patch type/syscall_num
	 * a1 = relocation addr/preceding_ins_addr
	 */

	// store results (a0 is only relevant to TYPE_SML):
	SDSYMT	a1, preceding_ins_addr, t0
	// restore original a7 in case it was clobbered
	mv	a7, s1

	bge	a0, zero, .Lsml
	li	t0, -1
	beq	a0, t0, .Lmid
	li	t0, -2
	beq	a0, t0, .Lgw

.Lsml:
	SDSYMT	a7, asm_return_address, t0
	ld	t1, 0(s0)
	SDSYMT	t1, asm_ra_orig, t0
	// NOTE: detect_cur_patch returned syscall_num, replace old a7 on the stack
	SDSP	a0, 17
	j	.Ldone

.Lmid:
	ld	t1, 0(s0)
	SDSYMT	t1, asm_return_address, t0
	ld	t1, 8(s0)
	SDSYMT	t1, asm_ra_orig, t0
	j	.Ldone

.Lgw:
	LDSYMT	t1, asm_ra_temp
	SDSYMT	t1, asm_return_address, t0
	ld	t1, 0(s0)
	SDSYMT	t1, asm_ra_orig, t0
	j	.Ldone

.Ldone:
	LOAD_CONTEXT
	ret
	.cfi_endproc
	.size	detect_cur_patch_wrapper, . - detect_cur_patch_wrapper


intercept_routine_wrapper:
	.cfi_startproc
	STORE_CONTEXT

	// pass return address to intercept_routine to detect patch_desc
	LDSYMT	a6, asm_return_address

	STORE_GLOBALS
	call	intercept_routine
	LOAD_GLOBALS
	/*
	 * Returns:
	 * a0 = result
	 * a1 = action number
	 */

	li	t0, 0
	beq	a1, t0, .Lunhandled
	li	t0, 1
	beq	a1, t0, .Lhandled
	li	t0, 2
	beq	a1, t0, .Lclone

	wfi	// unexpected return value (wfi in U-mode: illegal instr, exit)

.Lunhandled:	// SYS_rt_sigreturn
	LOAD_CONTEXT
	ecall
	ret

.Lhandled:
	// result of ecall processed by C hook or syscall_no_intercept()
	SDSP	a0, 10
	LOAD_CONTEXT
	ret

.Lclone:
	// store globals for very independent child (CLONE_SETTLS)
	STORE_SHR
	// now restore original context before cloning
	LOAD_CONTEXT
	ecall

	// save again context for each thread before going into C again
	STORE_CONTEXT
	call	intercept_routine_post_clone

	// put globals that the parent provided (STORE_SHR) in childs memory space
	LOAD_SHR
	// restore context before intercept_routine_post_clone
	LOAD_CONTEXT
	ret
	.cfi_endproc
	.size	intercept_routine_wrapper, . - intercept_routine_wrapper


	.section .data
	.global	asm_relocation_space_size
	.hidden	asm_relocation_space_size
asm_relocation_space_size:
	.8byte	asm_entry_point - asm_relocation_space


	/*
	 *.bss is shared space for multithreading,
	 * only these are relevant after cloning
	 */
	.section .bss
	.local	asm_return_address_shr
	.local	asm_ra_orig_shr
	.local	following_ins_addr_shr
asm_return_address_shr:
	.zero	8
asm_ra_orig_shr:
	.zero	8
following_ins_addr_shr:
	.zero	8


	/* .tbss is used for multithreading */
	.section .tbss
	.global	asm_return_address
	.hidden	asm_return_address
	.global	asm_ra_orig
	.hidden	asm_ra_orig
	.global	asm_ra_temp
	.hidden	asm_ra_temp
	.local	preceding_ins_addr
	.local	following_ins_addr
asm_return_address:
	.zero	8
asm_ra_orig:
	.zero	8
asm_ra_temp:
	.zero	8
preceding_ins_addr:
	.zero	8
following_ins_addr:
	.zero	8
