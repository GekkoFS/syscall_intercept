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
 * intercept_template.s -- see asm_wrapper.md
 */

/*
    Things to take into account with POWER9
    - We have TOC in r2, we have to load it dynamically
    - Some syscalls (mmap) changes r10,r11,r12
    - Results are placed on r3
    - If the syscall is not successful CR0.SL is 1
*/

.global intercept_asm_wrapper_tmpl;
.hidden intercept_asm_wrapper_tmpl;
.global intercept_asm_wrapper_patch_desc_addr;
.hidden intercept_asm_wrapper_patch_desc_addr;
.global intercept_asm_wrapper_wrapper_level1_addr;
.hidden intercept_asm_wrapper_wrapper_level1_addr;
.global intercept_asm_wrapper_tmpl_end;
.hidden intercept_asm_wrapper_tmpl_end;
.global intercept_asm_wrapper_r2_load_addr;
.hidden intercept_asm_wrapper_r2_load_addr;

/* Define some helpers for registers */
#define r0 0
#define r1 1
#define r2 2
#define r3 3
#define r4 4
#define r5 5
#define r6 6
#define r9 9
#define r10 10
#define r11 11
#define r12 12
#define r14 14
#define r15 15
#define r30 30
#define r31 31

#define r19 19
.text

/*
 * Locals on the stack:
 * 0(%rsp) the original value of %rsp, in the code around the syscall
 * 8(%rsp) the pointer to the struct patch_desc instance
 *
 * The %r12 register controls which C function to call in intercept.c:
 *
 * if %r12 == 0 then call intercept_routine
 * if %r12 == 1 then intercept_routine_post_clone
 *
 * This value in %r12 is passed to the function intercep_wrapper.
 *
 *
 * Note: the subq instruction allocating stack for locals must not
 * ruin the stack alignment. It must round up the number of bytes
 * needed for locals.
 */

/* Some helpers to save registers */

.macro intercept_asm_wrapper_save_regs
stdu r1, -88(r1)	# Stack space for registers // 80 has issues with clone r31
std r0,40(r1)
mflr r0
std r0, 8(r1)
mfctr r0			# CR is not stored as needs to be recovered
std r0, 16(r1)
std r2, 24(r1)
std r3, 32(r1)		# This is not needed
std r4, 48(r1)
std r30, 56(r1)
std r31, 64(r1)
std r19, 72(r1)
//subi  r0,r1, 0
//addi r12,r0,80
//stvx 0,r12,r0

ld r0,40(r1)		# Reload r0, syscall number
stdu r1, -392(r1)   # Add extra space for next steps
.endm

.macro intercept_asm_wrapper_restore_regs
# We need a addi r1,r1, 392 we will do externally
ld r19, 72(r1)
ld r31, 64(r1)
ld r30, 56(r1)
ld r4, 48(r1)
#    ld r3, 32(r1)  // Results do not restore
ld r2, 24(r1)

//subi  r0,r1, 0
//addi r12,r0,80
//lvx 0,r12,r0

ld r0, 16(r1)
mtctr r0
ld r0, 8(r1)
mtlr r0
ld r0, 40(r1)
addi r1,r1, 88  // 80 has issues with r31 in clone
.endm

/* Helper to load a 64 bit immediate into a register */
#define LOAD_REG_IMMEDIATE(reg,expr)		\
 	li     reg,(expr)@higher;		\
 	rldicr  reg,reg,32,31;		\
	oris    reg,reg,(expr)@high;	\
 	ori     reg,reg,(expr)@l;

intercept_asm_wrapper_tmpl:
	intercept_asm_wrapper_save_regs
	li r30, 0 # Intercept routine in r30
intercept_asm_wrapper_r2_load_addr:
# We need to save dnamically the r2 (TOC) to allow global variable
	LOAD_REG_IMMEDIATE(r2, 0)
k: # We don't need to reload the R2 (clones)
intercept_asm_wrapper_patch_desc_addr:
	LOAD_REG_IMMEDIATE(r4,0)
	std r4, 80(r1)	 # We store the address in the stack
intercept_asm_wrapper_wrapper_level1_addr:
    LOAD_REG_IMMEDIATE(r4,0)
    mtlr r4
    ld r4, 48+392(r1)
    blrl
	/*
	 *
	 * If r4 is zero, r3 contains a syscall number, and that syscall
	 *  is executed here.
	 * If r4 is 1, r3 contains the return value of the hooked syscall.
	 * If r4 is 2, a clone syscall is executed here.
	 */
	cmpdi r4,0
    beq 2f
    cmpdi r4,1
    beq 3f
    cmpdi r4,2
    beq 1f
1:
	/* execute the clone syscall in its original context */
	ld r0, 88(r1)
	mtcr r0     // We restore the syscall CR (error code)
	addi r1, r1, 392
	ld r3, 32(r1) // We need to reload r3, syscall number
	intercept_asm_wrapper_restore_regs
	sc
	intercept_asm_wrapper_save_regs // Save regs
    li r30, 1
	b intercept_asm_wrapper_r2_load_addr // Reload the TOC for child
2:
	ld r0, 88(r1)
	mtcr r0
	addi r1, r1, 392
	ld r3, 32(r1)
	intercept_asm_wrapper_restore_regs
	sc
	b e
3:
    ld r0, 88(r1)
    mtcr r0
    addi r1, r1,  392
    intercept_asm_wrapper_restore_regs
e:
    LOAD_REG_IMMEDIATE(r4,0) // We need to jump to the syscall again
    mtctr r4
    ld r4, 32(r1)
    bctr
intercept_asm_wrapper_tmpl_end:
	/*
	 * This template must be appended here with a
	 * jump back to the intercepted code.
	 */
