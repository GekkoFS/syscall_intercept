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
 * intercept_wrapper.s -- see asm_wrapper.md
 */
// Helpers
#define r12 12
#define r1 1
#define r0 0
#define r3 3
#define f0 0
#define r4 4
#define r2 2
#define r5 5
#define r10 10
#define r16 16
#define r31 31
#define r30 30
#define r15 15

// Helpers

#define NR_GPR		32
#define NR_SPR		4

#define SAVE_AREA	((NR_GPR + NR_SPR) * 8)
// 288 bytes for the stack frame
#define CALLER_FRAME	384
// 376 - 288 = 88 bytes 
// 384 - 288 = 96 bytes
// 512 - 288 = 320 bytes

#define STACK_FRAME	SAVE_AREA

#define CCR_SAVE	(CALLER_FRAME)
#define LR_SAVE		(CCR_SAVE + 8)
#define CTR_SAVE	(LR_SAVE  + 8)
#define XER_SAVE	(CTR_SAVE + 8)
#define GPR_SAVE(n)	(XER_SAVE + 8 + (8 * n))


#define SAVE_GPR(n)	std n,GPR_SAVE(n)(r1)
#define REST_GPR(n)	ld  n,GPR_SAVE(n)(r1)

// Load a 64 bit immediate into a register
#define LOAD_REG_IMMEDIATE(reg,expr)	\
	lis     reg,0;	\
	ori     reg,reg,(expr)@higher;	\
	rldicr  reg,reg,32,31;		\
	oris    reg,reg,(expr)@high;	\
	ori     reg,reg,(expr)@l;


/* the function in this file */
.global intercept_wrapper
.hidden intercept_wrapper
.type intercept_wrapper, @function

/* the C function in intercept.c */
.global intercept_routine
.hidden intercept_routine
.type intercept_routine, @function

/* the other C function in intercept.c, called right after cloning a thread */
.global intercept_routine_post_clone
.hidden intercept_routine_post_clone
.type intercept_routine_post_clone, @function

.text


intercept_wrapper:
	.cfi_startproc

	stdu    r1,-STACK_FRAME(r1)
    SAVE_GPR(0)
    mflr    r0
    std     r0,LR_SAVE(r1)
    mfcr    r0
    std     r0,CCR_SAVE(r1)
    mfctr   r0
    std     r0,CTR_SAVE(r1)
    mfxer   r0
    std     r0,XER_SAVE(r1)
    REST_GPR(0)
    SAVE_GPR(1)
    SAVE_GPR(2)
    SAVE_GPR(3)
    SAVE_GPR(4)
    SAVE_GPR(5)
    SAVE_GPR(6)
    SAVE_GPR(7)
    SAVE_GPR(8)
    SAVE_GPR(9)
    SAVE_GPR(10)
    SAVE_GPR(11)
    SAVE_GPR(12)
    SAVE_GPR(13)
    SAVE_GPR(14)
    SAVE_GPR(15)
    SAVE_GPR(16)
    SAVE_GPR(17)
    SAVE_GPR(18)
    SAVE_GPR(19)
    SAVE_GPR(20)
    SAVE_GPR(21)
    SAVE_GPR(22)
    SAVE_GPR(23)
    SAVE_GPR(24)
    SAVE_GPR(25)
    SAVE_GPR(26)
    SAVE_GPR(27)
    SAVE_GPR(28)
    SAVE_GPR(29)
    SAVE_GPR(30)
    SAVE_GPR(31)


    cmpdi r30 ,1
    beq 0f
    addi r3, r1, CALLER_FRAME-8 #368
    bl intercept_routine
    b 1f

0:  addi r3, r1, CALLER_FRAME-8  // Put in R3 the @ of the context
    bl intercept_routine_post_clone
    nop

1:
	/*
     * At this point, the return value of the C
     * function (a struct wrapper_ret instance) is in r3, r4
     *
     * This function doesn't use these values for anything, just
     * forwards them to the higher level wrapper function, generated
     * from the template.
     */


    /*
	 * At this point, the return values of this asm function
	 * are in r3, r4.
	 *
	 * Restore the other registers, and return.
	 */

    ld      r0,XER_SAVE(r1)
    mtxer   r0
    ld      r0,CTR_SAVE(r1)
    mtctr   r0
    ld      r0,CCR_SAVE(r1)
    mtcr    r0
    ld      r0,LR_SAVE(r1)
    mtlr    r0
    REST_GPR(0)
    REST_GPR(1)
    REST_GPR(2)
#            REST_GPR(3) # Result in r3
#       REST_GPR(4) # Result in r4
    REST_GPR(5)
    REST_GPR(6)
    REST_GPR(7)
    REST_GPR(8)
    REST_GPR(9)
    REST_GPR(10)
    REST_GPR(11)
    REST_GPR(12)
    REST_GPR(13)
    REST_GPR(14)
    REST_GPR(15)
    REST_GPR(16)
    REST_GPR(17)
    REST_GPR(18)
    REST_GPR(19)
    REST_GPR(20)
    REST_GPR(21)
    REST_GPR(22)
    REST_GPR(23)
    REST_GPR(24)
    REST_GPR(25)
    REST_GPR(26)
    REST_GPR(27)
    REST_GPR(28)
    REST_GPR(29)
    REST_GPR(30)
    REST_GPR(31)
    addi    r1,r1,STACK_FRAME
    blr
	.cfi_endproc
