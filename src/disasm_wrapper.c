/*
 * Copyright 2016-2020, Intel Corporation
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
 * disasm_wrapper.c -- connecting the interceptor code
 * to the disassembler code from the capstone project.
 *
 * See:
 * http://www.capstone-engine.org/lang_c.html
 */

#include "intercept.h"
#include "intercept_util.h"
#include "disasm_wrapper.h"

#include <assert.h>
#include <string.h>
#include <syscall.h>
#include "capstone_wrapper.h"

struct intercept_disasm_context {
	csh handle;
	cs_insn *insn;
	const unsigned char *begin;
	const unsigned char *end;
};

/*
 * nop_vsnprintf - A dummy function, serving as a callback called by
 * the capstone implementation. The syscall_intercept library never makes

 * any use of string representation of instructions, but there seems to no
 * trivial way to use disassemble using capstone without it spending time
 * on printing syscalls. This seems to be the most that can be done in
 * this regard i.e. providing capstone with nop implementation of vsnprintf.
 */
static int
nop_vsnprintf()
{
	return 0;
}

/*
 * intercept_disasm_init -- should be called before disassembling a region of
 * code. The context created contains the context capstone needs ( or generally
 * the underlying disassembling library, if something other than capstone might
 * be used ).
 *
 * One must pass this context pointer to intercept_disasm_destroy following
 * a disassembling loop.
 */
struct intercept_disasm_context *
intercept_disasm_init(const unsigned char *begin, const unsigned char *end)
{
	struct intercept_disasm_context *context;

	context = xmmap_anon(sizeof(*context));
	context->begin = begin;
	context->end = end;

#ifdef __riscv_c
	cs_mode disasm_rv = CS_MODE_RISCV64 | CS_MODE_RISCVC;
#else
	cs_mode disasm_rv = CS_MODE_RISCV64;
#endif

	/*
	 * Initialize the disassembler.
	 * The handle here must be passed to capstone each time it is used.
	 */
	if (cs_open(CS_ARCH_RISCV, disasm_rv, &context->handle) != CS_ERR_OK)
		xabort("cs_open");

	/*
	 * Kindly ask capstone to return some details about the instruction.
	 * Without this, it only prints the instruction, and we would need
	 * to parse the resulting string.
	 */
	if (cs_option(context->handle, CS_OPT_DETAIL, CS_OPT_ON) != 0)
		xabort("cs_option - CS_OPT_DETAIL");

	/*
	 * Overriding the printing routine used by capstone,
	 * see comments above about nop_vsnprintf.
	 */
	cs_opt_mem x = {
		.malloc = malloc,
		.free = free,
		.calloc = calloc,
		.realloc = realloc,
		.vsnprintf = nop_vsnprintf};
	if (cs_option(context->handle, CS_OPT_MEM, (size_t)&x) != 0)
		xabort("cs_option - CS_OPT_MEM");

	if ((context->insn = cs_malloc(context->handle)) == NULL)
		xabort("cs_malloc");

	return context;
}

/*
 * intercept_disasm_destroy -- see comments for above routine
 */
void
intercept_disasm_destroy(struct intercept_disasm_context *context)
{
	cs_free(context->insn, 1);
	cs_close(&context->handle);
	xmunmap(context, sizeof(*context));
}

/*
 * Finds the value of a7 that is used for the TYPE_SML patch which relies on
 * the static analysis of the disassemble. check_surrounding_instructions() in
 * patcher.c uses this to find out which a7 value was set last before
 * ecall. Because of the static nature of the TYPE_SML patch, TYPE_GW and
 * TYPE_MID (both dynamically store the a7 value) are prioritized when choosing
 * the patch type.
 */
static inline void
get_a7(struct intercept_disasm_result *result, struct cs_insn *insn)
{
	if (insn->detail->riscv.operands[0].reg != RISCV_REG_A7)
		return;

	switch (insn->id) {
#ifdef __riscv_c
	case RISCV_INS_C_LI:
		result->a7_set = insn->detail->riscv.operands[1].imm;
		return;
#endif
	case RISCV_INS_ADDI:
		if (insn->detail->riscv.operands[1].reg == RISCV_REG_ZERO) {
			result->a7_set = insn->detail->riscv.operands[2].imm;
			return;
		}
		/* fallthrough */
	default:
		if (insn->detail->riscv.operands[0].access > 0x1)
			result->is_a7_modified = true;
		return;
	}
}

/*
 * In asm_entry_point (intercept_irq_entry.S), ra is being used for jumping
 * back and forth between executing preceding and following instrs, so it
 * gets overwritten. That is why it's important to check if any patched instr
 * uses ra. If they do (currently there is no such case), the original ra value
 * is restored before executing the patched instrs.
 */
static inline void
check_ra(struct intercept_disasm_result *result, struct cs_insn *insn)
{
	uint8_t op_c = insn->detail->riscv.op_count;
	cs_riscv_op *ops = insn->detail->riscv.operands;

	for (uint8_t i = 0; i < op_c; ++i) {
		if (ops[i].type == RISCV_OP_REG && ops[i].reg == RISCV_REG_RA) {
			result->is_ra_used = true;
			return;
		}
	}
}

/*
 * This helps only the TYPE_SML patch when there is a register which gets set
 * immediately after ecall. In these situations (which are quite frequent) the
 * patching size is only 4 bytes (in that case, only ecall gets replaced with jal)
 * because on the way back to glibc, the register that gets set immediately after
 * ecall is used for the absolute jump.
 */
static inline void
check_reg_set(struct intercept_disasm_result *result, struct cs_insn *insn)
{
	cs_riscv_op op0 = insn->detail->riscv.operands[0];
	cs_riscv_op op1 = insn->detail->riscv.operands[1];

	if (op0.access == 0x2 && (op0.type != op1.type || op0.reg != op1.reg))
		result->reg_set = op0.reg - 1;
#ifdef __riscv_c
	// ra implicitly overwritten
	else if (insn->id == RISCV_INS_C_JAL || (insn->id == RISCV_INS_C_JALR &&
			op0.reg != RISCV_REG_RA))
		result->reg_set = RISCV_REG_RA - 1;
#endif
}

/*
 * Just check which jump is used here (absolute or relative) and save the
 * destination of the relative jumps. Used for jump_table...
 */
static inline void
check_jump(struct intercept_disasm_result *result, struct cs_insn *insn,
		const uint8_t *code)
{
	uint8_t op_c = insn->detail->riscv.op_count;
	cs_riscv_op *ops = insn->detail->riscv.operands;

	if (insn->id == RISCV_INS_JALR || insn->id == RISCV_INS_C_JALR ||
			insn->id == RISCV_INS_C_JR) {
		result->is_abs_jump = true;
	} else if (ops[op_c - 1].type == RISCV_OP_IMM) {
		result->has_ip_relative_opr = true;
		result->rip_disp = ops[op_c - 1].imm;
		result->rip_ref_addr = code + ops[op_c - 1].imm;
	}
}

/*
 * intercept_disasm_next_instruction - Examines a single instruction
 * in a text section. This is only a wrapper around capstone specific code,
 * collecting data that can be used later to make decisions about patching.
 */
struct intercept_disasm_result
intercept_disasm_next_instruction(struct intercept_disasm_context *context,
					const uint8_t *code)
{
	struct intercept_disasm_result result = {
		.address = code,
		// syscall can be 0 so set it to -1 initially
		.a7_set = -1
	};
	const unsigned char *start = code;
	size_t size = (size_t)(context->end - code + 1);
	uint64_t address = (uint64_t)code;

	if (!cs_disasm_iter(context->handle, &start, &size,
	    &address, context->insn)) {
		return result;
	}

	result.length = context->insn->size;

	assert(result.length != 0);

	get_a7(&result, context->insn);
	check_ra(&result, context->insn);
	check_reg_set(&result, context->insn);

	/*
	 * auipc could be patched and relocated, but the absolute addr would
	 * have to be loaded into the register in the relocation space which
	 * is costly.
	 * For now just skip it unless it becomes needed in the future...
	 */
	result.has_ip_relative_opr = (context->insn->id == RISCV_INS_AUIPC);
	result.is_syscall = (context->insn->id == RISCV_INS_ECALL);

#ifndef NDEBUG
	strncpy(result.mnemonic, context->insn->mnemonic,
		sizeof(result.mnemonic) - 1);
#endif
	uint8_t grp_count = context->insn->detail->groups_count;
	for (uint8_t i = 0; i < grp_count; ++i) {
		switch (context->insn->detail->groups[i]) {
		case RISCV_GRP_RET:
		case RISCV_GRP_CALL:
		case RISCV_GRP_JUMP:
		case RISCV_GRP_BRANCH_RELATIVE:
			check_jump(&result, context->insn, code);
			goto grp_done;
		}
	}
grp_done:

	result.is_set = true;

	return result;
}
