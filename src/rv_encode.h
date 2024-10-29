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

#pragma once
#include <stdint.h>
#include <stddef.h>

/* Generic instruction sizes */
#define RV_INS_SIZE		4
#define RVC_INS_SIZE		2

/* Sizes of some frequently used instructions */
#ifdef __riscv_c
#define C_NOP_INS_SIZE		RVC_INS_SIZE
#define C_LI_INS_SIZE		RVC_INS_SIZE
#define C_JR_INS_SIZE		RVC_INS_SIZE
#define MODIFY_SP_INS_SIZE	RVC_INS_SIZE
#define STORE_LOAD_INS_SIZE	RVC_INS_SIZE
#define SLLI_INS_SIZE		RVC_INS_SIZE
#else
#define MODIFY_SP_INS_SIZE	RV_INS_SIZE
#define STORE_LOAD_INS_SIZE	RV_INS_SIZE
#define SLLI_INS_SIZE		RV_INS_SIZE
#endif
#define LUI_INS_SIZE		RV_INS_SIZE
#define ADDI_INS_SIZE		RV_INS_SIZE
#define ADDIW_INS_SIZE		RV_INS_SIZE
#define ECALL_INS_SIZE		RV_INS_SIZE
#define JAL_INS_SIZE		RV_INS_SIZE
#define JALR_INS_SIZE		RV_INS_SIZE
#define AUIPC_INS_SIZE		RV_INS_SIZE

#define JUMP_2GB_INS_SIZE	(AUIPC_INS_SIZE + \
				JALR_INS_SIZE)
/*
 * Size of this varies quite a bit, depending on the destination address
 * and compression. This size is for the worst case scenario. The final size
 * is 20-24 bytes depending only on SLLI because the compressed version can
 * shift same as the non-compressed version (at least on 64-bit CPU).
 * For that reason, the SLLI size is determined in preprocessing time.
 */
#define JUMP_ABS_INS_SIZE	(LUI_INS_SIZE + \
				ADDIW_INS_SIZE + \
				SLLI_INS_SIZE + \
				ADDI_INS_SIZE + \
				SLLI_INS_SIZE + \
				JALR_INS_SIZE)

/*
 * NOTE: JAL_MID_REACH reach lays in between +/- offset, the positive offset is
 *       0xffffe and the negative is 0x100000.
 *       The bias is 2 because of the implicit bit.
 */
#define JAL_MID_REACH		0xfffff
/*
 * NOTE: JUMP_2GB_MAX_REACH reach applies to the negative offset
 * 	 while the positive offset is: JUMP_2GB_MAX_REACH - 4KB
 * 	 because of 2's complement bias and auipc shifting (1 << 12)
 */
#define JUMP_2GB_NEG_REACH	INT32_MIN
#define JUMP_2GB_POS_REACH	(INT32_MAX - 0xfff)

/* Pseudo instructions max sizes */
#define MAX_PC_INS_SIZE		RV_INS_SIZE
// max size of the biggest pseudo instruction, currently rvp_jump_abs()
#define MAX_P_INS_SIZE		JUMP_ABS_INS_SIZE


enum {
	REG_ZERO,
	REG_RA,
	REG_SP,
	REG_GP,
	REG_TP,
	REG_T0,
	REG_T1,
	REG_T2,
	REG_S0,
	REG_S1,
	REG_A0,
	REG_A1,
	REG_A2,
	REG_A3,
	REG_A4,
	REG_A5,
	REG_A6,
	REG_A7,
	REG_S2,
	REG_S3,
	REG_S4,
	REG_S5,
	REG_S6,
	REG_S7,
	REG_S8,
	REG_S9,
	REG_S10,
	REG_S11,
	REG_T3,
	REG_T4,
	REG_T5,
	REG_T6
};

/* Base Instructions */
uint8_t rv_lui(uint8_t *instr_buff, uint8_t rd, int32_t imm);
uint8_t rv_addi(uint8_t *instr_buff, uint8_t rd, uint8_t rs, int32_t imm);
uint8_t rv_addiw(uint8_t *instr_buff, uint8_t rd, uint8_t rs, int32_t imm);
uint8_t rv_slli(uint8_t *instr_buff, uint8_t rd, uint8_t rs, int32_t imm);
uint8_t rv_sd(uint8_t *instr_buff, uint8_t rs1, uint8_t rs2, int32_t imm);
uint8_t rv_ld(uint8_t *instr_buff, uint8_t rd, uint8_t rs, int32_t imm);
uint8_t rv_auipc(uint8_t *instr_buff, uint8_t rd, int32_t imm);
uint8_t rv_jal(uint8_t *instr_buff, uint8_t rd, int32_t imm);
uint8_t rv_jalr(uint8_t *instr_buff, uint8_t rd, uint8_t rs, int32_t imm);

/* Compressed Instructions */
#ifdef __riscv_c
uint8_t rvc_li(uint8_t *instr_buff, uint8_t rd, int32_t imm);
uint8_t rvc_sdsp(uint8_t *instr_buff, uint8_t rs, int32_t imm);
uint8_t rvc_ldsp(uint8_t *instr_buff, uint8_t rd, int32_t imm);
uint8_t rvc_addi16sp(uint8_t *instr_buff, int32_t imm);
uint8_t rvc_addi(uint8_t *instr_buff, uint8_t rd, int32_t imm);
uint8_t rvc_addiw(uint8_t *instr_buff, uint8_t rd, int32_t imm);
uint8_t rvc_slli(uint8_t *instr_buff, uint8_t rd, int32_t imm);
uint8_t rvc_jalr(uint8_t *instr_buff, uint8_t rs);
uint8_t rvc_jr(uint8_t *instr_buff, uint8_t rs);
uint8_t rvc_nop(uint8_t *instr_buff);
#endif

/*
 * Pseudo (Potentially) Compressed Instructions
 * Encode only one instruction, either compressed or noncompressed
 * based on CPU support and operands.
 */
uint8_t rvpc_addi(uint8_t *instr_buff, uint8_t rd, uint8_t rs, int32_t imm);
uint8_t rvpc_addiw(uint8_t *instr_buff, uint8_t rd, uint8_t rs, int32_t imm);
uint8_t rvpc_slli(uint8_t *instr_buff, uint8_t rd, uint8_t rs, int32_t imm);
uint8_t rvpc_li(uint8_t *instr_buff, uint8_t rd, int32_t imm);
uint8_t rvpc_addisp(uint8_t *instr_buff, int32_t imm);
uint8_t rvpc_sd(uint8_t *instr_buff, uint8_t rs1, uint8_t rs2, int32_t imm);
uint8_t rvpc_ld(uint8_t *instr_buff, uint8_t rd, uint8_t rs, int32_t imm);
uint8_t rvpc_jalr(uint8_t *instr_buff, uint8_t rd, uint8_t rs, int32_t imm);

/*
 * Pseudo Instructions
 * NOTE: Not following the RV standard pseudo instructions necessarily.
 *       These are here to serve mostly the purpose of syscall_intercept.
 */
uint8_t rvp_jal(uint8_t *instr_buff, uint8_t rd, uintptr_t from, uintptr_t to);
uint8_t rvp_sd_to_sym(uint8_t *instrs_buff, uint8_t tmp_reg, uint8_t rs,
			uintptr_t from, uintptr_t sym_addr);
uint8_t rvp_ld_from_sym(uint8_t *instrs_buff, uint8_t rd,
			uintptr_t from, uintptr_t sym_addr);
uint8_t rvp_jump_2GB(uint8_t *instrs_buff, uint8_t rd, uint8_t rs,
			uintptr_t from, uintptr_t to);
uint8_t rvp_jump_abs(uint8_t *instrs_buff, uint8_t rd,
			uint8_t rs, uintptr_t to);
