#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "rv_encode.h"


/* for now, used only by auipc-related pseudo instructions */
typedef struct {
	// upper 20 bits
	int32_t offset_hi;
	// lower 12 bits
	int16_t offset_lo;
} offsets_2GB;


static void
reverse_byte_order(uint8_t *instr_buff, uint32_t instr, size_t size)
{
	for (size_t i = 0; i < size; ++i) {
		uint8_t shift = i * 8;
		instr_buff[i] = instr >> shift & 0xff;
	}
}

static offsets_2GB
get_auipc_offsets(uintptr_t from, uintptr_t to)
{
	ptrdiff_t delta = to - from;

	if (delta < JUMP_2GB_NEG_REACH || delta > JUMP_2GB_POS_REACH)
		return (offsets_2GB){0};

	int32_t delta_hi = delta >> 12 & 0xfffff;
	int16_t delta_lo = delta & 0xfff;

	if (delta_lo >= 0x800) {
		// if the address is canonical, there shouldn't be an overflow
		++delta_hi;
		delta_lo -= 0x1000;
	}

	// sign-extends 20 bits
	if (delta_hi & 0x80000)
		delta_hi |= 0xfff00000;
	else
		delta_hi &= 0xfffff;

	// sign-extends 12 bits
	if (delta_lo & 0x800)
		delta_lo |= 0xf000;
	else
		delta_lo &= 0xfff;

	return (offsets_2GB){.offset_hi = delta_hi, .offset_lo = delta_lo};
}


#ifdef __riscv_c
uint8_t
rvc_li(uint8_t *instr_buff, uint8_t rd, int32_t imm)
{
	if (imm < -0x20 || imm >= 0x20)
		return 0;

	uint16_t instr = 0;

	instr = 0x2 << 13 | (imm >> 5 & 0x1) << 12;
	instr |= rd << 7 | (imm & 0x1f) << 2 | 0x1;

	reverse_byte_order(instr_buff, instr, RVC_INS_SIZE);

	return RVC_INS_SIZE;
}

uint8_t
rvc_sdsp(uint8_t *instr_buff, uint8_t rs, int32_t imm)
{
	if (imm < 0 || imm % 8 != 0 || imm / 8 >= 0x40)
		return 0;

	uint16_t instr = 0;
	imm /= 8;

	instr = 0x7 << 13 | (imm & 0x7) << 10;
	instr |= (imm >> 3 & 0x7) << 7 | rs << 2 | 0x2;

	reverse_byte_order(instr_buff, instr, RVC_INS_SIZE);

	return RVC_INS_SIZE;
}

uint8_t
rvc_ldsp(uint8_t *instr_buff, uint8_t rd, int32_t imm)
{
	if (imm < 0 || imm % 8 != 0 || imm / 8 >= 0x40)
		return 0;

	uint16_t instr = 0;
	imm /= 8;

	instr = 0x3 << 13 | (imm >> 2 & 0x1) << 12 | rd << 7;
	instr |= (imm & 0x3) << 5 | (imm >> 3 & 0x7) << 2 | 0x2;

	reverse_byte_order(instr_buff, instr, RVC_INS_SIZE);

	return RVC_INS_SIZE;
}

uint8_t
rvc_addi16sp(uint8_t *instr_buff, int32_t imm)
{
	if (imm == 0 || imm % 16 != 0 || imm / 16 < -0x20 || imm / 16 >= 0x20)
		return 0;

	uint16_t instr = 0;
	imm /= 16;

	instr = 0x3 << 13 | (imm >> 5 & 0x1) << 12 | 0x2 << 7;
	instr |= (imm & 0x1) << 6 |(imm >> 2 & 0x1) << 5;
	instr |= (imm >> 3 & 0x3) << 3 | (imm >> 1 & 0x1) << 2 | 0x1;

	reverse_byte_order(instr_buff, instr, RVC_INS_SIZE);

	return RVC_INS_SIZE;
}

uint8_t
rvc_addi(uint8_t *instr_buff, uint8_t rd, int32_t imm)
{
	if (rd == REG_ZERO || imm == 0 || imm < -0x20 || imm >= 0x20)
		return 0;

	uint16_t instr = 0;

	instr = (imm >> 5 & 0x1) << 12 | rd << 7 | (imm & 0x1f) << 2 | 0x1;

	reverse_byte_order(instr_buff, instr, RVC_INS_SIZE);

	return RVC_INS_SIZE;
}

uint8_t
rvc_addiw(uint8_t *instr_buff, uint8_t rd, int32_t imm)
{
	if (rd == REG_ZERO || imm < -0x20 || imm >= 0x20)
		return 0;

	uint16_t instr = 0;

	instr = 0x1 << 13 | (imm >> 5 & 0x1) << 12 | rd << 7;
	instr |= (imm & 0x1f) << 2 | 0x1;

	reverse_byte_order(instr_buff, instr, RVC_INS_SIZE);

	return RVC_INS_SIZE;
}

uint8_t
rvc_slli(uint8_t *instr_buff, uint8_t rd, int32_t imm)
{
	if (rd == REG_ZERO || imm <= 0 || imm >= 40)
		return 0;

	uint16_t instr = 0;

	instr = (imm >> 5 & 0x1) << 12 | rd << 7 | (imm & 0x1f) << 2 | 0x2;

	reverse_byte_order(instr_buff, instr, RVC_INS_SIZE);

	return RVC_INS_SIZE;
}

uint8_t
rvc_jalr(uint8_t *instr_buff, uint8_t rs)
{
	if (rs == REG_ZERO)
		return 0;

	uint16_t instr = 0;

	instr = 0x9 << 12 | rs << 7 | REG_ZERO << 2 | 0x2;

	reverse_byte_order(instr_buff, instr, RVC_INS_SIZE);

	return RVC_INS_SIZE;
}

uint8_t
rvc_jr(uint8_t *instr_buff, uint8_t rs)
{
	if (rs == REG_ZERO)
		return 0;

	uint16_t instr = 0;

	instr = 0x8 << 12 | rs << 7 | REG_ZERO << 2 | 0x2;

	reverse_byte_order(instr_buff, instr, RVC_INS_SIZE);

	return RVC_INS_SIZE;
}

uint8_t
rvc_nop(uint8_t *instr_buff)
{
	uint16_t instr = 0x1;

	reverse_byte_order(instr_buff, instr, RVC_INS_SIZE);

	return RVC_INS_SIZE;
}
#endif

uint8_t
rv_lui(uint8_t *instr_buff, uint8_t rd, int32_t imm)
{
	if (rd == REG_ZERO || imm < -0x80000 || imm >= 0x80000)
		return 0;

	uint32_t instr = imm << 12 | rd << 7 | 0x37;

	reverse_byte_order(instr_buff, instr, RV_INS_SIZE);

	return RV_INS_SIZE;
}

uint8_t
rv_addi(uint8_t *instr_buff, uint8_t rd, uint8_t rs, int32_t imm)
{
	if (rd == REG_ZERO || imm < -0x800 || imm >= 0x800)
		return 0;

	uint32_t instr = 0;

	instr = imm << 20 | rs << 15 | rd << 7 | 0x13;

	reverse_byte_order(instr_buff, instr, RV_INS_SIZE);

	return RV_INS_SIZE;
}

uint8_t
rv_addiw(uint8_t *instr_buff, uint8_t rd, uint8_t rs, int32_t imm)
{
	if (rd == REG_ZERO || imm < -0x800 || imm >= 0x800)
		return 0;

	uint32_t instr = 0;

	instr = imm << 20 | rs << 15 | rd << 7 | 0x1B;

	reverse_byte_order(instr_buff, instr, RV_INS_SIZE);

	return RV_INS_SIZE;
}

uint8_t
rv_slli(uint8_t *instr_buff, uint8_t rd, uint8_t rs, int32_t imm)
{
	if (rd == REG_ZERO || imm < 0 || imm >= 0x40)
		return 0;

	uint32_t instr = 0;

	instr = imm << 20 | rs << 15 | 0x1 << 12 | rd << 7 | 0x13;

	reverse_byte_order(instr_buff, instr, RV_INS_SIZE);

	return RV_INS_SIZE;
}

uint8_t
rv_sd(uint8_t *instr_buff, uint8_t rs1, uint8_t rs2, int32_t imm)
{
	if (-0x800 > imm || imm >= 0x800)
		return 0;

	uint32_t instr = 0;

	instr = (imm >> 5 & 0x7f) << 25 | rs1 << 20 | rs2 << 15;
	instr |= 0x3 << 12 | (imm & 0x1f) << 7 | 0x23;

	reverse_byte_order(instr_buff, instr, RV_INS_SIZE);

	return RV_INS_SIZE;
}

uint8_t
rv_ld(uint8_t *instr_buff, uint8_t rd, uint8_t rs, int32_t imm)
{
	if (-0x800 > imm || imm >= 0x800)
		return 0;

	uint32_t instr = 0;

	instr = imm << 20 | rs << 15 | 0x3 << 12 | rd << 7 | 0x3;

	reverse_byte_order(instr_buff, instr, RV_INS_SIZE);

	return RV_INS_SIZE;
}

uint8_t
rv_auipc(uint8_t *instr_buff, uint8_t rd, int32_t imm)
{
	if (rd == REG_ZERO || imm < -0x80000 || imm >= 0x80000)
		return 0;

	uint32_t instr = 0;

	instr = imm << 12 | rd << 7 | 0x17;

	reverse_byte_order(instr_buff, instr, RV_INS_SIZE);

	return RV_INS_SIZE;
}

uint8_t
rv_jal(uint8_t *instr_buff, uint8_t rd, int32_t imm)
{
	if (imm < -JAL_MID_REACH - 1 || imm >= JAL_MID_REACH)
		return 0;

	uint32_t instr = 0;
	imm = imm >> 1;

	instr = (imm >> 19 & 0x1) << 31 | (imm & 0x3ff) << 21;
	instr |= (imm >> 10 & 0x1) << 20 | (imm >> 11 & 0xff) << 12;
	instr |= rd << 7 | 0x6f;

	reverse_byte_order(instr_buff, instr, RV_INS_SIZE);

	return RV_INS_SIZE;
}

uint8_t
rv_jalr(uint8_t *instr_buff, uint8_t rd, uint8_t rs, int32_t imm)
{
	if (-0x800 > imm || imm >= 0x800)
		return 0;

	uint32_t instr = 0;

	instr = imm << 20 | rs << 15 | 0x0 << 12 | rd << 7 | 0x67;

	reverse_byte_order(instr_buff, instr, RV_INS_SIZE);

	return RV_INS_SIZE;
}

uint8_t
rvpc_addi(uint8_t *instr_buff, uint8_t rd, uint8_t rs, int32_t imm)
{
	uint8_t total_size;

#ifdef __riscv_c
	if (rd != rs || (total_size = rvc_addi(instr_buff, rd, imm)) == 0)
		total_size = rv_addi(instr_buff, rd, rs, imm);
#else
	total_size = rv_addi(instr_buff, rd, rs, imm);
#endif

	return total_size;
}

uint8_t
rvpc_addiw(uint8_t *instr_buff, uint8_t rd, uint8_t rs, int32_t imm)
{
	uint8_t total_size;

#ifdef __riscv_c
	if (rd != rs || (total_size = rvc_addiw(instr_buff, rd, imm)) == 0)
		total_size = rv_addiw(instr_buff, rd, rs, imm);
#else
	total_size = rv_addiw(instr_buff, rd, rs, imm);
#endif

	return total_size;
}

uint8_t
rvpc_slli(uint8_t *instr_buff, uint8_t rd, uint8_t rs, int32_t imm)
{
	uint8_t total_size;

#ifdef __riscv_c
	if (rd == rs)
		total_size = rvc_slli(instr_buff, rd, imm);
	else
		total_size = rv_slli(instr_buff, rd, rs, imm);
#else
	total_size = rv_slli(instr_buff, rd, rs, imm);
#endif

	return total_size;
}

uint8_t
rvpc_li(uint8_t *instr_buff, uint8_t rd, int32_t imm)
{
	uint8_t total_size;

#ifdef __riscv_c
	if ((total_size = rvc_li(instr_buff, rd, imm)) == 0)
		total_size = rv_addi(instr_buff, rd, REG_ZERO, imm);
#else
	total_size = rv_addi(instr_buff, rd, REG_ZERO, imm);
#endif

	return total_size;
}

uint8_t
rvpc_addisp(uint8_t *instr_buff, int32_t imm)
{
	uint8_t total_size;

#ifdef __riscv_c
	if ((total_size = rvc_addi16sp(instr_buff, imm)) == 0)
		total_size = rv_addi(instr_buff, REG_SP, REG_SP, imm);
#else
	total_size = rv_addi(instr_buff, REG_SP, REG_SP, imm);
#endif

	return total_size;
}

uint8_t
rvpc_sdsp(uint8_t *instr_buff, uint8_t rs, int32_t imm)
{
	uint8_t total_size;

#ifdef __riscv_c
	if ((total_size = rvc_sdsp(instr_buff, rs, imm)) == 0)
		total_size = rv_sd(instr_buff, rs, REG_SP, imm);
#else
	total_size = rv_sd(instr_buff, rs, REG_SP, imm);
#endif

	return total_size;
}

uint8_t
rvpc_ldsp(uint8_t *instr_buff, uint8_t rd, int32_t imm)
{
	uint8_t total_size;

#ifdef __riscv_c
	if ((total_size = rvc_ldsp(instr_buff, rd, imm)) == 0)
		total_size = rv_ld(instr_buff, rd, REG_SP, imm);
#else
	total_size = rv_ld(instr_buff, rd, REG_SP, imm);
#endif

	return total_size;
}

uint8_t
rvpc_jalr(uint8_t *instr_buff, uint8_t rd, uint8_t rs, int32_t imm)
{
	uint8_t total_size;

#ifdef __riscv_c
	if (rd == REG_ZERO && imm == 0)
		total_size = rvc_jr(instr_buff, rs);
	else if (rd == REG_RA && imm == 0)
		total_size = rvc_jalr(instr_buff, rs);
	else
		total_size = rv_jalr(instr_buff, rd, rs, imm);
#else
	total_size = rv_jalr(instr_buff, rd, rs, imm);
#endif

	return total_size;
}

uint8_t
rvp_jal(uint8_t *instr_buff, uint8_t rd, uintptr_t from, uintptr_t to)
{
	uint8_t total_size;
	int32_t offset = to - from;

	total_size = rv_jal(instr_buff, rd, offset);

	return total_size;
}

uint8_t
rvp_sd_to_sym(uint8_t *instrs_buff, uint8_t tmp_reg, uint8_t rs,
		uintptr_t from, uintptr_t sym_addr)
{
	uint8_t total_size = 0;
	offsets_2GB offs;

	offs = get_auipc_offsets(from, sym_addr);
	if (offs.offset_hi == 0 && offs.offset_lo == 0)
		return 0;

	total_size += rv_auipc(instrs_buff + total_size,
				tmp_reg, offs.offset_hi);
	total_size += rv_sd(instrs_buff + total_size,
				rs, tmp_reg, offs.offset_lo);

	return total_size;
}

uint8_t
rvp_ld_from_sym(uint8_t *instrs_buff, uint8_t rd,
		uintptr_t from, uintptr_t sym_addr)
{
	uint8_t total_size = 0;
	offsets_2GB offs;

	offs = get_auipc_offsets(from, sym_addr);
	if (offs.offset_hi == 0 && offs.offset_lo == 0)
		return 0;

	total_size += rv_auipc(instrs_buff + total_size,
				rd, offs.offset_hi);
	total_size += rv_ld(instrs_buff + total_size,
				rd, rd, offs.offset_lo);

	return total_size;
}

uint8_t
rvp_jump_2GB(uint8_t *instrs_buff, uint8_t rd, uint8_t rs,
		uintptr_t from, uintptr_t to)
{
	uint8_t total_size = 0;
	offsets_2GB offs;

	offs = get_auipc_offsets(from, to);
	if (offs.offset_hi == 0 && offs.offset_lo == 0)
		return 0;

	total_size += rv_auipc(instrs_buff + total_size, rs, offs.offset_hi);
	total_size += rvpc_jalr(instrs_buff + total_size,
				rd, rs, offs.offset_lo);

	return total_size;
}

uint8_t
rvp_jump_abs(uint8_t *instrs_buff, uint8_t rd, uint8_t rs, uintptr_t to)
{
	// either kernel space or just too big address, return 0
	if (to >> 48 & 0xfff)
		return 0;

	uint8_t total_size = 0;

	int32_t addr_hi = to >> 28;
	int16_t addr_mid = (to & 0xfff0000) >> 16;
	int16_t addr_lo = to & 0xffff;

	if (addr_mid >= 0x800) {
		++addr_hi;
		addr_mid -= 0x1000;
	}

	total_size += rv_lui(instrs_buff + total_size, rs, addr_hi);

	if (addr_mid != 0)
		total_size += rvpc_addiw(instrs_buff + total_size,
						rs, rs, addr_mid);

	if (addr_lo == 0) {
		total_size += rvpc_slli(instrs_buff + total_size, rs, rs, 16);
		total_size += rvpc_jalr(instrs_buff + total_size, rd, rs, 0);

		return total_size;
	}

	int8_t addr_lo_upper4 = (addr_lo & 0xf000) >> 12;
	int16_t addr_lo_lower12 = addr_lo & 0xfff;

	total_size += rvpc_slli(instrs_buff + total_size, rs, rs, 4);

	if (addr_lo_lower12 >= 0x800) {
		addr_lo_upper4 += 1 & 0xf;
		addr_lo_lower12 -= 0x1000;
	}

	if (addr_lo_upper4 != 0)
		total_size += rvpc_addi(instrs_buff + total_size, rs, rs,
					addr_lo_upper4);

	total_size += rvpc_slli(instrs_buff + total_size, rs, rs, 12);

	total_size += rvpc_jalr(instrs_buff + total_size,
				rd, rs, addr_lo_lower12);

	return total_size;
}
