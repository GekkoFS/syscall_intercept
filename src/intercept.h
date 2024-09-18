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
 * intercept.h - a few declarations used in libsyscall_intercept
 */

#ifndef INTERCEPT_INTERCEPT_H
#define INTERCEPT_INTERCEPT_H

#include <stdbool.h>
#include <elf.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>

#include "disasm_wrapper.h"
#include "rv_encode.h"

extern bool debug_dumps_on;
void debug_dump(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#define INTERCEPTOR_EXIT_CODE 111

__attribute__((noreturn)) void xabort_errno(int error_code, const char *msg);

__attribute__((noreturn)) void xabort(const char *msg);

void xabort_on_syserror(long syscall_result, const char *msg);

struct syscall_desc {
	int nr;
	long args[6];
};

/*
 * The patch_list array stores some information on
 * whereabouts of patches made to glibc.
 * The syscall_addr pointer points to where a syscall
 *  instruction originally resided in glibc.
 * The asm_wrapper pointer points to the function
 *  called from glibc.
 * The glibc_call_patch pointer points to the exact
 *  location, where the new call instruction should
 *  be written.
 */
struct patch_desc {
	/* the address to jump back to */
	const uint8_t *return_address;
	/* the address where the relocated patches are */
	const uint8_t *relocation_address;
	/* holds the a7 value found before ecall or -1 for MID a7, -2 for GW */
	int16_t syscall_num;

	/* the original syscall instruction */
	const uint8_t *syscall_addr;

	const char *containing_lib_path;

	/* the offset of the original syscall instruction */
	uint64_t syscall_offset;

	/*
	 * GW:  address of the first byte overwritten in the code,
	 *      excluding c_nop when needed to align patch block
	 * MID: address of the GW's patch, skipping MODIFY_SP_INS_SIZE
	 *      because TYPE_MID already reduced the stack pointer
	 * SML: address of the GW's first byte overwritten in the code
	 */
	uint8_t *dst_jmp_patch;
	uint8_t patch_size_bytes;

	/* align patch with surrounding instrs, only needed with compressed code */
#ifdef __riscv_c
	bool start_with_c_nop;
	bool end_with_c_nop;
#endif

	/*
	 * Describe up to three instructions surrounding the original
	 * syscall instructions. Sometimes just overwritting the two
	 * direct neighbors of the syscall is not enough, ( e.g. if
	 * both the directly preceding, and the directly following are
	 * single byte instruction, that only gives 4 bytes of space ).
	 */
	struct intercept_disasm_result *surrounding_instrs;
	uint8_t syscall_idx;
	bool is_ra_used_before;
	uint8_t return_register;
};

/*
 * A section_list struct contains information about sections where
 * libsyscall_intercept looks for jump destinations among symbol addresses.
 * Generally, only two sections are used for this, so 16 should be enough
 * for the maximum number of headers to be stored.
 *
 * See the calls to the add_table_info routine in the intercept_desc.c source
 * file.
 */
struct section_list {
	Elf64_Half count;
	Elf64_Shdr headers[0x10];
};

struct intercept_desc {
	/*
	 * uses_trampoline_table - For now this is decided runtime
	 * to make it easy to compare the operation of the library
	 * with and without it. If it is OK, we can remove this
	 * flag, and just always use the trampoline table.
	 */
	bool uses_trampoline;

	/*
	 * delta between vmem addresses and addresses in symbol tables,
	 * non-zero for dynamic objects
	 */
	unsigned char *base_addr;

	/* where the object is in fs */
	const char *path;

	/*
	 * Some sections of the library from which information
	 * needs to be extracted.
	 * The text section is where the code to be hotpatched
	 * resides.
	 * The symtab, and dynsym sections provide information on
	 * the whereabouts of symbols, whose address in the text
	 * section.
	 */
	Elf64_Half text_section_index;
	Elf64_Shdr sh_text_section;

	struct section_list symbol_tables;
	struct section_list rela_tables;

	/* Where the text starts inside the shared object */
	unsigned long text_offset;

	/*
	 * Where the text starts and ends in the virtual memory seen by the
	 * current process.
	 */
	unsigned char *text_start;
	unsigned char *text_end;

	struct patch_desc *items;
	unsigned count;

	uint8_t *jump_table;

	/* the RISC-V version only needs one trampoline per patched library */
	uint8_t *trampoline_address;
};

bool has_jump(const struct intercept_desc *desc, const uint8_t *addr);
void mark_jump(const struct intercept_desc *desc, const unsigned char *addr);

void allocate_trampoline(struct intercept_desc *desc);
void find_syscalls(struct intercept_desc *desc);

void create_patch(struct intercept_desc *desc, unsigned char **dst);

/*
 * Actually overwrite instructions in glibc.
 */
void activate_patches(struct intercept_desc *desc);

#define SURROUNDING_INSTRS_NUM	13
#define SYSCALL_IDX		6

#define TYPE_GW			-2
#define TYPE_MID		-1
//Implicitly: TYPE_SML >= 0

#define TYPE_MID_SIZE		(MODIFY_SP_INS_SIZE + \
				STORE_LOAD_INS_SIZE + \
				JAL_INS_SIZE + \
				STORE_LOAD_INS_SIZE + \
				MODIFY_SP_INS_SIZE)

#define TYPE_GW_SIZE		(MODIFY_SP_INS_SIZE + \
				STORE_LOAD_INS_SIZE + \
				JUMP_2GB_INS_SIZE + \
				STORE_LOAD_INS_SIZE + \
				MODIFY_SP_INS_SIZE)

#define TRAMPOLINE_SIZE 	(MODIFY_SP_INS_SIZE + \
				STORE_LOAD_INS_SIZE + \
				JUMP_ABS_INS_SIZE)
/*
 * When the trampoline is not used, the GW jumps directly to asm_entry_point
 * but with a small offset because the first two instructions in asm_entry_point
 * are there to restore the GW's ra that was overwritten by the trampoline.
 * This is clearly not necessary when the GW jumps directly.
 */
#define DIRECT_JUMP_OFFSET	(STORE_LOAD_INS_SIZE + \
				MODIFY_SP_INS_SIZE)

extern const char *cmdline;

#define PAGE_SIZE ((size_t)0x1000)

static inline unsigned char *
round_down_address(unsigned char *address)
{
	return (unsigned char *)(((uintptr_t)address) & ~(PAGE_SIZE - 1));
}

#endif
