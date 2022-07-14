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
 * patcher.c -- patching a library
 *
 * Jumping from the subject library:
 *
 *     /--------------------------\
 *     |               subject.so |
 *     |                          |
 *     |  jmp to_trampoline_table |  patched by activate_patches()
 *  /->|   |                      |
 *  |  \___|______________________/
 *  |      |
 *  |  /---|--------------------------\
 *  |  | movabs %r11, wrapper_address | jmp generated by activate_patches()
 *  |  | jmp *%r11                    | This allows subject.so and
 *  |  |   |                          | libsyscall_intercept.so to be farther
 *  |  \___|__________________________/ than 2 gigabytes from each other
 *  |      |
 *  |  /---|-----------------------------\
 *  |  |   |  libsyscall_intercept.so    |
 *  |  |   |                             |
 *  |  | /-|--------------------------\  |
 *  |  | | |  static unsigned char    |  |
 *  |  | | |  asm_wrapper_space[]     |  |
 *  |  | | |    in BSS                |  | wrapper routine
 *  |  | | |                          |  | generated into asm_wrapper_space
 *  |  | | |                          |  | by create_wrapper()
 *  |  | |wrapper routine             |  |
 *  |  | |calls C hook function  ----------> intercept_routine in intercept.c
 *  |  | |movabs %r11, return_address |  |
 *  |  | |jmp *%r11                   |  |
 *  |  | \_|__________________________/  |
 *  |  \___|_____________________________/
 *  |      |
 *  \______/
 *
 */

#include "intercept.h"
#include "intercept_util.h"
#include "intercept_log.h"

#include <assert.h>
#include <stdint.h>
#include <syscall.h>
#include <sys/mman.h>
#include <string.h>

#include <stdio.h>

/* The size of a trampoline jump */
enum { TRAMPOLINE_SIZE = 28 + 8 - 8};

static void create_wrapper(struct patch_desc *patch, unsigned char **dst);

/*
 * create_absolute_jump(from, to)
 * Create an indirect jump, with the pointer right next to the instruction.
 *
 * ba @address
 *
 * This uses up 6 bytes for the jump instruction, and another 8 bytes
 * for the pointer right after the instruction.
 */
static unsigned char *
create_absolute_jump(unsigned char *from, void *to)
{
	*(unsigned *)from = (unsigned)0x48000002; // Branch absolute
	uintptr_t delta32 = (uintptr_t)to;

	*(unsigned *)from |= (((((delta32))))& 0x3FFFFFC);
	from += 4;
	return from;
}


/*
 * create_absolute_jumptr
 * Creates a jump to the trampoline,
 * We need to load a 64 bit address to a register
 *
 * and do a bctr
 */
static unsigned char *
create_absolute_jumptr(unsigned char *from, void *to)
{

/// Nota : La primera 
	uintptr_t delta32 = (uintptr_t)to;
	*(unsigned *)from = (unsigned)0xf9e1ffe0;// 8; // std r15,-8(r1)  => deletes the r31 stored inside clone, we may have sideeffects here
	from += 4;
	*(unsigned *)from = (unsigned)0x39E00000; // 39 (li) 3D (lis)
//	*(unsigned *)from |= (((((delta32 >> 48))))& 0xFFFF);
//	from += 4;
//	*(unsigned *)from = (unsigned)0x61EF0000;
	*(unsigned *)from |= (((((delta32 >> 32))))& 0xFFFF);
	from += 4;

	*(unsigned *)from = (unsigned)0x79EF07C6;

	from += 4;
	*(unsigned *)from = (unsigned)0x65EF0000; // 61 ori 65 oris
	*(unsigned *)from |= (((((delta32 >> 16))))& 0xFFFF);
	from += 4;
	*(unsigned *)from = (unsigned)0x61EF0000;
	*(unsigned *)from |= (((((delta32))))& 0xFFFF);
	from += 4;
	*(unsigned *)from = (unsigned)0x7de903a6;
	from += 4;
	*(unsigned *)from = (unsigned)0xe9e1ffe0;// 8;  // ld r15, -8(r1) (restore 31)
	from += 4;
	*(unsigned *)from = (unsigned)0x4e800420;
	from += 4;

	return from;
}

/*
 * check_relative_jump
 * Check if we are inside the jump zone allowed
 * in powerpc (with a branch)
 */
bool
check_relative_jump(unsigned char *from, void *to)
{
	ptrdiff_t delta = ((unsigned char *)to) - (from);
	if (delta > ((ptrdiff_t)INT32_MAX>>8) ||
		delta < ((ptrdiff_t)INT32_MIN>>8))
		return false;
	return true;
}


/*
 * create_jump(opcode, from, to)
 * Create a 5 byte jmp/call instruction jumping to address to, by overwriting
 * code starting at address from.
 */
void
create_jump(unsigned char opcode, unsigned char *from, void *to)
{
	(void) opcode;

	ptrdiff_t delta = ((unsigned char *)to) - (from);
	// TODO: we remove it to left some syscalls unpatched
	// if (delta > ((ptrdiff_t)INT32_MAX>>8) ||
	//	delta < ((ptrdiff_t)INT32_MIN>>8))
	//	xabort("create_jump distance check");
	//	return;
	int32_t delta32 = (int32_t)delta;

	unsigned char *d = (unsigned char *)&delta32;

	*(unsigned *)from = (unsigned)0x48000000;
	*(unsigned *)from |= ((((*((unsigned *)d))))& 0x3FFFFFC);
}

/*
 * check_trampoline_usage -
 * Make sure the trampoline table allocated at the beginning of patching has
 * enough space for all trampolines. This just aborts the process if the
 * allocate space does not seem to be enough, but it can be fairly easy
 * to implement more allocation here if such need would arise.
 */
static void
check_trampoline_usage(const struct intercept_desc *desc)
{
	if (!desc->uses_trampoline_table)
		return;

	/*
	 * We might actually not have enough space for creating
	 * more trampolines.
	 */

	size_t used = (size_t)(desc->next_trampoline - desc->trampoline_table);

	if (used + TRAMPOLINE_SIZE >= desc->trampoline_table_size)
		xabort("trampoline space not enough");
}




/*
 * create_patch_wrappers - create the custom assembly wrappers
 * around each syscall to be intercepted. Well, actually, the
 * function create_wrapper does that, so perhaps this function
 * deserves a better name.
 * What this function actually does, is figure out how to create
 * a jump instruction in libc ( which bytes to overwrite ).
 * If it successfully finds suitable bytes for hotpatching,
 * then it determines the exact bytes to overwrite, and the exact
 * address for jumping back to libc.
 *
 * This is all based on the information collected by the routine
 * find_syscalls, which does the disassembling, finding jump destinations,
 * finding padding bytes, etc..
 */
void
create_patch_wrappers(struct intercept_desc *desc, unsigned char **dst)
{

	for (unsigned patch_i = 0; patch_i < desc->count; ++patch_i) {
		struct patch_desc *patch = desc->items + patch_i;
		debug_dump("patching %s:0x%lx\n", desc->path,
				patch->syscall_addr - desc->base_addr);
			/*
			 * Count the number of overwritable bytes
			 * in the variable length.
			 * Sum up the bytes that can be overwritten.
			 * The 2 bytes of the syscall instruction can
			 * be overwritten definitely, so length starts
			 * as SYSCALL_INS_SIZE ( 2 bytes ).
			 */
		unsigned length = SYSCALL_INS_SIZE;

		patch->dst_jmp_patch = patch->syscall_addr;

		patch->return_address =
				patch->syscall_addr + SYSCALL_INS_SIZE;


		if (length < JUMP_INS_SIZE) {
			char buffer[0x1000];

			int l = snprintf(buffer, sizeof(buffer),
		"unintercepted syscall at: %s 0x%lx\n",
		desc->path,
		patch->syscall_offset);

			intercept_log(buffer, (size_t)l);
			xabort("not enough space for patching"
			" around syscal");
		}

		mark_jump(desc, patch->return_address);

		create_wrapper(patch, dst);
	}


}

/*
 * Referencing symbols defined in intercept_template.s
 */
extern unsigned char intercept_asm_wrapper_tmpl[];
extern unsigned char intercept_asm_wrapper_tmpl_end;
extern unsigned char intercept_asm_wrapper_patch_desc_addr;
extern unsigned char intercept_asm_wrapper_wrapper_level1_addr;
extern unsigned char intercept_wrapper;
extern unsigned char intercept_asm_wrapper_r2_load_addr;

size_t asm_wrapper_tmpl_size;
static ptrdiff_t o_patch_desc_addr;
static ptrdiff_t o_wrapper_level1_addr;
static ptrdiff_t o_r2_load_addr;


/*
 * init_patcher
 * Some variables need to be initialized before patching.
 * This routine must be called once before patching any library.
 */
void
init_patcher(void)
{
	unsigned char *begin = &intercept_asm_wrapper_tmpl[0];

	assert(&intercept_asm_wrapper_tmpl_end > begin);
	assert(&intercept_asm_wrapper_patch_desc_addr > begin);
	assert(&intercept_asm_wrapper_wrapper_level1_addr > begin);
	assert(&intercept_asm_wrapper_patch_desc_addr <
		&intercept_asm_wrapper_tmpl_end);
	assert(&intercept_asm_wrapper_wrapper_level1_addr <
		&intercept_asm_wrapper_tmpl_end);

	asm_wrapper_tmpl_size =
		(size_t)(&intercept_asm_wrapper_tmpl_end - begin);
	o_patch_desc_addr = &intercept_asm_wrapper_patch_desc_addr - begin;
	o_wrapper_level1_addr =
		&intercept_asm_wrapper_wrapper_level1_addr - begin;
	o_r2_load_addr = &intercept_asm_wrapper_r2_load_addr - begin;

}

void
create_movabs_p1(unsigned char *dst, uintptr_t loc)
{
//	*(unsigned *)dst |= ((loc >> 48) & 0xFFFF);

//	dst += 4;
	*(unsigned *)dst |= ((loc >> 32) & 0xFFFF);

	dst += 8;

	*(unsigned *)dst |= ((loc >> 16) & 0xFFFF);

	dst += 4;

	*(unsigned *)dst |= ((loc) & 0xFFFF);
}


/*
 * create_wrapper
 * Generates an assembly wrapper. Copies the template written in
 * intercept_template.s, and generates the instructions specific
 * to a particular syscall into the new copy.
 * After this wrapper is created, a syscall can be replaced with a
 * jump to this wrapper, and wrapper is going to call dest_routine
 * (actually only after a call to mprotect_asm_wrappers).
 */
static void
create_wrapper(struct patch_desc *patch, unsigned char **dst)
{
	/* Create a new copy of the template */
	patch->asm_wrapper = *dst;

	memcpy(*dst, intercept_asm_wrapper_tmpl, asm_wrapper_tmpl_size);
	unsigned long long i;
	// Store the TOC (global) in the wrapper
	__asm__ volatile
	(
	"mr %0, 2\n\t"
	:"=r"(i) /* Output registers */
	:
	: /* No clobbered registers */);

	create_movabs_p1(*dst + o_r2_load_addr, (uintptr_t)i);
	create_movabs_p1(*dst + o_patch_desc_addr, (uintptr_t)patch);
	create_movabs_p1(*dst + o_wrapper_level1_addr,
		(uintptr_t)&intercept_wrapper);

	*dst += asm_wrapper_tmpl_size - 7 * 4;
	if (check_relative_jump(*dst, patch->return_address)) {
		create_jump(1, *dst, patch->return_address);
		*dst += 4;
	} else {
		debug_dump("Check relative NEED A LONG JUMP => TOC?!\n");
		create_movabs_p1(*dst, (uintptr_t)patch->return_address);
		*dst += 7 * 4;
	}
}




/*
 * activate_patches()
 * Loop over all the patches, and and overwrite each syscall.
 */
void
activate_patches(struct intercept_desc *desc)
{
	unsigned char *first_page;
	size_t size;

	if (desc->count == 0)
		return;

	first_page = round_down_address(desc->text_start);
	size = (size_t)(desc->text_end - first_page);

	mprotect_no_intercept(first_page, size,
		PROT_READ | PROT_WRITE | PROT_EXEC,
		"mprotect PROT_READ | PROT_WRITE | PROT_EXEC");

	for (unsigned i = 0; i < desc->count; ++i) {
		const struct patch_desc *patch = desc->items + i;

		if (patch->dst_jmp_patch < desc->text_start ||
			patch->dst_jmp_patch > desc->text_end)
			xabort("dst_jmp_patch outside text");

		/*
		 * The dst_jmp_patch pointer contains the address where
		 * the actual jump instruction escaping the patched text
		 * segment should be written.
		 * This is either at the place of the original syscall
		 * instruction, or at some usable padding space close to
		 * it (an overwritable NOP instruction).
		 */

		if (desc->uses_trampoline_table) {
			/*
			 * First jump to the trampoline table, which
			 * should be in a 2 gigabyte range. From there,
			 * jump to the asm_wrapper.
			 */
			check_trampoline_usage(desc);

			/* jump - escape the text segment */
			create_jump(JMP_OPCODE,
				patch->dst_jmp_patch, desc->next_trampoline);

			/* jump - escape the 2 GB range of the text segment */
			desc->next_trampoline = create_absolute_jumptr(
				desc->next_trampoline, patch->asm_wrapper);
		} else {
			if (check_relative_jump(patch->dst_jmp_patch,
				patch->asm_wrapper))
				create_jump(JMP_OPCODE, patch->dst_jmp_patch,
				patch->asm_wrapper);
			else {
				printf("Without trampoline table %lx - %lx \n",
					(uintptr_t)patch->dst_jmp_patch,
					(uintptr_t)patch->asm_wrapper);
				create_absolute_jump(
				patch->dst_jmp_patch, patch->asm_wrapper);
			}
		}


		unsigned char *byte;

		for (byte = patch->dst_jmp_patch + JUMP_INS_SIZE;
			byte < patch->return_address;
			++byte) {
			*byte = INT3_OPCODE;

		}
	}

	mprotect_no_intercept(first_page, size,
		PROT_READ | PROT_EXEC,
		"mprotect PROT_READ | PROT_EXEC");
}
