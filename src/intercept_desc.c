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

#include <assert.h>
#include <syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <inttypes.h>

#include "intercept.h"
#include "intercept_util.h"
#include "disasm_wrapper.h"
#include "syscall_formats.h"


// Used with environment variables INTERCEPT_SYS_INCLUDE and INTERCEPT_SYS_EXCLUDE
static const char *filter_incl = NULL;
static const char *filter_excl = NULL;
static int32_t *sys_filter_ptr = NULL;


/*
 * For simplicity, declare syscall_no_intercept() with return value 'long'
 * because nothing in this TU needs the a1 register, only a0 is checked.
 */
extern long
syscall_no_intercept(long syscall_number, ...);

/*
 * open_orig_file
 *
 * Instead of looking for the needed metadata in already mmap library,
 * all this information is read from the file, thus its original place,
 * the file where the library is in an FS. The loaded library is mmaped
 * already of course, but not necessarily the whole file is mapped as one
 * readable mem mapping -- only some segments are present in memory, but
 * information about the file's sections, and the sections themselves might
 * only be present in the original file.
 * Note on naming: memory has segments, the object file has sections.
 */
static int
open_orig_file(const struct intercept_desc *desc)
{
	int fd;

	fd = syscall_no_intercept(SYS_openat, AT_FDCWD, desc->path, O_RDONLY);

	xabort_on_syserror(fd, __func__, NULL);

	return fd;
}

static void
add_table_info(struct section_list *list, const Elf64_Shdr *header)
{
	size_t max = sizeof(list->headers) / sizeof(list->headers[0]);

	if (list->count < max) {
		list->headers[list->count] = *header;
		list->count++;
	} else {
		xabort(__func__, "allocated section_list exhausted");
	}
}

/*
 * add_text_info -- Fill the appropriate fields in an intercept_desc struct
 * about the corresponding code text.
 */
static void
add_text_info(struct intercept_desc *desc, const Elf64_Shdr *header,
		Elf64_Half index)
{
	desc->text_offset = header->sh_offset;
	desc->text_start = desc->base_addr + header->sh_addr;
	desc->text_end = desc->text_start + header->sh_size - 1;
	desc->text_section_index = index;
}

/*
 * find_sections
 *
 * See: man elf
 */
static void
find_sections(struct intercept_desc *desc, int fd)
{
	Elf64_Ehdr elf_header;

	desc->symbol_tables.count = 0;
	desc->rela_tables.count = 0;

	xread(fd, &elf_header, sizeof(elf_header));

	Elf64_Shdr sec_headers[elf_header.e_shnum];

	xlseek(fd, elf_header.e_shoff, SEEK_SET);
	xread(fd, sec_headers, elf_header.e_shnum * sizeof(Elf64_Shdr));

	char sec_string_table[sec_headers[elf_header.e_shstrndx].sh_size];

	xlseek(fd, sec_headers[elf_header.e_shstrndx].sh_offset, SEEK_SET);
	xread(fd, sec_string_table,
	    sec_headers[elf_header.e_shstrndx].sh_size);

	bool text_section_found = false;

	for (Elf64_Half i = 0; i < elf_header.e_shnum; ++i) {
		const Elf64_Shdr *section = &sec_headers[i];
		char *name = sec_string_table + section->sh_name;

		debug_dump("looking at section: \"%s\" type: %ld\n",
		    name, (long)section->sh_type);
		if (strcmp(name, ".text") == 0) {
			text_section_found = true;
			add_text_info(desc, section, i);
		} else if (section->sh_type == SHT_SYMTAB ||
		    section->sh_type == SHT_DYNSYM) {
			debug_dump("found symbol table: %s\n", name);
			add_table_info(&desc->symbol_tables, section);
		} else if (section->sh_type == SHT_RELA) {
			debug_dump("found relocation table: %s\n", name);
			add_table_info(&desc->rela_tables, section);
		}
	}

	if (!text_section_found)
		xabort(__func__, "text section not found");
}

/*
 * allocate_jump_table
 *
 * Allocates a bitmap, where each bit represents a unique address in
 * the text section.
 */
static void
allocate_jump_table(struct intercept_desc *desc)
{
	/* How many bytes need to be addressed? */
	assert(desc->text_start < desc->text_end);
	size_t bytes = (size_t)(desc->text_end - desc->text_start + 1);

	/*
	 * RISC-V: Allocate 1 bit for every even address because all RISC-V
	 *         instructions are aligned to 2 bytes.
	 *         Divide by 16 instead of 8...
	 */
	/* Plus one -- integer division can result a number too low */
	desc->jump_table = xmmap_anon(bytes / 16 + 1);
}

/*
 * is_bit_set - check a bit in a bitmap
 */
static bool
is_bit_set(const unsigned char *table, uint64_t offset)
{
	return table[offset / 16] & (1 << (offset / 2 % 8));
}

/*
 * set_bit - set a bit in a bitmap
 */
static void
set_bit(unsigned char *table, uint64_t offset)
{
	unsigned char tmp = (unsigned char)(1 << (offset / 2 % 8));
	table[offset / 16] |= tmp;
}

/*
 * has_jump - check if addr is known to be a destination of any
 * jump ( or subroutine call ) in the code. The address must be
 * the one seen by the current process, not the offset in the original
 * ELF file.
 */
bool
has_jump(const struct intercept_desc *desc, const uint8_t *addr)
{
	if (addr >= desc->text_start && addr <= desc->text_end)
		return is_bit_set(desc->jump_table,
		    (uint64_t)(addr - desc->text_start));
	else
		return false;
}

/*
 * mark_jump - Mark an address as a jump destination, see has_jump above.
 */
void
mark_jump(const struct intercept_desc *desc, const unsigned char *addr)
{
	if (addr >= desc->text_start && addr <= desc->text_end)
		set_bit(desc->jump_table, (uint64_t)(addr - desc->text_start));
}

/*
 * find_jumps_in_section_syms
 *
 * Read the .symtab or .dynsym section, which stores an array of Elf64_Sym
 * structs. Some of these symbols are functions in the .text section,
 * thus their entry points are jump destinations.
 *
 * The st_value fields holds the virtual address of the symbol
 * relative to the base address.
 *
 * The format of the entries:
 *
 * typedef struct
 * {
 *   Elf64_Word	st_name;            Symbol name (string tbl index)
 *   unsigned char st_info;         Symbol type and binding
 *   unsigned char st_other;        Symbol visibility
 *   Elf64_Section st_shndx;        Section index
 *   Elf64_Addr	st_value;           Symbol value
 *   Elf64_Xword st_size;           Symbol size
 * } Elf64_Sym;
 *
 * The field st_value is offset of the symbol in the object file.
 */
static void
find_jumps_in_section_syms(struct intercept_desc *desc, Elf64_Shdr *section,
				int fd)
{
	assert(section->sh_type == SHT_SYMTAB ||
		section->sh_type == SHT_DYNSYM);

	size_t sym_count = section->sh_size / sizeof(Elf64_Sym);

	Elf64_Sym syms[sym_count];

	xlseek(fd, section->sh_offset, SEEK_SET);
	xread(fd, &syms, section->sh_size);

	for (size_t i = 0; i < sym_count; ++i) {
		if (ELF64_ST_TYPE(syms[i].st_info) != STT_FUNC)
			continue; /* it is not a function */

		if (syms[i].st_shndx != desc->text_section_index)
			continue; /* it is not in the text section */

		debug_dump("jump target: %lx\n",
		    (unsigned long)syms[i].st_value);

		unsigned char *address = desc->base_addr + syms[i].st_value;

		/* a function entry point in .text, mark it */
		mark_jump(desc, address);

		/* a function's end in .text, mark it */
		if (syms[i].st_size != 0)
			mark_jump(desc, address + syms[i].st_size);
	}
}

/*
 * find_jumps_in_section_rela - look for offsets in relocation entries
 *
 * The constant SHT_RELA refers to "Relocation entries with addends" -- see the
 * elf.h header file.
 *
 * The format of the entries:
 *
 * typedef struct
 * {
 *   Elf64_Addr	r_offset;      Address
 *   Elf64_Xword r_info;       Relocation type and symbol index
 *   Elf64_Sxword r_addend;    Addend
 * } Elf64_Rela;
 *
 */
static void
find_jumps_in_section_rela(struct intercept_desc *desc, Elf64_Shdr *section,
				int fd)
{
	assert(section->sh_type == SHT_RELA);

	size_t sym_count = section->sh_size / sizeof(Elf64_Rela);

	Elf64_Rela syms[sym_count];

	xlseek(fd, section->sh_offset, SEEK_SET);
	xread(fd, &syms, section->sh_size);

	for (size_t i = 0; i < sym_count; ++i) {
		switch (ELF64_R_TYPE(syms[i].r_info)) {
			case R_X86_64_RELATIVE:
			case R_X86_64_RELATIVE64:
				/* Relocation type: "Adjust by program base" */

				debug_dump("jump target: %lx\n",
				    (unsigned long)syms[i].r_addend);

				unsigned char *address =
				    desc->base_addr + syms[i].r_addend;

				mark_jump(desc, address);

				break;
		}
	}
}

static void
init_syscall_filter(void)
{
	const char *filter = NULL;
	filter_incl = getenv("INTERCEPT_SYS_INCLUDE");
	filter_excl = getenv("INTERCEPT_SYS_EXCLUDE");

	if (filter_incl && filter_excl)
		xabort(__func__, "INTERCEPT_SYS_INCLUDE and INTERCEPT_SYS_EXCLUDE "
			"are mutually exclusive");
	else if (filter_incl)
		filter = filter_incl;
	else if (filter_excl)
		filter = filter_excl;
	else
		return;

	if (filter[0] == '\0')
		return;

	// get the size of an input and the number of syscalls
	size_t filter_len = 0;
	size_t sys_num = 1;
	for (; filter[filter_len]; ++filter_len)
		if (filter[filter_len] == ',' && filter[filter_len+1] != ',')
			++sys_num;

	sys_filter_ptr = malloc(sizeof(int32_t) * (sys_num + 1));
	int sys_i = 0;
	char sys_str[0x100] = {0};
	int sys_str_i = 0;
	char *endptr;
	errno = 0;

	for (size_t i = 0; i <= filter_len; ++i) {
		if (filter[i] == ',' || filter[i] == '\0') {
			// repeated ',' or an input starts with it
			if (sys_str_i == 0)
				continue;

			sys_str[sys_str_i] = '\0';
			int32_t syscall_num = (int32_t)strtol(sys_str, &endptr, 10);

			if (errno == ERANGE)
				xabort_errno(ERANGE, __func__, strerror_no_intercept(ERANGE));
			else if (*endptr == '\0')
				sys_filter_ptr[sys_i] = syscall_num;
			else if (!strncmp(sys_str, "SYS_", 4))
				sys_filter_ptr[sys_i] = get_syscall_number(sys_str + 4);
			else
				sys_filter_ptr[sys_i] = get_syscall_number(sys_str);

			if (sys_filter_ptr[sys_i] < 0)
				xabort_errno(ENOENT, __func__, "Unknown syscall, "
						"provide a syscall number instead of the name");

			sys_str_i = 0;
			++sys_i;
		} else {
			sys_str[sys_str_i++] = filter[i];
		}
	}

	// mark end of input
	sys_filter_ptr[sys_i] = -1;
}

/*
 * is_not_filtered() uses has_jump() mostly to determine function boundaries.
 * In contrast to patcher.c, which also uses has_jump() to drop the previous a7 value,
 * the jump_table here is still incomplete.
 * The accuracy of this static analysis could be jeopardized if the same ecall is used for
 * different syscalls. For example, a7 gets set to SYS_read, the ecall executes, and afterward
 * a7 gets set to SYS_write and jumps back to the same ecall instruction.
 * This case (where the same ecall is reused by different system calls) is not found in glibc,
 * and that's why filtering is done in this phase, where adding patch structs is being decided.
 */
static inline bool
is_not_filtered(const struct intercept_desc *desc, const struct intercept_disasm_result *surr)
{
	if (!filter_incl && !filter_excl)
		return true;

	int32_t syscall_num = -1;

	for (size_t i = 0; i < SYSCALL_IDX; ++i) {
		if (has_jump(desc, surr[i].address))
			syscall_num = -1;

		if (surr[i].a7_set > -1)
			syscall_num = surr[i].a7_set;
		else if (surr[i].is_a7_modified)
			syscall_num = -1;
	}

	if (syscall_num == -1)
		return true;

	for (size_t i = 0; sys_filter_ptr[i] != -1; ++i) {
		if (sys_filter_ptr[i] == syscall_num)
			return (bool)filter_incl;
	}

	return (bool)filter_excl;
}

static void
free_syscall_filter(void)
{
	if (sys_filter_ptr) {
		free(sys_filter_ptr);
		sys_filter_ptr = NULL;
	}
}

/*
 * has_pow2_count
 * Checks if the positive number of patches in a struct intercept_desc
 * is a power of two or not.
 */
static bool
has_pow2_count(const struct intercept_desc *desc)
{
#ifdef __riscv_zbb
	bool ret;
	__asm__ volatile (
		"cpop %0, %1\n\t"
		"sltiu %0, %0, 2\n\t"
		: "=r" (ret)
		: "r" (desc->count)
	);
	return ret;
#else
	return (desc->count & (desc->count - 1)) == 0;
#endif
}

/*
 * add_new_patch
 * Acquires a new patch entry, and allocates memory for it if
 * needed.
 */
static struct patch_desc *
add_new_patch(struct intercept_desc *desc)
{
	if (desc->count == 0) {

		/* initial allocation */
		desc->items = xmmap_anon(sizeof(desc->items[0]));

	} else if (has_pow2_count(desc)) {

		/* if count is a power of two, double the allocate space */
		size_t size = desc->count * sizeof(desc->items[0]);

		desc->items = xmremap(desc->items, size, 2 * size);
	}

	return &(desc->items[desc->count++]);
}

static void
fill_up_patch(struct intercept_desc *desc, struct patch_desc *patch,
		struct intercept_disasm_result surr[], uint8_t syscall_idx)
{
	size_t surr_size = sizeof(struct intercept_disasm_result) *
				SURROUNDING_INSTRS_NUM;

	patch->containing_lib_path = desc->path;

	/*
	 * Using malloc/free should be safe when used before patching any
	 * library (including glibc), which happens in activate_patches()
	 * (patcher.c). If it is unsafe, SYS_brk or mmap can be used instead.
	 * This gets freed in create_patch(), patcher.c.
	 */
	patch->surrounding_instrs =
		(struct intercept_disasm_result *)malloc(surr_size);
	memcpy(patch->surrounding_instrs, surr, surr_size);

	patch->syscall_addr = surr[syscall_idx].address;

	ptrdiff_t syscall_offset = patch->syscall_addr -
	    (desc->text_start - desc->text_offset);

	assert(syscall_offset >= 0);

	patch->syscall_offset = (uint64_t)syscall_offset;
	patch->syscall_idx = syscall_idx;

    // Calculate syscall number to filter rt_sigreturn
    int32_t syscall_num = -1;
	for (size_t i = 0; i < syscall_idx; ++i) {
		if (has_jump(desc, surr[i].address))
			syscall_num = -1;

		if (surr[i].a7_set > -1)
			syscall_num = surr[i].a7_set;
		else if (surr[i].is_a7_modified)
			syscall_num = -1;
	}

    // Default to GP_COMPLETE for now, as we use global trampoline.
    patch->syscall_num = TYPE_GP_COMPLETE; 

    if (syscall_num != -1) {
         // Only patch identified syscalls (set type to GP_COMPLETE)
         patch->syscall_num = TYPE_GP_COMPLETE;
    } else {
         // Skip patching unknowns to avoid hitting rt_sigreturn
         patch->syscall_num = 999;
    }

    // Safety check for rt_sigreturn (139) used by libc
    if (syscall_num == 139) {
        patch->syscall_num = 139; // This will cause activate_patches to skip it
    }
}

/*
 * crawl_text
 * Crawl the text section, disassembling it all.
 * This routine collects information about potential addresses to patch.
 *
 * The addresses of all syscall instructions are stored, together with
 * a description of the preceding, and following instructions.
 *
 * A lookup table of all addresses which appear as jump destination is
 * generated, to help determine later, whether an instruction is suitable
 * for being overwritten -- of course, if an instruction is a jump destination,
 * it can not be merged with the preceding instruction to create a
 * new larger one.
 *
 * Note: The actual patching can not yet be done in this disassembling phase,
 * as it is not known in advance, which addresses are jump destinations.
 */
static void
crawl_text(struct intercept_desc *desc)
{
	uint8_t *code = desc->text_start;
    char buf[256];
    // Simple hex conversion for logging without printf
    // syscall_no_intercept(SYS_write, 2, "Crawl text start\n", 17);
    (void)buf;

	uint8_t instrs_num = SURROUNDING_INSTRS_NUM;

	/*
	 * Store results of n surrounding instructions (SURROUNDING_INSTRS_NUM).
	 * The RISC-V version of this library can patch any ecall, even if it
	 * appears at the beginning or at the end of the .text section.
	 */
	struct intercept_disasm_result surr[SURROUNDING_INSTRS_NUM] = {{0}};

	struct intercept_disasm_context *context =
	    intercept_disasm_init(desc->text_start, desc->text_end);

	while (code <= desc->text_end) {
		struct intercept_disasm_result result;

		result = intercept_disasm_next_instruction(context, code);

		if (result.length == 0) {
			++code;
			continue;
		}

		if (result.has_ip_relative_opr)
			mark_jump(desc, result.rip_ref_addr);

        if (surr[SYSCALL_IDX].is_syscall) {
            bool ok = is_not_filtered(desc, surr);
            if (ok) {
			    struct patch_desc *patch = add_new_patch(desc);
			    fill_up_patch(desc, patch, surr, SYSCALL_IDX);
            }
		}

		// shift each element to the left (decrement), FIFO
		memmove(surr, surr + 1, (instrs_num - 1) *
			sizeof(struct intercept_disasm_result));
		surr[instrs_num - 1] = result;

		code += result.length;
	}

	/*
	 * Last instrs in .text (from SYSCALL_IDX to the end of .text)
	 * could not be checked for ecall before, so it is done here
	 */
	for (uint8_t i = SYSCALL_IDX; i < instrs_num; ++i) {
		if (!surr[i].is_syscall)
			continue;

		uint8_t offset = i - SYSCALL_IDX;

		if (offset > 0) {
			// centralize ecall
			memmove(surr, surr + offset, (instrs_num - offset) *
				sizeof(struct intercept_disasm_result));

			// unset redundant last surr instrs
			memset(surr + (instrs_num - offset), 0, offset *
				sizeof(struct intercept_disasm_result));
		}

		if (is_not_filtered(desc, surr)) {
			struct patch_desc *patch = add_new_patch(desc);
			fill_up_patch(desc, patch, surr, i);
		}
	}

	intercept_disasm_destroy(context);
}

/*
 * get_min_address
 * Looks for the lowest address that might be mmap-ed. This is
 * useful while looking for space for a trampoline table close
 * to some text section.
 */

void
allocate_trampoline(struct intercept_desc *desc)
{
    if (desc->trampoline_address != NULL) {
        desc->uses_trampoline = true;
        return;
    }

	/*
	 * If trampoline_address is still NULL, it means no local slot was found.
	 * TYPE_JAL patches will be ignored, but TYPE_GP might still work if
	 * GP register is somehow valid (though currently mostly unsupported).
	 */
	desc->uses_trampoline = (desc->trampoline_address != NULL);
}


/*
 * find_syscalls
 * The routine that disassembles a text section. Here is some higher level
 * logic for finding syscalls, finding overwritable NOP instructions, and
 * finding out what instructions around syscalls can be overwritten or not.
 * This code is intentionally independent of the disassembling library used,
 * such specific code is in wrapper functions in the disasm_wrapper.c source
 * file.
 */
void
find_syscalls(struct intercept_desc *desc)
{
    syscall_no_intercept(SYS_write, 2, "Entering find_syscalls\n", 23);
	debug_dump("find_syscalls in %s "
	    "at base_addr 0x%016" PRIxPTR "\n",
	    desc->path,
	    (uintptr_t)desc->base_addr);

	desc->count = 0;

	int fd = open_orig_file(desc);

	find_sections(desc, fd);
	debug_dump(
	    "%s .text mapped at 0x%016" PRIxPTR " - 0x%016" PRIxPTR " \n",
	    desc->path,
	    (uintptr_t)desc->text_start,
	    (uintptr_t)desc->text_end);
	allocate_jump_table(desc);

	for (Elf64_Half i = 0; i < desc->symbol_tables.count; ++i) {
        syscall_no_intercept(SYS_write, 2, "Scanning symbol table...\n", 25);
		find_jumps_in_section_syms(desc,
		    desc->symbol_tables.headers + i, fd);
    }

	for (Elf64_Half i = 0; i < desc->rela_tables.count; ++i)
		find_jumps_in_section_rela(desc,
		    desc->rela_tables.headers + i, fd);

	syscall_no_intercept(SYS_close, fd);

	init_syscall_filter();

	crawl_text(desc);

	free_syscall_filter();
}
