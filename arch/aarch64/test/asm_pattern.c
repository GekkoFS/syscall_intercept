/*
 * Copyright 2017, Intel Corporation
 * asm_pattern.c COPYRIGHT FUJITSU LIMITED 2019
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
 * This program can be used to test certain instruction level details
 * of disassembling/patching the text section of a library.
 * One needs an 'input' and an 'expected output' library as two
 * shared objects in order to perform a comparison between what
 * syscall_intercept's patching results in, and what the result should be.
 * The paths of these two libraries are expected to be supplied as command
 * line arguments.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "libsyscall_intercept_hook_point.h"

#include "intercept.h"

struct find_sym_desc {
	const char *name; /* symbol name to search */
	void **ptr; /* address to pointer type to put result */
};
#define FIND_SYM_DESC_ENT(_name) {.name = #_name, .ptr = (void **)&_name##_ptr }

/*
 * find_symbol_addr - find the address of the desc[N].name
 *                    in the ELF binary indicated by the path.
 */
static void
find_symbol_addr(const char *path,
			struct find_sym_desc *desc,
			size_t nr_desc)
{
	int fd = open(path, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr,
			"error file open: %s\n",
			path);
		exit(EXIT_FAILURE);
	}

	Elf64_Ehdr ehdr;
	read(fd, &ehdr, sizeof(ehdr));

	Elf64_Shdr shdrs[ehdr.e_shnum * sizeof(Elf64_Shdr)];
	lseek(fd, ehdr.e_shoff, SEEK_SET);
	read(fd, shdrs, sizeof(shdrs));

	char section_string[shdrs[ehdr.e_shstrndx].sh_size];
	lseek(fd, shdrs[ehdr.e_shstrndx].sh_offset, SEEK_SET);
	read(fd, section_string, sizeof(section_string));

	Elf64_Shdr *symtab = NULL;
	Elf64_Shdr *strtab = NULL;
	for (Elf64_Half i = 0; i < ehdr.e_shnum; ++i) {
		Elf64_Shdr *shdr = &shdrs[i];
		const char *shname = section_string + shdr->sh_name;
		if (strcmp(".symtab", shname) == 0) {
			symtab = shdr;
		} else if (strcmp(".strtab", shname) == 0) {
			strtab = shdr;
		}
	}
	if (symtab == NULL) {
		fprintf(stderr,
			"error can not find .symtab: %s\n",
			path);
		exit(EXIT_FAILURE);
	}
	if (strtab == NULL) {
		fprintf(stderr,
			"error can not find .strtab: %s\n",
			path);
		exit(EXIT_FAILURE);
	}

	char symbol_string[strtab->sh_size];
	lseek(fd, strtab->sh_offset, SEEK_SET);
	read(fd, symbol_string, sizeof(symbol_string));

	lseek(fd, symtab->sh_offset, SEEK_SET);
	for (Elf64_Word size = 0;
		size < symtab->sh_size;
		size += sizeof(Elf64_Sym)) {
		Elf64_Sym sym;
		read(fd, &sym, sizeof(Elf64_Sym));
		if (!sym.st_name) {
			continue;
		}

		const char *symname = symbol_string + sym.st_name;
		for (size_t i = 0; i < nr_desc; i++) {
			if (strcmp(symname, desc[i].name) == 0) {
				*desc[i].ptr = (void *)sym.st_value;
				break;
			}
		}
	}
	close(fd);
}

/*
 * All test libraries are expected to provide the following symbols:
 * mock_asm_wrapper, mock_asm_wrapper_end - the mock asm wrapper space
 *                                          using while patching
 * text_start, text_end - symbols that help this program find the
 *				text section of the shared object
 *
 * The lib_data struct is used to describe a shared library loaded
 * for testing.
 */
struct lib_data {
	Dl_info info;
	unsigned char *mock_asm_wrapper;
	unsigned char *mock_asm_wrapper_end;
	const unsigned char *text_start;
	const unsigned char *text_end;
	size_t text_size;
};

/*
 * xdlsym - no-fail wrapper around dlsym
 */
static void *
xdlsym(void *lib, const char *name, const char *path)
{
	void *symbol = dlsym(lib, name);
	if (symbol == NULL) {
		fprintf(stderr,
		    "\"%s\" not found in %s: %s\n",
		    name, path, dlerror());
		exit(EXIT_FAILURE);
	}

	return symbol;
}

/*
 * Load a shared object into this process's address space, and set up
 * a lib_data struct to be used later while testing.
 * This same routine is used to load an 'input' library, and
 * an 'expected output' library.
 */
static struct lib_data
load_test_lib(const char *path)
{
	struct lib_data data;

	void *lib = dlopen(path, RTLD_LAZY);
	if (lib == NULL) {
		fprintf(stderr, "error loading \"%s\": %s\n",
		    path, dlerror());
		exit(EXIT_FAILURE);
	}

	data.mock_asm_wrapper = xdlsym(lib, "mock_asm_wrapper", path);

	if ((!dladdr(data.mock_asm_wrapper, &data.info)) ||
	    (data.info.dli_fname == NULL) ||
	    (data.info.dli_fbase == NULL)) {
		fprintf(stderr,
		    "error querying dlinfo for %s: %s\n",
		    path, dlerror());
		exit(EXIT_FAILURE);
	}

	data.mock_asm_wrapper_end = xdlsym(lib, "mock_asm_wrapper_end", path);

	if (data.mock_asm_wrapper_end <= data.mock_asm_wrapper) {
		fprintf(stderr,
		    "mock_asm_wrapper invalid in %s: \"%s\"\n",
		    path, dlerror());
		exit(EXIT_FAILURE);
	}

	data.text_start = xdlsym(lib, "text_start", path);
	data.text_end = xdlsym(lib, "text_end", path);

	if (data.text_start >= data.text_end) {
		fprintf(stderr, "text_start <= text_end in %s\n", path);
		exit(EXIT_FAILURE);
	}

	data.text_size = data.text_end - data.text_start;

	return data;
}

/*
 * check_patch - binary comparison of text sections
 * This routine compares each byte in the text section of the 'input'
 * library and the 'expected output library' -- after the input library
 * has been patched.
 *
 * If a difference is found, it prints both text sections, highlighting
 * the differences.
 */
static void
check_patch(const struct lib_data *in, const struct lib_data *out)
{
	if (memcmp(in->text_start, out->text_start, in->text_size) == 0)
		return;

	fputs("Invalid patch\n", stderr);

	const unsigned char *text = in->text_start;
	const unsigned char *expected = out->text_start;
	size_t count = in->text_size;

	fputs("patch vs. expected:\n", stderr);
	while (count > 0) {
		fprintf(stderr,
		    "0x%04zx: 0x%02hhx 0x%02hhx%s\n",
		    text - in->text_start,
		    *text, *expected, (*text == *expected) ? "" : " <-");
		++text;
		++expected;
		--count;
	}

	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	unsigned char **asm_wrapper_space_begin_ptr = NULL;
	unsigned char **next_asm_wrapper_space_ptr = NULL;
	unsigned char **asm_wrapper_space_end_ptr = NULL;

	struct find_sym_desc sym_desc[] = {
		FIND_SYM_DESC_ENT(asm_wrapper_space_begin),
		FIND_SYM_DESC_ENT(next_asm_wrapper_space),
		FIND_SYM_DESC_ENT(asm_wrapper_space_end),
	};
	size_t nr_sym_desc = sizeof(sym_desc) / sizeof(sym_desc[0]);

	if (argc < 3)
		return EXIT_FAILURE;

	debug_dumps_on = getenv("INTERCEPT_DEBUG_DUMP") != NULL;

	/* first load both libraries */
	struct lib_data lib_in = load_test_lib(argv[1]);
	struct lib_data lib_out = load_test_lib(argv[2]);

	if (lib_in.text_size != lib_out.text_size) {
		fprintf(stderr,
		    "text_size mismatch for %s(%zu) and %s(%zu)\n",
		    argv[1], lib_in.text_size, argv[2], lib_out.text_size);
		exit(EXIT_FAILURE);
	}

	/*
	 * Initialize syscall_intercept -- this initialization is usually
	 * done in the routine called intercept in the intercept.c source
	 * file.
	 */
	struct intercept_desc patches;
	init_patcher();
	find_symbol_addr(argv[0], sym_desc, nr_sym_desc);
	for (size_t i = 0; i < nr_sym_desc; i++) {
		if (*sym_desc[i].ptr == NULL) {
			fprintf(stderr,
				"symbol '%s' is not found.\n",
				sym_desc[i].name);
			exit(EXIT_FAILURE);
		}
	}
	*asm_wrapper_space_begin_ptr = lib_in.mock_asm_wrapper;
	*asm_wrapper_space_end_ptr = lib_in.mock_asm_wrapper_end;
	*next_asm_wrapper_space_ptr = *asm_wrapper_space_begin_ptr;

	/*
	 * Some more information about the library to be patched, normally
	 * these variables would refer to libc.
	 */
	patches.base_addr = lib_in.info.dli_fbase;
	patches.path = lib_in.info.dli_fname;
	patches.uses_trampoline_table = false;
	patches.trampoline_table = NULL;
	patches.trampoline_table_size = 0;
	patches.next_trampoline = patches.trampoline_table;

	/* perform the actually patching */
	find_syscalls(&patches);
	create_patch_wrappers(&patches);
	mprotect_asm_wrappers();
	activate_patches(&patches);

	/* compare the result of patching with the expected result */
	check_patch(&lib_in, &lib_out);

	return EXIT_SUCCESS;
}

/*
 * syscall_hook_in_process_allowed - this symbol must be provided to
 * be able to link with syscall_intercept's objects (other then the one
 * created from cmdline_filter.c).
 * This symbol is referenced from intercept.c,
 * defined once in cmdline_filter.c, and defined here as well.
 *
 * Note: this function is actually never called in this test.
 */
int
syscall_hook_in_process_allowed(void)
{
	return 0;
}
