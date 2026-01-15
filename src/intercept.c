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


/*
 * intercept.c - The entry point of libsyscall_intercept, and some of
 * the main logic.
 *
 * intercept() - the library entry point
 * intercept_routine() - the entry point for each hooked syscall
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define DEBUG 0
#include <assert.h>
#include <stdbool.h>
#include <elf.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <unistd.h>
#include <limits.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <sys/auxv.h>
#include <linux/sched.h>

#include "intercept.h"
#include "intercept_log.h"
#include "intercept_util.h"
#include "../include/libsyscall_intercept_hook_point.h"
#include "disasm_wrapper.h"
#include "magic_syscalls.h"

extern void asm_entry_point(void);

// ... existing unhandled syscalls ...

static struct intercept_desc *objs = NULL;
static size_t objs_count = 0;
static size_t objs_capacity = 0; // Restored
// static char static_objs[...] // Removed

/*
 * allocate_next_obj_desc - allocates a new object descriptor
 */
#include <string.h>
#include <syscall.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <sys/auxv.h>
#include <linux/sched.h>

#include "intercept.h"
#include "intercept_log.h"
#include "intercept_util.h"
#include "../include/libsyscall_intercept_hook_point.h"
#include "disasm_wrapper.h"
#include "magic_syscalls.h"

extern void asm_entry_point(void);

/*
 * Unhandled syscalls: syscalls that are not handled in this TU, but
 * intercept_irq_entry handles them.
 * To preserve both syscall return values (a0/a1), these macros are placed in
 * an a0/a1 register (struct wrapper_ret) to signify unhandled syscall and the
 * type to intercept_irq_entry.
 * - UNH_SYSCALL goes in a0 for both generic and clone type.
 * - UNH_GENERIC can be any syscall that this library cannot or should not
 *   intercept. Currently, only SYS_rt_sigreturn.
 * - UNH_CLONE all clones that have allocated stack space for a child process.
 *
 * Values are chosen based on the syscall's error code convention and the
 * unlikeliness of colliding with actual syscall return values.
 * E.g., the way glibc checks for errors after ecall indicates acceptable minimum:
 * (...)
 * ecall
 * c.lui   a5,0xfffff       <--- a5 = -0x1000
 * bltu    a5,a0,ba786      <--- check if a0 in between 0 and -0x1000
 * (...)
 */
#define UNH_SYSCALL	((int64_t)-0x1000)
#define UNH_GENERIC	((int64_t)-0x1001)
#define UNH_CLONE	((int64_t)-0x1002)
#define UNH_CLONE	((int64_t)-0x1002)

int (*intercept_hook_point)(long syscall_number,
			long arg0, long arg1,
			long arg2, long arg3,
			long arg4, long arg5,
			long *result)
	__attribute__((visibility("default")));

void (*intercept_hook_point_clone_child)(
			unsigned long flags, void *child_stack,
			int *ptid, int *ctid,
			long newtls)
	__attribute__((visibility("default")));
void (*intercept_hook_point_clone_parent)(
			unsigned long flags, void *child_stack,
			int *ptid, int *ctid,
			long newtls, long returned_pid)
	__attribute__((visibility("default")));

void (*intercept_hook_point_post_kernel)(long syscall_number,
			long arg0, long arg1,
			long arg2, long arg3,
			long arg4, long arg5,
			long result)	
	__attribute__((visibility("default")));





void
debug_dump(const char *fmt, ...)
{
#if DEBUG
	va_list ap;
	char buf[1024];

	va_start(ap, fmt);
	int len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (len > 0) {
        size_t write_len = (size_t)len;
        if (write_len >= sizeof(buf))
            write_len = sizeof(buf) - 1;
		syscall_no_intercept(SYS_write, 2, buf, write_len);
    }
#else
    (void)fmt;
#endif
}

static bool logging_enabled;


/* Should all objects be patched, or only libc and libpthread? */
static bool patch_all_objs;

/*
 * Information collected during disassemble phase, and anything else
 * needed for hotpatching are stored in this dynamically allocated
 * array of structs.
 * The number currently allocated is in the objs_count variable.
 */

/* was libc found while looking for loaded objects? */
static bool libc_found;

/* address of [vdso] */
static void *vdso_addr;

/*
 * allocate_next_obj_desc
 * Handles the dynamic allocation of the struct intercept_desc array.
 * Returns a pointer to a newly allocated item.
 */
static struct intercept_desc *
allocate_next_obj_desc(void)
{
	struct intercept_desc *new_desc;

	if (objs != NULL) {
		if (objs_count == objs_capacity) {
			new_desc = xmremap(objs,
			    objs_capacity * sizeof(struct intercept_desc),
			    objs_capacity * 2 *
			    sizeof(struct intercept_desc));
			objs_capacity *= 2;
			objs = new_desc;
		}
	} else {
		objs = xmmap_anon(sizeof(struct intercept_desc));
		objs_capacity = 1;
	}

	++objs_count;
	new_desc = objs + objs_count - 1;
	return new_desc;
}

/*
 * get_lib_short_name - find filename in path containing directories.
 */
static const char *
get_lib_short_name(const char *name)
{
	const char *slash = strrchr(name, '/');
	if (slash != NULL)
		name = slash + 1;

	return name;
}

/*
 * str_match - matching library names.
 * The first string (name) is not null terminated, while
 * the second string (expected) is null terminated.
 * This allows matching e.g.: "libc-2.25.so\0" with "libc".
 * If name_len is 4, the comparison is between: "libc" and "libc".
 */
static bool
str_match(const char *name, size_t name_len,
		const char *expected)
{
	return name_len == strlen(expected) &&
		strncmp(name, expected, name_len) == 0;
}

/*
 * get_name_from_proc_maps
 * Tries to find the path of an object file loaded at a specific
 * address.
 *
 * The paths found are stored in BSS, in the paths variable. The
 * returned pointer points into this variable. The next_path
 * pointer keeps track of the already "allocated" space inside
 * the paths array.
 */
static const char *
get_name_from_proc_maps(uintptr_t addr)
{
	static char paths[0x10000];
	static char *next_path = paths;
	const char *path = NULL;

	char line[0x2000];
	FILE *maps;

	if ((next_path >= paths + sizeof(paths) - sizeof(line)))
		return NULL; /* No more space left */

	if ((maps = fopen("/proc/self/maps", "r")) == NULL)
		return NULL;

	while ((fgets(line, sizeof(line), maps)) != NULL) {
		unsigned char *start;
		unsigned char *end;

		/* Read the path into next_path */
		if (sscanf(line, "%p-%p %*s %*x %*x:%*x %*u %s",
		    (void **)&start, (void **)&end, next_path) != 3)
			continue;
        
		if (addr < (uintptr_t)start)
			break;

		if ((uintptr_t)start <= addr && addr < (uintptr_t)end) {
			/*
			 * Object found, setting the return value.
			 * Adjusting the next_path pointer to point past the
			 * string found just now, to the unused space behind it.
			 * The next string found (if this routine is called
			 * again) will be stored there.
			 */
			path = next_path;
			next_path += strlen(next_path) + 1;
			break;
		}
	}

	fclose(maps);

	return path;
}

/*
 * get_any_used_vaddr - find a virtual address that is expected to
 * be a used for the object file mapped into memory.
 *
 * An Elf64_Phdr struct contains information about a segment in an on object
 * file. This routine looks for a segment with type LOAD, that has a non-zero
 * size in memory. The p_vaddr field contains the virtual address where this
 * segment should be loaded to. This of course is relative to the base address.
 *
 * typedef struct
 * {
 *   Elf64_Word p_type;			Segment type
 *   Elf64_Word p_flags;		Segment flags
 *   Elf64_Off p_offset;		Segment file offset
 *   Elf64_Addr p_vaddr;		Segment virtual address
 *   Elf64_Addr p_paddr;		Segment physical address
 *   Elf64_Xword p_filesz;		Segment size in file
 *   Elf64_Xword p_memsz;		Segment size in memory
 *   Elf64_Xword p_align;		Segment alignment
 * } Elf64_Phdr;
 *
 *
 */
static uintptr_t
get_any_used_vaddr(const struct dl_phdr_info *info)
{
	const Elf64_Phdr *pheaders = info->dlpi_phdr;

	for (Elf64_Word i = 0; i < info->dlpi_phnum; ++i) {
		if (pheaders[i].p_type == PT_LOAD && pheaders[i].p_memsz != 0)
			return info->dlpi_addr + pheaders[i].p_vaddr;
	}

	return 0; /* not found */
}

/*
 * get_object_path - attempt to find the path of the object in the
 * filesystem.
 *
 * This is usually supplied by dl_iterate_phdr in the dl_phdr_info struct,
 * but sometimes that does not contain it.
 */
static const char *
get_object_path(const struct dl_phdr_info *info)
{
	if (info->dlpi_name != NULL && info->dlpi_name[0] != '\0') {
		return info->dlpi_name;
	} else {
		uintptr_t addr = get_any_used_vaddr(info);
		if (addr == 0)
			return NULL;
		return get_name_from_proc_maps(addr);
	}
}

static bool
is_vdso(uintptr_t addr, const char *path)
{
	return addr == (uintptr_t)vdso_addr || strstr(path, "vdso") != NULL;
}

/*
 * should_patch_object
 * Decides whether a particular loaded object should should be targeted for
 * hotpatching.
 * Always skipped: [vdso], and the syscall_intercept library itself.
 * Besides these two, if patch_all_objs is true, everything object is
 * a target. When patch_all_objs is false, only libraries that are parts of
 * the glibc implementation are targeted, i.e.: libc and libpthread.
 */
static bool
should_patch_object(uintptr_t addr, const char *path)
{
	static uintptr_t self_addr;
	if (self_addr == 0) {
		extern uint8_t asm_relocation_space[];
		Dl_info self;
		if (!dladdr(asm_relocation_space, &self))
			xabort(__func__, "self dladdr failure");
		self_addr = (uintptr_t)self.dli_fbase;
	}

	static const char libc[] = "libc";
	static const char pthr[] = "libpthread";
	static const char caps[] = "libcapstone";

	if (is_vdso(addr, path)) {
		debug_dump(" - skipping: is_vdso\n");
		return false;
	}

	const char *name = get_lib_short_name(path);
	size_t len = strcspn(name, "-.");

	if (len == 0)
		return false;

	if (addr == self_addr) {
		debug_dump(" - skipping: matches self\n");
		return false;
	} else {
    }

    if (strstr(name, "libsyscall_logger")) {
        return false;
    }


	if (str_match(name, len, caps)) {
		debug_dump(" - skipping: matches capstone\n");
		return false;
	}

	if (str_match(name, len, libc)) {
		debug_dump(" - libc found\n");
		libc_found = true;
		return true;
	} else {
    }

	if (patch_all_objs)
		return true;

	if (str_match(name, len, pthr)) {
		debug_dump(" - libpthread found\n");
		return true;
	}

	debug_dump(" - skipping, patch_all_objs == false\n");
	return false;
}

// Forward declarations
struct intercept_desc;
struct intercept_desc *allocate_next_obj_desc(void);

static void
alloc_trampoline_in_object(struct intercept_desc *desc, struct dl_phdr_info *info)
{

    // Search for a suitable writable segment close to text
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];
        
        if (phdr->p_type == PT_LOAD && (phdr->p_flags & PF_W)) {
            uintptr_t seg_start = info->dlpi_addr + phdr->p_vaddr;
            uintptr_t seg_end = seg_start + phdr->p_memsz;
            
            if (!desc->text_start) {
                 continue;
            }
            
            // Check distance to text
            int64_t diff = (int64_t)seg_start - (int64_t)desc->text_start;
            // Conservative 1.8GB range
            if (diff > 0x70000000 || diff < -0x70000000) {
                 diff = (int64_t)seg_end - (int64_t)desc->text_start;
                 if (diff > 0x70000000 || diff < -0x70000000) {
                      continue; 
                 }
            }
            
            // Scan for 32 bytes of zeros
            // aligned to 8 bytes
            for (uintptr_t curr = seg_start; curr <= seg_end - 32; curr += 8) {
                bool empty = true;
                uint64_t *ptr = (uint64_t *)curr;
                if (ptr[0] != 0 || ptr[1] != 0 || ptr[2] != 0 || ptr[3] != 0) empty = false;
                
                if (empty) {
                    desc->trampoline_address = (uint8_t *)curr;
                    
                    // Make executable
                    uintptr_t page = curr & ~(PAGE_SIZE - 1);
                    long res_s = syscall_no_intercept(SYS_mprotect, page, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
                    if (res_s != 0) {
                        return; // Or continue searching?
                    }
                    
                    // Write trampoline
                    // 1. addi sp, sp, -48 (PATCH_SP_OFF)
                    // 2. sd ra, 0(sp) (ORIG_RA_OFF)
                    // 3. sd t0, 40(sp) (UNUSED_OFF2 - JAL return addr)
                    // 4. jump to asm_entry_point
                    
                    extern void asm_entry_point(void);
                    uint8_t buff[64];
                    unsigned int size = 0;
                    
                    // addi sp, sp, -48
                    size += rv_addi(buff + size, REG_SP, REG_SP, -48);
                    
                    // sd ra, 0(sp)
                    size += rv_sd(buff + size, REG_RA, REG_SP, 0);
                    
                    // sd t0, 32(sp) (UNUSED_OFF1)
                    size += rv_sd(buff + size, REG_T0, REG_SP, 32);
                    // sd t0, 16(sp) (RET_ADDR_OFF) - Required for intercept_routine logic
                    size += rv_sd(buff + size, REG_T0, REG_SP, 16);
                    
                    // jump to asm_entry_point
                    // using t1 (6) as scratch
                    size += rvp_jump_abs(buff + size, 0, 6, (uintptr_t)asm_entry_point); 
                    
                    uint8_t *tramp = desc->trampoline_address;
                    for(unsigned int k=0; k<size; ++k) tramp[k] = buff[k];
                    
                    __builtin___clear_cache((char *)tramp, (char *)tramp + 64);
                    return;
                }
            }
            // syscall_no_intercept(SYS_write, 2, "DEBUG: Segment full, no empty slot\n", 35);
        }
    }
    
}

/*
 * analyze_object
 * Look at a library loaded into the current process, and determine as much as
 * possible about it. The disassembling, allocations are initiated here.
 *
 * This is a callback function, passed to dl_iterate_phdr(3).
 * data and size are just unused callback arguments.
 *
 *
 * From dl_iterate_phdr(3) man page:
 *
 * struct dl_phdr_info
 * {
 *     ElfW(Addr) dlpi_addr;             Base address of object
 *     const char *dlpi_name;            (Null-terminated) name of object
 *     const ElfW(Phdr) *dlpi_phdr;      Pointer to array of ELF program headers
 *     ElfW(Half) dlpi_phnum;            # of items in dlpi_phdr
 *     ...
 * }
 *
 */
static int
analyze_object(struct dl_phdr_info *info, size_t size, void *data);

static int
analyze_object(struct dl_phdr_info *info, size_t size, void *data)
{
	(void) data;
	(void) size;
	const char *path;
    struct intercept_desc *desc;

	if ((path = get_object_path(info)) == NULL) { 
		/*
		 * It can happen that we can't find the object path
		 * for a mapping. For example, the restricted area
		section of the vdso. In this case, we just skip it.
		 */
		return 0;
	} else {
    }

	desc = allocate_next_obj_desc(); 
	desc->base_addr = (unsigned char *)info->dlpi_addr;
	desc->path = strdup(path);

	if (should_patch_object(info->dlpi_addr, desc->path)) {
        debug_dump("Patching object: %s\n", desc->path);
		find_syscalls(desc);
        alloc_trampoline_in_object(desc, info);
        create_patch(desc);
        if (desc->count > 0)
            activate_patches(desc);
	} else {
        debug_dump("Skipping object: %s\n", desc->path);
		desc->count = 0;
	}

    debug_dump("analyze_object finished on %s \n", desc->path);
	return 0;
}

const char *cmdline;

extern uint8_t asm_relocation_space[];
extern uint64_t asm_relocation_space_size;

/*
 * Enable/disable writing on relocation space (intercept_irq_entry.S).
 */
static void
write_enable_asm_relocation_space(bool enable_write)
{
	int prot;
	const char *err_msg;
	uint8_t *start = round_down_address(asm_relocation_space);
	uint64_t size = asm_relocation_space_size + (uint64_t)(asm_relocation_space - start);

	if (enable_write) {
		prot = PROT_READ | PROT_WRITE | PROT_EXEC;
		err_msg = "asm_relocation_space write enable";
	} else {
		prot = PROT_READ | PROT_EXEC;
		err_msg = "asm_relocation_space write disable";
		__builtin___clear_cache((char *)asm_relocation_space,
					(char *)(asm_relocation_space + asm_relocation_space_size));
	}

	mprotect_no_intercept(start, size, prot, err_msg);
}

/*
 * intercept - This is where the highest level logic of hotpatching
 * is described. Upon startup, this routine looks for libc, and libpthread.
 * If these libraries are found in the process's address space, they are
 * patched.
 *
 * This is init routine of syscall_intercept. This library constructor
 * must be in a TU which also contains public symbols, otherwise linkers
 * might just get rid of the whole object file containing it, when linking
 * statically with libsyscall_intercept.
 */
/*
 * compare_patches - qsort comparator for patch_desc by return_address
 */
static int
compare_patches(const void *a, const void *b)
{
	const struct patch_desc *pa = (const struct patch_desc *)a;
	const struct patch_desc *pb = (const struct patch_desc *)b;

	if (pa->return_address < pb->return_address)
		return -1;
	if (pa->return_address > pb->return_address)
		return 1;
	return 0;
}

static __attribute__((constructor)) void
intercept(int argc, char **argv)
{
	(void) argc;
    cmdline = argv[0];
    static bool init_done = false;
	char *path = NULL;
	extern void init_patcher(long page_size);
	extern void init_tls_offset_table(void);

	/*
	 * This is the constructor invocation -- the very first time
	 * libsyscall_intercept code runs.
	 * Here we must inspect every library that is already loaded, and
	 * patch them.
	 */

	if (init_done)
		return;

	init_done = true;

	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		page_size = 4096;

	extern void init_patcher(long page_size);
	init_patcher(page_size);

	vdso_addr = (void *)(uintptr_t)getauxval(AT_SYSINFO_EHDR);
	patch_all_objs = (getenv("INTERCEPT_ALL_OBJS") != NULL);
	path = getenv("INTERCEPT_LOG");

	logging_enabled = (path != NULL && path[0] != '\0');
	if (logging_enabled) {
		intercept_setup_log(path, getenv("INTERCEPT_LOG_TRUNC"));
	}

	if (!syscall_hook_in_process_allowed()) {
		return;
    }

	dl_iterate_phdr(analyze_object, NULL);

	if (!libc_found)
		xabort("intercept", "libc not found");

	init_tls_offset_table();
	write_enable_asm_relocation_space(true);

	for (uint32_t i = 0; i < objs_count; ++i) {
		if (objs[i].count == 0)
			continue;

		allocate_trampoline(objs + i);
		create_patch(objs + i);

        // Sort patches by return_address for binary_search
        qsort(
            objs[i].items,
            objs[i].count,
            sizeof(struct patch_desc),
            compare_patches
        );
	}

	for (uint32_t i = 0; i < objs_count; ++i) {
		activate_patches(objs + i);
    }
}


/*
 * xabort_errno - print a message to stderr, and exit the process.
 * Calling abort() in libc might result other syscalls being called
 * by libc.
 *
 * If error_code is not zero, it is also printed.
 */



/*
 * xabort_errno - print a message to stderr, and exit the process.
 * Calling abort() in libc might result other syscalls being called
 * by libc.
 *
 * If error_code is not zero, it is also printed.
 */
void
xabort_errno(int error_code, const char *func, const char *msg)
{
	const char main_msg[] = "\033[3;35mlibsyscall_intercept\033[m: \033[1;31mERROR\033[m";
	syscall_no_intercept(SYS_write, 2, main_msg, sizeof(main_msg) - 1);

	if (error_code != 0) {
		char buf[0x20] = " \033[33m(exit code ";
		size_t len = 0;
		char *end = ")\033[m";
		char *ec_str = buf + sizeof(buf) - 1;

		// strlen()
		while (buf[len])
			++len;

		/* not using libc - inline sprintf */
		*ec_str-- = '\0';
		do {
			*ec_str-- = (error_code % 10) + '0';
			error_code /= 10;
		} while (error_code != 0);

		// strcat(), skip first because of previous extra decrement in while loop
		while (*++ec_str)
			buf[len++] = *ec_str;

		// strcat()
		while (*end)
			buf[len++] = *end++;

		syscall_no_intercept(SYS_write, 2, buf, len);
	}

	if (func != NULL) {
		char start[] = ": \033[32m";
		syscall_no_intercept(SYS_write, 2, start, sizeof(start) - 1);

		size_t len = 0;
		while (func[len])
			++len;
		syscall_no_intercept(SYS_write, 2, func, len);

		char end[] = "()\033[m";
		syscall_no_intercept(SYS_write, 2, end, sizeof(end) - 1);
	}

	if (msg != NULL) {
		char start[] = ": ";
		syscall_no_intercept(SYS_write, 2, start, sizeof(start) - 1);

		size_t len = 0;
		while (msg[len])
			++len;
		syscall_no_intercept(SYS_write, 2, msg, len);
	}

	syscall_no_intercept(SYS_write, 2, "\n", 1);

	syscall_no_intercept(SYS_exit_group, 1);

	__builtin_unreachable();
}

/*
 * xabort - print a message to stderr, and exit the process.
 */
void
xabort(const char *func, const char *msg)
{
	xabort_errno(0, func, msg);
}

/*
 * xabort_on_syserror -- examines the return value of syscall_no_intercept,
 * and calls xabort_errno if the said return value indicates an error.
 */
void __attribute__((used))
xabort_on_syserror(long syscall_result, const char *func, const char *msg)
{
	if (syscall_error_code(syscall_result) != 0)
		xabort_errno(syscall_error_code(syscall_result), func, msg);
}


static inline __attribute__((section(".text.irqentry"))) int64_t
binary_search(const struct patch_desc *items, uint32_t count, uint64_t ret_addr)
{
	if (count == 0) return -1;
	int64_t low = 0;
	int64_t high = count - 1;
	int64_t mid;

	while (low <= high) {
		mid = low + (high - low) / 2;

		if ((uint64_t)items[mid].return_address == ret_addr)
			return mid;
		else if ((uint64_t)items[mid].return_address < ret_addr)
			low = mid + 1;
		else
			high = mid - 1;
	}
	return -1;
}

/*
 * When a patch comes to asm_entry_point (intercept_irq_entry.S), one of the
 * first things done is to find its "identity" using its unique return address.
 */


static int64_t
binary_search_fuzzy(const struct patch_desc *items, uint32_t count, uint64_t ret_addr);

__attribute__((section(".text.irqentry"), used)) struct wrapper_ret
detect_cur_patch(uint64_t MID_ret_addr, uint64_t SML_ret_addr, uint64_t GW_ret_addr, uint64_t JAL_ret_addr)
{
    syscall_no_intercept(SYS_write, 2, "DEBUG: JAL_addr=", 16);
    for (int i = 15; i >= 0; --i) {
        int nibble = (JAL_ret_addr >> (i * 4)) & 0xF;
        char c = (nibble < 10) ? ('0' + nibble) : ('a' + nibble - 10);
        syscall_no_intercept(SYS_write, 2, &c, 1);
    }
    syscall_no_intercept(SYS_write, 2, "\n", 1);
    
    const uint64_t check_ret_addrs[4] = {MID_ret_addr, SML_ret_addr, GW_ret_addr, JAL_ret_addr};

	for (uint8_t ra_idx = 0; ra_idx < (sizeof(check_ret_addrs) / sizeof(check_ret_addrs[0])); ++ra_idx) {
		uint64_t ra = check_ret_addrs[ra_idx];
		for (uint32_t o = 0; o < objs_count; ++o) {
			// check if current obj contains the return address
			if (ra < (uint64_t)objs[o].text_start || ra > (uint64_t)objs[o].text_end)
				continue;

			int64_t match_idx = binary_search_fuzzy(objs[o].items, objs[o].count, ra);
			if (match_idx >= 0) {
				const struct patch_desc *patch = objs[o].items + match_idx;
				int64_t sn = (int64_t)patch->syscall_num;
				int64_t reloc_addr = (int64_t)patch->relocation_address;

				switch (sn) {
				case TYPE_GP_COMPLETE:
				case TYPE_GP_FAILSAFE:
					if (ra_idx == 2)
						return (struct wrapper_ret){sn, reloc_addr};
					break;
                case TYPE_JAL:
                    if (ra_idx == 3)
                        return (struct wrapper_ret){sn, reloc_addr};
                    break;
				default:
                    // SML/Other types removed
					break;
				}
			 break;
		}
	}
	}
	
	xabort(__func__, "failed to identify patch");
}




/* 
 * Helper for fuzzy matching (needed for JAL / C.JAL ambiguity)
 */
static int64_t
binary_search_fuzzy(const struct patch_desc *items, uint32_t count, uint64_t ret_addr)
{
	if (count == 0) return -1;
	int64_t low = 0;
	int64_t high = count - 1;
	int64_t mid;

	while (low <= high) {
		mid = low + (high - low) / 2;
        uint64_t addr = (uint64_t)items[mid].return_address;
        
		if (addr == ret_addr)
			return mid;
        // Check fuzzy (handle +/- 2 bytes for instruction alignment differences)
        int64_t diff = (int64_t)ret_addr - (int64_t)addr;
        if (diff >= -2 && diff <= 2) 
            return mid;

		if (addr < ret_addr)
			low = mid + 1;
		else
			high = mid - 1;
	}
	return -1;
}

struct patch_desc *
get_cur_patch(uint64_t return_address)
{
	for (uint32_t o = 0; o < objs_count; ++o) {
        // Relax bounds check slightly for the +2 tolerance
		if (return_address < (uint64_t)objs[o].text_start ||
				return_address > (uint64_t)objs[o].text_end + 4)
			continue;

		int64_t match_idx = binary_search_fuzzy(objs[o].items, objs[o].count, return_address);
		if (match_idx >= 0)
			return objs[o].items + match_idx;
	}
    
    char buf[100];
    snprintf(buf, sizeof(buf), "ERROR: get_cur_patch failed for %lx\n", return_address);
	xabort(__func__, "failed to identify patch");
}

__attribute__((section(".text.irqentry"))) void
intercept_post_clone_log_syscall(int64_t a0, int64_t a1, int64_t a2, int64_t a3,
					int64_t a4, int64_t a5, int64_t a6, int64_t a7)
{
	if (!logging_enabled)
		return;

	const struct patch_desc *patch = get_cur_patch(a6);

	struct syscall_desc desc = {
		.nr = (int)a7, /* ignore higher 32 bits */
		.args[0] = a0,
		.args[1] = a1,
		.args[2] = a2,
		.args[3] = a3,
		.args[4] = a4,
		.args[5] = a5
	};

	intercept_log_syscall(patch, &desc, KNOWN, a0);
}


/*
 * intercept_routine_post_clone
 * The routine called by an assembly wrapper when a clone syscall returns zero,
 * and a new stack pointer is used in the child thread.
 */
__attribute__((section(".text.irqentry"))) void
intercept_routine_post_clone(int64_t a0, int64_t a1, int64_t a2, int64_t a3,
			int64_t a4, int64_t a5, int64_t a6, int64_t a7)
{

	(void) a6;
	struct syscall_desc desc = {
		.nr = (int)a7, /* ignore higher 32 bits */
		.args[0] = a0,
		.args[1] = a1,
		.args[2] = a2,
		.args[3] = a3,
		.args[4] = a4,
		.args[5] = a5
	};
	if (a0 == 0) {
		if (intercept_hook_point_clone_child != NULL)
			intercept_hook_point_clone_child(
					(unsigned long)desc.args[0],
					(void *)desc.args[1],
					(int *)desc.args[2],
					(int *)desc.args[3],
					desc.args[4]);
	} else {
		if (intercept_hook_point_clone_parent != NULL)
			intercept_hook_point_clone_parent(
					(unsigned long)desc.args[0],
					(void *)desc.args[1],
					(int *)desc.args[2],
					(int *)desc.args[3],
					desc.args[4],
					a0);

	}
}

/*
 * intercept_routine(...)
 * This is the function called from the asm wrappers,
 * forwarding the syscall parameters to a hook function
 * if one is present.
 *
 * Arguments:
 * nr, arg0 - arg 5 -- syscall number
 *
 * For logging ( debugging, validating ):
 *
 * syscall_offset -- the offset of the original syscall
 *  instruction in the shared object
 * libpath -- the path of the .so being intercepted,
 *  e.g.: "/usr/lib/libc.so.6"
 *
 * For returning to libc:
 * return_to_asm_wrapper_syscall, return_to_asm_wrapper -- the
 *  address to jump to, when this function is done. The function
 *  is called with a faked return address on the stack ( to aid
 *  stack unwinding ). So, instead of just returning from this
 *  function, one must jump to one of these addresses. The first
 *  one triggers the execution of the syscall after restoring all
 *  registers, and before actually jumping back to the subject library.
 *
 * clone_wrapper -- the address to call in the special case of thread
 *  creation using clone.
 *
 * rsp_in_asm_wrapper -- the stack pointer to restore after returning
 *  from this function.
 */
__attribute__((section(".text.irqentry"))) struct wrapper_ret
intercept_routine(int64_t a0, int64_t a1, int64_t a2, int64_t a3,
			int64_t a4, int64_t a5, int64_t a6, int64_t a7)
{
	/*
	 * SAFEGUARD: RISC-V implementations of intercept_hook_point might expect
	 * to write a struct wrapper_ret (a0, a1) instead of just long (a0),
	 * even if the signature says long*. We provide enough space to avoid
	 * stack smashing.
	 */
	struct wrapper_ret result_safe = {.a0 = a0, .a1 = a1};
	long *result_ptr = &result_safe.a0;
	int forward_to_kernel = true;
	const struct patch_desc *patch = get_cur_patch(a6);
	/*
	 * The RISC-V version of this library doesn't rely on offsets, instead
	 * ecall args get passed directly. It's more straightforward, and
	 * manually arranging the layout is likely to "offset" a programmer.
	 */
	struct syscall_desc desc = {
		.nr = (int)a7, /* ignore higher 32 bits */
		.args[0] = a0,
		.args[1] = a1,
		.args[2] = a2,
		.args[3] = a3,
		.args[4] = a4,
		.args[5] = a5
	};

#ifndef SYSCALL_INTERCEPT_WITHOUT_MAGIC_SYSCALLS
	if (handle_magic_syscalls(&desc, result_ptr) == 0)
		return (struct wrapper_ret){.a0 = result_safe.a0, .a1 = a1};
#endif

	if (logging_enabled)
		intercept_log_syscall(patch, &desc, UNKNOWN, 0);

	if (intercept_hook_point != NULL)
		forward_to_kernel = intercept_hook_point(desc.nr,
				desc.args[0],
				desc.args[1],
				desc.args[2],
				desc.args[3],
				desc.args[4],
				desc.args[5],
				result_ptr);

	if (desc.nr == SYS_rt_sigreturn) {
		/* can't handle these syscalls the normal way */
		return (struct wrapper_ret){.a0 = UNH_SYSCALL, .a1 = UNH_GENERIC};
	}

	if (forward_to_kernel) {
		/*
		 * The clone syscall's arg1 is a pointer to a memory region
		 * that serves as the stack space of a new child thread.
		 * If this is zero, the child thread uses the same address
		 * as stack pointer as the parent does (e.g.: a copy of
		 * of the memory area after fork).
		 *
		 * The code at clone_wrapper only returns to this routine
		 * in the parent thread. In the child thread, it calls
		 * the clone_child_intercept_routine instead, executing
		 * it on the new child threads stack, then returns to libc.
		 */
		if (desc.nr == SYS_clone && (desc.args[1] != 0 || desc.args[0] & CLONE_VFORK))
			return (struct wrapper_ret){.a0 = UNH_SYSCALL, .a1 = UNH_CLONE};
#ifdef SYS_clone3
		else if (desc.nr == SYS_clone3 && ((struct clone_args *)desc.args[0])->stack != 0)
			return (struct wrapper_ret){.a0 = UNH_SYSCALL, .a1 = UNH_CLONE};
#endif

		result_safe.a0 = syscall_no_intercept(desc.nr,
				desc.args[0],
				desc.args[1],
				desc.args[2],
				desc.args[3],
				desc.args[4],
				desc.args[5]);

		/*
		 * For consistency among all clone variants, from the user's
		 * perspective, offer execution of intercept_routine_post_clone
		 * hooks even when the child and parent share stack space
		 * (fork) and the 'KNOWN' logging is done here successfully
		 * after the clone syscall (syscall_no_intercept).
		 */
		if (desc.nr == SYS_clone)
			intercept_routine_post_clone(a0, a1, a2, a3, a4, a5, a6, a7);
#ifdef SYS_clone3
		else if (desc.nr == SYS_clone3)
			intercept_routine_post_clone(a0, a1, a2, a3, a4, a5, a6, a7);
#endif

		/*
			* some users might want to execute code after a syscall has
			* been forwarded to the kernel (for example, to check its
			* return value).
			*/
		if (intercept_hook_point_post_kernel != NULL)
			intercept_hook_point_post_kernel(desc.nr,
					desc.args[0],
					desc.args[1],
					desc.args[2],
					desc.args[3],
					desc.args[4],
					desc.args[5],
					result_safe.a0);
	}

	if (logging_enabled)
		intercept_log_syscall(patch, &desc, KNOWN, result_safe.a0);

	return (struct wrapper_ret){.a0 = result_safe.a0, .a1 = a1};
}
