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

#ifndef LIBSYSCALL_INTERCEPT_HOOK_POINT_H
#define LIBSYSCALL_INTERCEPT_HOOK_POINT_H

/*
 * The inteface for using the intercepting library.
 * This callback function should be implemented by
 * the code using the library.
 *
 * The syscall_number, and the six args describe the syscall
 * currently being intercepted.
 * A non-zero return value means libsyscall_intercept
 * should execute the original syscall, use its result. A zero return value
 * means libsyscall_intercept should not execute the syscall, and
 * use the integer stored to *result as the result of the syscall
 * to be returned in RAX to libc.
 */

#ifdef __cplusplus
extern "C" {
#endif
#include <errno.h>

extern int (*intercept_hook_point)(long syscall_number,
			long arg0, long arg1,
			long arg2, long arg3,
			long arg4, long arg5,
			long *result);
extern void (*intercept_hook_point_clone_child)(
			unsigned long flags, void *child_stack,
			int *ptid, int *ctid, long newtls);
extern void (*intercept_hook_point_clone_parent)(
			unsigned long flags, void *child_stack,
			int *ptid, int *ctid, long newtls,
			long returned_pid);
extern void (*intercept_hook_point_post_kernel)(long syscall_number,
			long arg0, long arg1,
			long arg2, long arg3,
			long arg4, long arg5,
			long result);

/*
 * syscall_no_intercept - syscall without interception
 *
 * Call syscall_no_intercept to make syscalls
 * from the interceptor library, once glibc is already patched.
 * Don't use the syscall function from glibc, that
 * would just result in an infinite recursion.
 */
long syscall_no_intercept(long syscall_number, ...);

/*
 * syscall_error_code - examines a return value from
 * syscall_no_intercept, and returns an error code if said
 * return value indicates an error.
 * In POWER9 we check a register so we must use it only once
 * after the syscall_no_intercept call
 */
static inline int
__attribute__((always_inline)) syscall_error_code(long result)
{
	unsigned long long i;
	__asm__ volatile
	(
	"mfcr %0\n\t"
	:"=r"(i) /* Output registers */
	:
	: "cr0");

	if ((i & 0x10000000) > 0) {
		errno = result;

		__asm__ volatile("mtcr %0\n\t"
		:   /* Output registers */
		: "r" (i)
		: "cr0");

		
	}
	else{

	result = 0;
	
	__asm__ volatile("mtcr %0\n\t"
	:  /* Output registers */
	: "r" (i)
	: "cr0");
	}
	return result;
}

/*
 * The syscall intercepting library checks for the
 * INTERCEPT_HOOK_CMDLINE_FILTER environment variable, with which one can
 * control in which processes interception should actually happen.
 * If the library is loaded in this process, but syscall interception
 * is not allowed, the syscall_hook_in_process_allowed function returns zero,
 * otherwise, it returns one. The user of the library can use it to notice
 * such situations, where the code is loaded, but no syscall will be hooked.
 */
int syscall_hook_in_process_allowed(void);

#ifdef __cplusplus
}
/* Wrapper to call syscall + error code */
template < class... Args >
inline long __attribute__((always_inline)) syscall_no_intercept_wrapper(long syscall_number, Args ... args) {

	long result;
	int error_sc = 0;
	result = syscall_no_intercept(syscall_number, args...);
	error_sc = syscall_error_code(result);
	if (error_sc != 0) {
		return -1;
	}
	return result;

}
#endif

#endif
