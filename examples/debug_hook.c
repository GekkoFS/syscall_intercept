/*
 * Copyright 2024, Custom Debug Hook
 */

#include "../include/libsyscall_intercept_hook_point.h"
#include <syscall.h>
#include <errno.h>
#include <stdio.h>

static int
hook(long syscall_number,
			long arg0, long arg1,
			long arg2, long arg3,
			long arg4, long arg5,
			long *result)
{
	(void) arg0;
	(void) arg1;
	(void) arg2;
	(void) arg3;
	(void) arg4;
	(void) arg5;
	(void) result;
    (void)syscall_number;

    long ret = syscall_no_intercept(SYS_write, 2, "HOOK HIT\n", 9);
    (void)ret;

	return 1; // Forward to kernel
}

static __attribute__((constructor)) void
init(void)
{
    // Set up the hook
    intercept_hook_point = hook;
    syscall_no_intercept(SYS_write, 2, "DEBUG HOOK LOADED\n", 18);
}
