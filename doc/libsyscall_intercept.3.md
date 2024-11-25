---
layout: manual
Content-Style: 'text/css'
title: libsyscall_intercept(3)
header: SYSCALL_INTERCEPT
date: syscall_intercept API version 0.1.0
...

[comment]: <> (Copyright 2017, Intel Corporation)

[comment]: <> (Redistribution and use in source and binary forms, with or without)
[comment]: <> (modification, are permitted provided that the following conditions)
[comment]: <> (are met:)
[comment]: <> (    * Redistributions of source code must retain the above copyright)
[comment]: <> (      notice, this list of conditions and the following disclaimer.)
[comment]: <> (    * Redistributions in binary form must reproduce the above copyright)
[comment]: <> (      notice, this list of conditions and the following disclaimer in)
[comment]: <> (      the documentation and/or other materials provided with the)
[comment]: <> (      distribution.)
[comment]: <> (    * Neither the name of the copyright holder nor the names of its)
[comment]: <> (      contributors may be used to endorse or promote products derived)
[comment]: <> (      from this software without specific prior written permission.)

[comment]: <> (THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS)
[comment]: <> ("AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT)
[comment]: <> (LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR)
[comment]: <> (A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT)
[comment]: <> (OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,)
[comment]: <> (SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT)
[comment]: <> (LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,)
[comment]: <> (DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY)
[comment]: <> (THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT)
[comment]: <> ((INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE)
[comment]: <> (OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.)

[comment]: <> (libsyscall_intercept.3 -- man page for libsyscall_intercept)

[NAME](#name)<br />
[SYNOPSIS](#synopsis)<br />
[DESCRIPTION](#description)<br />
[ENVIRONMENT VARIABLES](#environment-variables)<br />
[EXAMPLE](#example)<br />
[SEE ALSO](#see-also)


# NAME #
**libsyscall_intercept** -- User space syscall intercepting library

# SYNOPSIS #

```c
#include <libsyscall_intercept_hook_point.h>
```
```bash
cc -lsyscall_intercept -fpic -shared source.c -o preloadlib.so

LD_PRELOAD=preloadlib.so ./application
```

# DESCRIPTION #
The system call intercepting library provides a low-level interface
for hooking Linux system calls in user space. This is achieved
by hotpatching the machine code of the standard C library in the
memory of a process. The user of this library can provide the
functionality of almost any syscall in user space, using the very
simple API specified in the libsyscall\_intercept\_hook\_point.h header file:
```c
int (*intercept_hook_point)(long syscall_number,
			long arg0, long arg1,
			long arg2, long arg3,
			long arg4, long arg5,
			long *result);
```

The user of the library shall assign to the variable called
intercept\_hook\_point a pointer to the address of a callback function.
A non-zero return value returned by the callback function is used
to signal to the intercepting library that the specific system
call was ignored by the user and the original syscall should be
executed. A zero return value signals that the user takes over the
system call. In this case, the result of the system call
(the value stored in the A0 register after the system call)
can be set via the \*result pointer. In order to use the library,
the intercepting code is expected to be loaded using the
LD\_PRELOAD feature provided by the system loader.

All syscalls issued by glibc are intercepted. Syscalls made
by code outside glibc are not intercepted by default (see
INTERCEPT\_ALL\_OBJS below). In order to be able to issue
syscalls that are not intercepted, a convenience function
is provided by the library:
```c
struct wrapper_ret syscall_no_intercept(long syscall_number, ...);
```
The struct `wrapper_ret` is part of the RISC-V version of this library's API:
```c
struct wrapper_ret {
    int64_t a0;
    int64_t a1;
}
```
If A1 is modified by a syscall, this struct will preserve both
return values (A0 and A1).

In addition to hooking syscalls before they would be called, the API
has two special hook points that are executed after thread creation,
right after a clone syscall creating a thread returns:
```c
void (*intercept_hook_point_clone_child)(void);
void (*intercept_hook_point_clone_parent)(long pid);
```
The parameter `long pid` for the parent's hook is a
PID of a newly created child thread.  
Using `intercept_hook_point_clone_child` or `intercept_hook_point_clone_parent`,
one can be notified of thread creations.

To make it easy to detect syscall return values indicating errors, one
can use the syscall\_error\_code function:
```c
int syscall_error_code(long result);
```
When passed a return value from syscall\_no\_intercept, this function
can translate it to an error code equivalent to a glibc error code:
```c
struct wrapper_ret ret;
ret = syscall_no_intercept(SYS_open, "file", O_RDWR);
int fd = (int)ret.a0;
if (syscall_error_code(fd) != 0)
	fprintf(stderr, strerror(syscall_error_code(fd)));
```

# ENVIRONMENT VARIABLES #
Several environment variables control the operation of the library:

_INTERCEPT_LOG_ -- When set, the library logs each intercepted syscall
to a file. If the variable ends with "-", the filename is suffixed with
the process ID. E.g., for a process with PID 123 and INTERCEPT\_LOG set
to "intercept.log-", the resulting log file would be "intercept.log-123".

_INTERCEPT_LOG_TRUNC_ -- When set to 0, the log file specified by
INTERCEPT\_LOG is not truncated.

_INTERCEPT_HOOK_CMDLINE_FILTER_ -- When set, the library checks the command
line used to start the program. Hotpatching and syscall interception occur
only if the last component of the command matches the string provided in this
variable. This can also be queried by the user of the library:
```c
int syscall_hook_in_process_allowed(void);
```

_INTERCEPT_ALL_OBJS_ -- When set, all libraries are patched, not just _glibc_ and
_pthread_. Note: The syscall\_intercept library and Capstone are never patched.

*INTERCEPT_NO_TRAMPOLINE* -- When set, the trampoline is not used for jumping
from the patched library to the syscall\_intercept library. In the RISC-V
version of this library, the trampoline size is less than 30 bytes, requiring
only one page of memory when allocated with `mmap()`. Consequently, setting
this variable does not significantly reduce memory usage.

*INTERCEPT_DEBUG_DUMP* -- Enables verbose output.

# EXAMPLE #

```c
#include <libsyscall_intercept_hook_point.h>
#include <syscall.h>
#include <errno.h>

static int
hook(long syscall_number,
			long arg0, long arg1,
			long arg2, long arg3,
			long arg4, long arg5,
			long *result)
{
	if (syscall_number == SYS_getdents) {
		/*
		 * Prevent the application from
		 * using the getdents syscall. From
		 * the point of view of the calling
		 * process, it is as if the kernel
		 * would return the ENOTSUP error
		 * code from the syscall.
		 */
		*result = -ENOTSUP;
		return 0;
	} else {
		/*
		 * Ignore any other syscalls
		 * i.e.: pass them on to the kernel
		 * as would normally happen.
		 */
		return 1;
	}
}

static __attribute__((constructor)) void
init(void)
{
	// Set up the callback function
	intercept_hook_point = hook;
}
```

```bash
$ cc example.c -lsyscall_intercept -fpic -shared -o example.so
$ LD_LIBRARY_PATH=. LD_PRELOAD=example.so ls
ls: reading directory '.': Operation not supported
```

# SEE ALSO #
**syscall**(2)
