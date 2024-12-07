# syscall\_intercept

A user space library for intercepting syscalls on the RISC-V architecture.


# Dependencies

### Build dependencies:

 * RISC-V toolchain -- tested with recent versions of GCC and Clang
 * CMake ≥ v3.13 -- build system
 * Perl -- required for code style checks
 * Pandoc -- required to generate the manual page

### Runtime dependencies:

 * Capstone ≥ v5 (v6 recommended) -- the disassembly engine used under the hood


# How to Build

The RISC-V toolchain can be built from the [RISC-V GNU Toolchain](https://github.com/riscv-collab/riscv-gnu-toolchain).  
Capstone can be installed from [Capstone Engine](https://www.capstone-engine.org/documentation.html).

Building libsyscall\_intercept requires CMake:
```bash
cmake path_to_syscall_intercept -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release
make
```
Alternatively, use the CMake CUI (GUI):
```bash
ccmake path_to_syscall_intercept
make
```

There is an install target. For now, all it does is `cp`:
```bash
make install
```

Coming soon:
```bash
make test
```


# Synopsis

#### API
```c
#include <libsyscall_intercept_hook_point.h>

int (*intercept_hook_point)(long syscall_number,
                            long arg0, long arg1,
                            long arg2, long arg3,
                            long arg4, long arg5,
                            long *result);
void (*intercept_hook_point_clone_child)(void);
void (*intercept_hook_point_clone_parent)(long pid);
struct wrapper_ret syscall_no_intercept(long syscall_number, ...);
int syscall_error_code(long result);
int syscall_hook_in_process_allowed(void);
```
#### Compile
```bash
$ cc -lsyscall_intercept -fpic -shared source.c -o preloadlib.so
```
#### Run with `LD_PRELOAD`
```bash
$ LD_PRELOAD=preloadlib.so ./application
```


# Description

The syscall-intercepting library provides a low-level interface for hooking Linux system calls in user space. This is achieved by hotpatching the machine code of the standard C library (_glibc_) in the memory of a process. Using this library, almost any syscall can be intercepted in user space via the API specified in _libsyscall_intercept_hook_point.h_.

#### Using `intercept_hook_point()`
```c
int (*intercept_hook_point)(long syscall_number,
                            long arg0, long arg1,
                            long arg2, long arg3,
                            long arg4, long arg5,
                            long *result);
```
* To enable syscall interception, assign a callback function to `intercept_hook_point`.
* A **non-zero return value** from the callback function indicates that the syscall should proceed as normal and will be passed to the kernel.
* A **zero return value** indicates that the user takes over the syscall with the result value stored via the `*result` parameter.

#### Clone hooks
In addition to hooking syscalls, the user can be notified of thread creations with post-clone hooks. These hooks are executed immediately after a thread is created with a `clone` syscall:
```c
void (*intercept_hook_point_clone_child)(void);
void (*intercept_hook_point_clone_parent)(long pid);
```

#### Bypassing interception
The library provides this function to execute syscalls that bypass the interception mechanism:
```c
struct wrapper_ret syscall_no_intercept(long syscall_number, ...);
```

#### Detecting error codes
With the `syscall_error_code()` function it's easy to detect syscall return values indicating errors:
```c
int syscall_error_code(long result);
```

#### Checking interception status
This function is used to query if interception is disabled with the `INTERCEPT_HOOK_CMDLINE_FILTER` [environment variable](#environment-variables).
```c
int syscall_hook_in_process_allowed(void);
```

# Environment Variables

_INTERCEPT_LOG_ -- When set, the library logs each intercepted syscall to a file. If the variable ends with "-", the filename is suffixed with the process ID. E.g., for a process with PID 123 and INTERCEPT\_LOG set to "intercept.log-", the resulting log file would be "intercept.log-123".

_INTERCEPT_LOG_TRUNC_ -- When set to 0, the log file specified by INTERCEPT\_LOG is not truncated.

_INTERCEPT_HOOK_CMDLINE_FILTER_ -- When set, the library checks the command line used to start the program. Hotpatching and syscall interception occur only if the last component of the command matches the string provided in this variable. The library also provides a [function](#checking-interception-status) for querying this state.

_INTERCEPT_ALL_OBJS_ -- When set, all libraries are patched, not just _glibc_ and _pthread_. Note: The syscall\_intercept library and Capstone are never patched.

*INTERCEPT_NO_TRAMPOLINE* -- When set, the trampoline is not used for jumping from the patched library to the syscall\_intercept library. In the RISC-V version of this library, the trampoline size is less than 30 bytes, requiring only one page of memory when allocated with `mmap()`. Consequently, setting this variable does not significantly reduce memory usage.

*INTERCEPT_DEBUG_DUMP* -- Enables verbose output.

# Example

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
Compile and run:
```bash
$ cc example.c -lsyscall_intercept -fpic -shared -o example.so
$ LD_LIBRARY_PATH=. LD_PRELOAD=example.so ls
ls: reading directory '.': Operation not supported
```


# Functional Changes
The key differences in functionality between the RISC-V and x86\_64 versions of this library relevant to the user:
1. `syscall_no_intercept()` returns a struct containing both `A0` and `A1`, the two return values of a syscall, instead of returning only the primary value (`RAX`) on x86\_64.
2. All threads (clones) are intercepted, and results are logged. On x86\_64, the result of thread creation is not logged for threads with separate stack spaces.
3. Post-clone hooks, `intercept_hook_point_clone_child()` and `intercept_hook_point_clone_parent()`, are triggered by every thread creation, not just by the threads with separate stack spaces.


# Under the Hood

### Assumptions:

To handle syscalls in user space, the library relies on the following assumptions:

* All syscalls are issued via _glibc_.
* No other facility hotpatches _glibc_.
* _Glibc_ is loaded before library initialization.
* The _glibc_ machine code is suitable for patching methods used.
* For some more basic assumptions, see [limitations](#limitations).

### Disassembly:

The library disassembles the text segment of _glibc_ loaded into the memory space of the process in which it is initialized. It locates all syscall instructions and replaces each of them with a jump. This is in common with both x86\_64 and RISC-V, but RISC-V differs in how patching is [implemented](#patching-risc-v).

### Patching RISC-V

Reasons to change implementation logic:
1. The relative jump instruction (`jal`) has a ±1 MB reach which is not enough to jump out of _glibc_ like x86's `jmp` with ±2 GB reach.
2. Instructions are naturally better aligned so `nop`s are rarely used in _glibc_ removing the possibility of having the nop trampolines.

Jumping out of _glibc_ is only doable with an indirect jump, `auipc` + `jalr` = ±2 GB reach. That requires much more patching space than x86\_64 `jmp` instruction with its 5 bytes for a 2 GB jump or 2 bytes for a 127 B jump (used in combination with the nop trampoline). RISC-V needs 16 B (when RVC is supported) to perform a 2 GB jump. Not all syscalls are surrounded by that many relocatable instructions. To be able to patch all the syscalls, three different patch types are created based on the space available for patching:
1. _Gateway_ -- the syscall is surrounded by many relocatable instructions which makes it suitable to create a ±2 GB jump. _Gateways_ are the cornerstone of the library because smaller patch types jump here to get "forwarded" to the syscall\_intercept library.
2. _Middle_ -- the syscall is surrounded by enough relocatable instructions to replace them with the store instruction that stores `ra` on the stack. Jumps using `jal ra, GW_addr` to the _gateway_, from where it jumps to the syscall\_intercept library.
3. _Small_ -- not enough space to store the register used by `jal` on the stack. The _small_ type relies on static analysis during the disassembly phase to store the syscall number (`A7` value) in the patch's struct. Like the _middle_ type, the _small_ patch jumps to the _gateway_ using `jal` (`jal a7, GW_addr`).

The final destination for all patches is the same assembly routine (`asm_entry_point`) inside the syscall\_intercept library where C functions get called like in the x86\_64 counterpart library.

### In action:

Hotpatching the _gateway_ type:
```
Before:                           After:

b2d28 <__open>:                   b2d28 <__open>:
...                               ...
b2dac: ld      a1,8(sp)           b2dac: ld      a1,8(sp)
b2dae: ld      a3,0(sp)           b2dae: addi    sp, sp, -48    # GW start
b2db0: mv      a2,s0              b2db0: sd      ra, 0(sp)
b2db2: li      a7,56              b2db2: auipc   ra, offset
b2db6: li      a0,-100            b2db6: jalr    ra, offset(ra)
b2dba: ecall                      b2dba: ld      ra, 0(sp)
b2dbe: lui     a4,0xfffff         b2dbc: addi    sp, sp, 48     # GW end
...                               b2dbe: lui     a4,0xfffff
...                               ...
```
The destination of the _gateway_'s `jalr` is either directly the syscall\_intercept library (if `INTERCEPT_NO_TRAMPOLINE=1`) or a trampoline where an absolute jump is performed to the syscall\_intercept library.  
The _gateway_ and _middle_ types are patched similarly. The difference is that the _middle_ type uses `jal` instead of `auipc`/`jalr` and spares 4 bytes of patching space. Type _small_ is a bit less straightforward, check the [documentation](doc/RV_doc.md).


# Limitations

* Only supports GNU/Linux.
* Tested only with _glibc_, compatibility with other libc implementations is unverified.
* Syscall _rt\_sigreturn_ is not intercepted as it's used by the kernel for signal handling.


# Debugging

Prevent interception of syscalls within the debugger by setting the `INTERCEPT_HOOK_CMDLINE_FILTER` variable described [above](#environment-variables):
```
INTERCEPT_HOOK_CMDLINE_FILTER=ls LD_PRELOAD=libsyscall_intercept.so gdb ls
```

Alternatively, set `LD_PRELOAD` within the gdb session or configure it in a `.gdbinit` file:
```
set environment LD_PRELOAD libsyscall_intercept.so
```

