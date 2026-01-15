/*
 * Copyright 2016-2022, Intel Corporation
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
 * syscall_no_intercept -- syscall without interception
 *
 * Call syscall_no_intercept to make syscalls
 * from the interceptor library, once glibc is already patched.
 * Don't use the syscall function from glibc, that
 * would just result in an infinite recursion.
 */

.text
.global raw_syscall
.type raw_syscall, @function

raw_syscall:
	/*
	 * Function signature: long raw_syscall(long number, ...);
	 *
	 * Arguments are passed in registers:
	 * a0: syscall number
	 * a1: arg0
	 * a2: arg1
	 * a3: arg2
	 * a4: arg3
	 * a5: arg4
	 * a6: arg5
	 *
	 * RISC-V Linux syscall calling convention:
	 * a7: syscall number
	 * a0: arg0
	 * a1: arg1
	 * a2: arg2
	 * a3: arg3
	 * a4: arg4
	 * a5: arg5
	 *
	 * Return value in a0.
	 */

	mv a7, a0
	mv a0, a1
	mv a1, a2
	mv a2, a3
	mv a3, a4
	mv a4, a5
	mv a5, a6
	ecall
	ret

.size raw_syscall, .-raw_syscall
