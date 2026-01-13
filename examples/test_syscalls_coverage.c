
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>

/*
 * Simple test to verify syscall interception coverage.
 * It attempts to call several common syscalls and verifies
 * (via libsyscall_logger or similar hook) that they are intercepted.
 */

int main()
{
	printf("Starting syscall coverage test...\n");

    // 1. Simple syscall (getpid)
    long pid = syscall(SYS_getpid);
    printf("getpid: %ld\n", pid);

    // 2. File I/O (open/write/close)
    int fd = syscall(SYS_openat, AT_FDCWD, "/dev/null", O_WRONLY, 0);
    if (fd < 0) {
        perror("openat");
    } else {
        syscall(SYS_write, fd, "test", 4);
        syscall(SYS_close, fd);
        printf("File I/O syscalls passed\n");
    }

	return 0;
}
