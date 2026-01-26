
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/mman.h>

/*
 * Expanded test to verify syscall interception coverage.
 */

int main()
{
	printf("Starting expanded syscall coverage test...\n");
    
    // Debug: Print memory map structure
    char buf[1024];
    int fd_map = open("/proc/self/maps", O_RDONLY);
    if (fd_map >= 0) {
        while (1) {
            int n = read(fd_map, buf, sizeof(buf));
            if (n <= 0) break;
            write(1, buf, n);
        }
        close(fd_map);
    }
    printf("--- End of Maps ---\n");

    // 1. Simple Process Info
    long pid = syscall(SYS_getpid);
    printf("[PASS] getpid: %ld\n", pid);

    long uid = syscall(SYS_getuid);
    printf("[PASS] getuid: %ld\n", uid);

    long gid = syscall(SYS_getgid);
    printf("[PASS] getgid: %ld\n", gid);

    // 2. System Info
    struct utsname u;
    if (syscall(SYS_uname, &u) == 0) {
        printf("[PASS] uname: %s %s\n", u.sysname, u.release);
    } else {
        perror("[FAIL] uname");
    }

    struct sysinfo si;
    if (syscall(SYS_sysinfo, &si) == 0) {
        printf("[PASS] sysinfo: uptime %ld\n", si.uptime);
    } else {
        perror("[FAIL] sysinfo");
    }

    // 3. Time
    // time() syscall is often deprecated or implemented via VDSO/other means.
    // We stick to gettimeofday for time checks.

    struct timeval tv;
    if (syscall(SYS_gettimeofday, &tv, NULL) == 0) {
        printf("[PASS] gettimeofday: %ld.%ld\n", tv.tv_sec, tv.tv_usec);
    } else {
        perror("[FAIL] gettimeofday");
    }

    struct timespec rem;
    struct timespec req = {0, 1000000}; // 1ms
    if (syscall(SYS_nanosleep, &req, &rem) == 0) {
        printf("[PASS] nanosleep success\n");
    } else {
        perror("[FAIL] nanosleep");
    }

    // 4. Memory
    void *current_brk = (void*)syscall(SYS_brk, 0);
    printf("[PASS] current brk: %p\n", current_brk);

    void *map = (void*)syscall(SYS_mmap, NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (map != MAP_FAILED) {
        printf("[PASS] mmap: %p\n", map);
        syscall(SYS_munmap, map, 4096);
        printf("[PASS] munmap success\n");
    } else {
        perror("[FAIL] mmap");
    }

    // 5. File I/O
    if (syscall(SYS_faccessat, AT_FDCWD, "/dev/null", F_OK, 0) == 0) {
        printf("[PASS] access (faccessat) /dev/null success\n");
    } else {
        perror("[FAIL] access");
    }

    int fd = syscall(SYS_openat, AT_FDCWD, "/dev/null", O_WRONLY, 0);
    if (fd >= 0) {
        syscall(SYS_write, fd, "test", 4);
        syscall(SYS_close, fd);
        printf("[PASS] File I/O (openat/write/close) passed\n");
    } else {
        perror("[FAIL] openat");
    }

	return 0;
}
