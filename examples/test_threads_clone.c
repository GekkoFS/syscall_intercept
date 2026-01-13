#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <string.h>

void my_print(const char* msg) {
    long len = strlen(msg);
    long fd = 1;
    register long a7 __asm__("a7") = SYS_write;
    register long a0 __asm__("a0") = fd;
    register long a1 __asm__("a1") = (long)msg;
    register long a2 __asm__("a2") = len;
    __asm__ __volatile__ ("ecall" : "+r"(a0) : "r"(a7), "r"(a0), "r"(a1), "r"(a2) : "memory");
}

void* thread_func(void* arg) {
    (void)arg;
    my_print("  [Thread] Hello from thread!\n");
    // Perform some syscalls
    syscall(SYS_getuid);
    return NULL;
}

int child_func(void* arg) {
    (void)arg;
    my_print("  [Clone] Hello from clone!\n");
    syscall(SYS_getgid);
    return 0;
}

int main() {
    my_print("--- Concurrency Test ---\n");

    // 1. Pthreads
    my_print("1. Testing pthreads...\n");
    pthread_t t1, t2;
    if (pthread_create(&t1, NULL, thread_func, NULL) != 0) {
        perror("pthread_create 1");
    }
    if (pthread_create(&t2, NULL, thread_func, NULL) != 0) {
        perror("pthread_create 2");
    }
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    my_print("   Pthreads finished.\n");

    // 2. Fork
    my_print("2. Testing fork...\n");
    pid_t pid = fork();
    if (pid == 0) {
        // Child
        my_print("  [Fork] Child process.\n");
        syscall(SYS_getuid);
        exit(0);
    } else if (pid > 0) {
        wait(NULL);
        my_print("   Fork finished.\n");
    } else {
        perror("fork");
    }

    // 3. Clone
    my_print("3. Testing clone...\n");
    // Allocate stack
    size_t stack_size = 1024 * 1024;
    char *stack = malloc(stack_size);
    if (!stack) {
        perror("malloc");
        return 1;
    }
    char *stack_top = stack + stack_size;
    
    // clone with SIGCHLD behaves like fork but with manually managed stack
    pid_t cpid = clone(child_func, stack_top, SIGCHLD, NULL);
    if (cpid == -1) {
        perror("clone");
    } else {
        waitpid(cpid, NULL, 0);
        my_print("   Clone finished.\n");
    }
    
    free(stack);

    return 0;
}
