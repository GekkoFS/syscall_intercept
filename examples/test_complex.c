#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

int main() {
    printf("Starting complex test...\n");

    // 1. Get PID
    pid_t pid = getpid();
    printf("PID: %d\n", pid);

    // 2. Open a file
    const char *filename = "test_file.txt";
    int fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    printf("Opened file fd: %d\n", fd);

    // 3. Write to file
    const char *data = "Hello from syscall intercept test!\n";
    #include <syscall.h>
    ssize_t written = syscall(SYS_write, fd, data, strlen(data));
    if (written < 0) {
        perror("write");
        close(fd);
        return 1;
    }
    printf("Written %zd bytes\n", written);

    // 4. Close file
    close(fd);
    printf("Closed file\n");

    // 5. Open for reading
    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open read");
        return 1;
    }

    // 6. Read from file
    char buffer[128];
    ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    if (bytes_read < 0) {
        perror("read");
        close(fd);
        return 1;
    }
    buffer[bytes_read] = '\0';
    printf("Read %zd bytes: %s", bytes_read, buffer);

    // 7. Close file
    close(fd);

    // 8. Delete file
    if (unlink(filename) < 0) {
        perror("unlink");
        return 1;
    }
    printf("Unlinked file\n");

    return 0;
}
