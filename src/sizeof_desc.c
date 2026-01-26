#define _GNU_SOURCE
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include "intercept.h"

int main() {
    printf("sizeof(struct intercept_desc): %zu\n", sizeof(struct intercept_desc));
    printf("offsetof(count): %zu\n", offsetof(struct intercept_desc, count));
    printf("offsetof(items): %zu\n", offsetof(struct intercept_desc, items));
    printf("offsetof(base_addr): %zu\n", offsetof(struct intercept_desc, base_addr));
    printf("offsetof(path): %zu\n", offsetof(struct intercept_desc, path));
    return 0;
}
