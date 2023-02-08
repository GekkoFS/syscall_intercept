/* executable_with_syscall.S COPYRIGHT FUJITSU LIMITED 2019 */
.global main

#define return_success    0
#define return_failure    1

#define __NR_write 0x40
#define stdout     1

.text
main:
	cmp     x0, #0x1             // cmp argc with 2
	b.gt    1f                   // jump if 1 < argc
	mov     x0, #return_failure  // return from function
	ret
1:
	add     x1, x1, #0x8         // inc argv
	ldr     x1, [x1]             // syscall argument : buf
	mov     x9, x1
	b       find_null            // scan memory to find null terminator
next_char:
	add     x9, x9, #0x1         // next address
find_null:
	ldrb    w10, [x9]            // load char
	cmp     w10, #0x0            // cmp char with '\0'
	b.ne    next_char            // jump if '\0' != char
	sub     x2, x9, x1           // syscall argument : count
	mov     x0, #stdout          // syscall argument : fd
	mov     x8, #__NR_write      // syscall number
	svc     #0x0
	adr     x1, new_line         // syscall argument : buf
	mov     x2, #1               // syscall argument : count
	mov     x0, #stdout          // syscall argument : fd
	mov     x8, #__NR_write      // syscall number
	svc     #0x0
	mov     x0, #return_success  // return from function
	ret
.data
new_line:   .ascii  "\n"
