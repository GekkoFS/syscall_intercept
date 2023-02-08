/* nosyscall.in.S COPYRIGHT FUJITSU LIMITED 2019 */
.global text_start;
.global text_end;

#include "mock_asm_wrapper.S"

.text

text_start:
		add     x0, x0, x1
		add     x0, x0, x1
		ret
text_end:
