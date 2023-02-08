/* pattern1.out.S COPYRIGHT FUJITSU LIMITED 2019 */
.global text_start;
.global text_end;

#include "mock_asm_wrapper.S"

#define _text_start       0x10000
#define _mock_asm_wrapper 0x30000

.text
.align page_shift
text_start:
		mov     x8, #0x5e
		branch  _mock_asm_wrapper - (_text_start + 4)
0:		b       0b
text_end:
