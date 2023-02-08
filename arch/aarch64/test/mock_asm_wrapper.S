/* mock_asm_wrapper.S COPYRIGHT FUJITSU LIMITED 2019 */
#define align_down(x, align) ((x) & ~((align) - 1))
#define align_up(x, align)   align_down((x) + (align) - 1, (align))

#define page_shift 16
#define page_size  (1 << page_shift)
#define int26_max  0x1FFFFFF
#define int26_min  (-0x2000000)

.macro branch offset
	.if (\offset) % 4 != 0
		.error "invalid offset.(offset=\offset)"
	.elseif (\offset) < (int26_min * 4) || (int26_max * 4) < (\offset)
		.error "out of range.(offset=\offset)"
	.endif
	.inst   0x14000000  | ((\offset) / 4)
.endm

.global mock_asm_wrapper;
.global mock_asm_wrapper_end;
.data
.align page_shift
mock_asm_wrapper:
	.skip (page_size * 2)
mock_asm_wrapper_end:
