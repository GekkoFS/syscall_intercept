SECTIONS
{
	.text.irqentry : ALIGN(0x1000)
	{
		*(.text.irqentry)
	}
}
INSERT BEFORE .text;
