SECTIONS
{
	.text.relocation :
	{
		*(.text.relocation)
	}
	.text.irqentry :
	{
		*(.text.irqentry)
	}
}
INSERT AFTER .text;
