ENTRY(call_start_cpu0)

MEMORY
{
  iram0_0_seg (RX) : org = 0x40080000, len = 0x20000
  irom0_0_seg (RX) : org = 0x400D0020, len = 0x330000 - 0x20
  drom0_0_seg (R)  : org = 0x3F400020, len = 0x400000 - 0x20
  dram0_0_seg (RW) : org = 0x3FFB0000, len = 0x2C200
}

SECTIONS
{
  .iram0.text :
  {
    _iram_start = ABSOLUTE(.);
    *(.iram1.entry.literal)
    KEEP(*(.iram1.entry))
    *(.iram1.literal .iram1 .iram1.*)
    _iram_end = ABSOLUTE(.);
  } > iram0_0_seg

  .dram0.data :
  {
    _data_start = ABSOLUTE(.);
    *(.data .data.* .sdata .sdata.*)
    _data_end = ABSOLUTE(.);
  } > dram0_0_seg

  .dram0.bss (NOLOAD) :
  {
    . = ALIGN(8);
    _bss_start = ABSOLUTE(.);
    *(.bss .bss.* .sbss .sbss.* COMMON)
    . = ALIGN(8);
    _bss_end = ABSOLUTE(.);
    __heap_start = ABSOLUTE(.);
  } > dram0_0_seg

  __heap_end = 0x3FFDC200;
  __stack = 0x3FFDC200;

  .flash.rodata :
  {
    _rodata_start = ABSOLUTE(.);
    KEEP(*(.rodata_desc))
    *(.rodata .rodata.* .srodata .srodata.*)
    *(.tdata .tdata.* .tbss .tbss.*)
    _rodata_end = ABSOLUTE(.);
  } > drom0_0_seg

  .flash.text :
  {
    _text_start = ABSOLUTE(.);
    *(.literal .text .literal.* .text.*)
    _text_end = ABSOLUTE(.);
  } > irom0_0_seg

  /DISCARD/ : { *(.comment) *(.note.*) *(.xt.prop .xt.prop.* .xt.lit .xt.lit.*) *(.xtensa.info) }
}
