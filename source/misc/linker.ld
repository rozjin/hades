ENTRY (_start)

OUTPUT_FORMAT(elf64-x86-64)

SECTIONS { 
   . = 0xFFFFFFFF80100000;

   .stivale2hdr : ALIGN(4K) {
      *(.stivale2hdr)
   }

   .text : ALIGN(4K) {
      *(.text)
   }

   .init_array : ALIGN(4K) {
		_init_array_begin = .;
		KEEP(*(SORT(.init_array.*)))
		KEEP(*(.init_array*))
		_init_array_end = .;
	}

   .data : ALIGN(4K) {
   	*(.data)
      *(.rodata)
      *(.stivale2tags)
   }

   .bss : ALIGN(4K) {
      *(COMMON)
	   *(.bss)
   }
}
