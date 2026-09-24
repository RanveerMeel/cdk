/*
 * CDK user program layout. The base must match the kernel's user region:
 * USER_BASE (0x80_0000_0000, PML4 slot 1) + 4 MiB. Each section starts on a
 * page boundary so segments with different permissions never share a page.
 */
ENTRY(_start)

SECTIONS
{
    . = 0x8000400000;

    .text : ALIGN(4K) {
        *(.text._start)
        *(.text .text.* .ltext .ltext.*)
    }

    /* The large code model emits .lrodata/.ldata/.lbss alongside the usual names. */
    .rodata : ALIGN(4K) {
        *(.rodata .rodata.* .lrodata .lrodata.*)
    }

    /* The large code model reaches data through a GOT that the linker fills
       in completely (static, no dynamic relocations); keep it with .data. */
    .data : ALIGN(4K) {
        *(.got .got.*)
        *(.data .data.* .ldata .ldata.*)
    }

    .bss : ALIGN(4K) {
        *(.bss .bss.* .lbss .lbss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.eh_frame*)
        *(.comment)
        *(.note*)
    }
}
