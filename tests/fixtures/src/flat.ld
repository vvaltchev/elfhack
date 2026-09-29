/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * Linker script of the "flat" fixtures (flat32, flat64). "Flat" as in Tilck:
 * an ELF binary that can also be run as a raw, non-ELF image by skipping its
 * headers. Tilck's legacy bootloader loads its stage 3 (elf_stage3) exactly
 * like that: the whole file is copied to memory as it is, and executed from
 * its lowest loaded address. --verify-flat-elf checks the two properties
 * that make it work:
 *
 *   - The file mirrors memory: every loaded section's file offset equals
 *     its distance, in memory, from where the start of the file lands.
 *   - The entry point is the lowest address of any loaded section.
 *
 * Besides that, like Tilck's kernel (which is loaded segment by segment):
 *
 *   - Only PT_LOAD segments: no PT_GNU_STACK, PT_NOTE etc.
 *   - Linked at a high virtual address (VIRT_BASE) and loaded at a low
 *     physical one (PHYS_BASE): p_vaddr != p_paddr.
 *   - The data segment is larger in memory than in the file (.bss), and its
 *     end is not a multiple of the segment alignment.
 *
 * VIRT_BASE and PHYS_BASE are defined on the command line (--defsym).
 */

ENTRY(_start)

PHDRS
{
   text PT_LOAD FILEHDR PHDRS;
   data PT_LOAD;
}

SECTIONS
{
   . = VIRT_BASE + SIZEOF_HEADERS;

   .text ALIGN(0x1000) : AT(ADDR(.text) - VIRT_BASE + PHYS_BASE)
   {
      *(.text.entry)
      *(.text*)
   } :text

   .rodata : AT(ADDR(.rodata) - VIRT_BASE + PHYS_BASE)
   {
      *(.rodata*)
   } :text

   .data ALIGN(0x1000) : AT(ADDR(.data) - VIRT_BASE + PHYS_BASE)
   {
      *(.data*)
   } :data

   .bss : AT(ADDR(.bss) - VIRT_BASE + PHYS_BASE)
   {
      *(.bss*)
   } :data

   /DISCARD/ :
   {
      *(.note*)
      *(.eh_frame*)
   }
}
