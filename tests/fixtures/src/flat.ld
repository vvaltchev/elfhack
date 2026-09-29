/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * Linker script of the "flat" fixtures (flat32, flat64): an image laid out
 * like a kernel that a bootloader copies to memory as it is.
 *
 *   - Only PT_LOAD segments: no PT_GNU_STACK, PT_NOTE etc.
 *   - The file mirrors memory: the ELF headers are at offset 0 of the first
 *     segment, and every section's file offset equals its distance from
 *     the start of the image in memory.
 *   - The entry point is the lowest address of any section.
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
