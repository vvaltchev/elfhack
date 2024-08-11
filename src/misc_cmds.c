/* SPDX-License-Identifier: BSD-2-Clause */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "basic_defs.h"
#include "elf_utils.h"
#include "cmds.h"


static int
move_metadata(struct elf_file_info *nfo)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   char *hc = (char *)h;

   size_t off = h->e_ehsize;

   memcpy(hc + off, hc + h->e_phoff, h->e_phentsize*h->e_phnum);
   h->e_phoff = off;
   off += h->e_phentsize*h->e_phnum;

   memcpy(hc + off, hc + h->e_shoff, h->e_shentsize*h->e_shnum);
   h->e_shoff = off;
   off += h->e_shentsize*h->e_shnum;

   Elf_Shdr *sections = (Elf_Shdr *) (hc + h->e_shoff);
   Elf_Shdr *shstrtab = sections + h->e_shstrndx;

   memcpy(hc + off, hc + shstrtab->sh_offset, shstrtab->sh_size);
   shstrtab->sh_offset = off;

   Elf_Phdr *phdrs = (Elf_Phdr *)(hc + h->e_phoff);
   shstrtab->sh_addr = phdrs[0].p_vaddr + shstrtab->sh_offset;
   shstrtab->sh_flags |= SHF_ALLOC;

   for (uint32_t i = 0; i < h->e_shnum; i++) {
      Elf_Shdr *s = sections + i;

      /* Make sure that all the sections with a vaddr != 0 are 'alloc' */
      if (s->sh_addr)
         s->sh_flags |= SHF_ALLOC;
   }

   return 0;
}

REGISTER_CMD(
   move_metadata,
   "--move-metadata",
   "",
   0,
   &move_metadata
)

/* ------------------------------------------------------------------------- */

static int
verify_flat_elf_file(struct elf_file_info *nfo)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Shdr *sections = (Elf_Shdr *)((char*)h + h->e_shoff);
   Elf_Shdr *shstrtab = sections + h->e_shstrndx;
   Elf_Addr lowest_addr = (Elf_Addr) -1;
   Elf_Addr base_addr = lowest_addr;
   bool failed = false;

   if (!h->e_shnum) {
      fprintf(stderr, "ERROR: the ELF file has no sections!\n");
      return 1;
   }

   for (uint32_t i = 0; i < h->e_shnum; i++) {

      Elf_Shdr *s = sections + i;
      Elf_Phdr *phdr = get_phdr_for_section(h, s);

      if (!phdr || phdr->p_type != PT_LOAD)
         continue;

      if (s->sh_addr < lowest_addr) {
         base_addr = s->sh_addr - s->sh_offset;
         lowest_addr = s->sh_addr;
      }
   }

   for (uint32_t i = 0; i < h->e_shnum; i++) {

      Elf_Shdr *s = sections + i;
      Elf_Phdr *phdr = get_phdr_for_section(h, s);
      char *name = (char *)h + shstrtab->sh_offset + s->sh_name;

      if (!phdr || phdr->p_type != PT_LOAD)
         continue;

      Elf_Addr mem_offset = s->sh_addr - base_addr;

      if (mem_offset != s->sh_offset) {

         fprintf(stderr, "ERROR: section[%d] '%s' has "
                 "memory_offset (%p) != file_offset (%p)\n", i,
                 name, (void *)(size_t)mem_offset,
                 (void *)(size_t)s->sh_offset);

         failed = true;
      }
   }

   if (h->e_entry != lowest_addr) {
      fprintf(stderr, "ERROR: entry point (%p) != lowest load addr (%p)\n",
              (void *)(size_t)h->e_entry, (void *)(size_t)lowest_addr);
      failed = true;
   }

   if (failed) {
      fprintf(stderr, "ERROR: flat ELF check FAILED for file: %s\n", nfo->path);
      return 1;
   }

   return 0;
}

REGISTER_CMD(
   verify_flat_elf,
   "--verify-flat-elf",
   "",
   0,
   &verify_flat_elf_file
)

/* ------------------------------------------------------------------------- */

static int
check_entry_point(struct elf_file_info *nfo, const char *exp)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   uintptr_t exp_val;
   char *endptr;

   errno = 0;
   exp_val = strtoul(exp, &endptr, 16);

   if (errno || endptr == exp) {
      fprintf(stderr, "Invalid value '%s' for expected entry point.\n", exp);
      fprintf(stderr, "It must be a hex string like 0xc0101000.\n");
      return 1;
   }

   if (h->e_entry != exp_val) {

      fprintf(stderr,
              "ERROR: entry point (%#lx) != expected (%#lx) for file %s\n",
              (uintptr_t)h->e_entry, exp_val, nfo->path);

      return 1;
   }

   return 0;
}

REGISTER_CMD(
   check_entry_point,
   "--check-entry-point",
   "<expected>",
   1,
   &check_entry_point
)

/* ------------------------------------------------------------------------- */

static int
check_mem_size(struct elf_file_info *nfo, const char *exp, const char *unit)
{
   size_t sz = elf_calc_mem_size(nfo->vaddr);
   size_t exp_val;
   char *endptr;
   int base = 10;

   if (exp[0] == '0' && exp[1] == 'x')
      base = 16;

   errno = 0;
   exp_val = strtoul(exp, &endptr, base);

   if (errno || endptr == exp) {
      fprintf(stderr, "Invalid value '%s' for expected_max.\n", exp);
      return 1;
   }

   if (!strcmp(unit, "kb"))
      exp_val *= KB;

   if (sz > exp_val) {

      fprintf(stderr,
              "ELF's max in-memory size (%zu) > expected_max (%zu).\n",
              sz, exp_val);

      return 1;
   }

   return 0;
}

REGISTER_CMD(
   check_mem_size,
   "--check-mem-size",
   "<expected_max> <b|kb>",
   2,
   &check_mem_size
)

/* ------------------------------------------------------------------------- */

static int
redirect_reloc(struct elf_file_info *nfo, const char *sym1, const char *sym2)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Sym *s1 = get_symbol_by_name(h, sym1, NULL);
   Elf_Sym *s2 = get_symbol_by_name(h, sym2, NULL);

   if (!s1) {
      fprintf(stderr, "Cannot find symbol '%s'\n", sym1);
      return 1;
   }

   if (!s2) {
      fprintf(stderr, "Cannot find symbol '%s'\n", sym2);
      return 1;
   }

   Elf_Shdr *sections = (Elf_Shdr *) ((char *)h + h->e_shoff);
   for (uint32_t i = 0; i < h->e_shnum; i++) {
      Elf_Shdr *s = sections + i;
      if (s->sh_type == SHT_REL || s->sh_type == SHT_RELA) {
         redirect_rel_internal(h, s, s1, s2);
      }
   }

   return 0;
}

REGISTER_CMD(
   redirect_reloc,
   "--redirect-reloc",
   "<sym1> <sym2>",
   2,
   &redirect_reloc
)
