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
section_bin_dump(struct elf_file_info *nfo, const char *section_name)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Shdr *s = get_section_by_name(nfo->vaddr, section_name);

   if (!s) {
      fprintf(stderr, "No section '%s'\n", section_name);
      return 1;
   }

   fwrite((char*)h + s->sh_offset, 1, s->sh_size, stdout);
   return 0;
}

REGISTER_CMD(
   section_bin_dump,
   "--section-bin-dump",
   "<section name>",
   1,
   &section_bin_dump
)


static int
copy_section(struct elf_file_info *nfo, const char *src, const char *dst)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Shdr *s_src, *s_dst;

   if (!src) {
      fprintf(stderr, "Missing <source section> argument\n");
      return 1;
   }

   if (!dst) {
      fprintf(stderr, "Missing <dest section> argument\n");
      return 1;
   }

   s_src = get_section_by_name(nfo->vaddr, src);

   if (!s_src) {
      fprintf(stderr, "No section '%s'\n", src);
      return 1;
   }

   s_dst = get_section_by_name(nfo->vaddr, dst);

   if (!s_dst) {
      fprintf(stderr, "No section '%s'\n", dst);
      return 1;
   }

   if (s_src->sh_size > s_dst->sh_size) {
      fprintf(stderr, "The source section '%s' is too big "
              "[%lu bytes] to fit in the dest section '%s' [%lu bytes]\n",
              src, (unsigned long)s_src->sh_size,
              dst, (unsigned long)s_dst->sh_size);
      return 1;
   }

   memcpy((char*)h + s_dst->sh_offset,
          (char*)h + s_src->sh_offset,
          s_src->sh_size);

   s_dst->sh_info = s_src->sh_info;
   s_dst->sh_flags = s_src->sh_flags;
   s_dst->sh_type = s_src->sh_type;
   s_dst->sh_entsize = s_src->sh_entsize;
   s_dst->sh_size = s_src->sh_size;
   return 0;
}

REGISTER_CMD(
   copy,
   "--copy",
   "<src section> <dest section>",
   2,
   &copy_section
)


static int
rename_section(struct elf_file_info *nfo,
               const char *section_name,
               const char *new_name)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   char *hc = (char *)h;
   Elf_Shdr *sections = (Elf_Shdr *)(hc + h->e_shoff);
   Elf_Shdr *shstrtab = sections + h->e_shstrndx;

   if (!new_name) {
      fprintf(stderr, "Missing <new_name> argument\n");
      return 1;
   }

   if (strlen(new_name) > strlen(section_name)) {
      fprintf(stderr, "Section rename with length > old one NOT supported.\n");
      return 1;
   }

   Elf_Shdr *s = get_section_by_name(nfo->vaddr, section_name);

   if (!s) {
      fprintf(stderr, "No section '%s'\n", section_name);
      return 1;
   }

   strcpy(hc + shstrtab->sh_offset + s->sh_name, new_name);
   return 0;
}

REGISTER_CMD(
   rename,
   "--rename",
   "<section> <new_name>",
   2,
   &rename_section
)


static int
link_sections(struct elf_file_info *nfo,
              const char *section_name,
              const char *linked)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   char *hc = (char *)h;
   Elf_Shdr *sections = (Elf_Shdr *)(hc + h->e_shoff);

   if (!linked) {
      fprintf(stderr, "Missing <linked section> argument\n");
      return 1;
   }

   Elf_Shdr *a = get_section_by_name(nfo->vaddr, section_name);
   Elf_Shdr *b = get_section_by_name(nfo->vaddr, linked);

   if (!a) {
      fprintf(stderr, "No section '%s'\n", section_name);
      return 1;
   }

   if (!b) {
      fprintf(stderr, "No section '%s'\n", linked);
      return 1;
   }

   unsigned bidx = (b - sections);
   a->sh_link = bidx;
   return 0;
}

REGISTER_CMD(
   link,
   "--link",
   "<section> <linked_section>",
   2,
   &link_sections
)

static int
undef_section(struct elf_file_info *nfo, const char *section_name)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Shdr *sec = get_section_by_name(h, section_name);

   if (!sec) {
      fprintf(stderr, "Section '%s' not found\n", section_name);
      return 1;
   }

   memset(sec, 0, sizeof(*sec));
   return 0;
}

REGISTER_CMD(
   undef_section,
   "--undef-section",
   "<section_name>",
   1,
   &undef_section
)
