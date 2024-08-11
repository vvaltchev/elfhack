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

/* ------------------------------------------------------------------------- */

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

/* ------------------------------------------------------------------------- */

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

/* ------------------------------------------------------------------------- */

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

/* ------------------------------------------------------------------------- */

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

/* ------------------------------------------------------------------------- */

static int
drop_last_section(struct elf_file_info *nfo)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   char *hc = (char *)h;
   Elf_Shdr *sections = (Elf_Shdr *)(hc + h->e_shoff);
   Elf_Shdr *shstrtab = sections + h->e_shstrndx;

   Elf_Shdr *last_section = sections;
   int last_section_index = 0;
   Elf_Off last_offset = 0;

   if (!h->e_shnum) {
      fprintf(stderr, "ERROR: the ELF file has no sections!\n");
      return 1;
   }

   for (uint32_t i = 0; i < h->e_shnum; i++) {

      Elf_Shdr *s = sections + i;

      if (s->sh_offset > last_offset) {
         last_section = s;
         last_offset = s->sh_offset;
         last_section_index = i;
      }
   }

   if (last_section == shstrtab) {
      fprintf(stderr,
              "The last section is .shstrtab and it cannot be removed!\n");
      return 1;
   }

   if (last_section_index != h->e_shnum - 1) {

      /*
       * If the last section physically on file is not the last section in
       * the table, we cannot just decrease h->e_shnum, otherwise we'll remove
       * from the table an useful section. Therefore, in that case we just
       * use the slot of the last_section to store the section metainfo of the
       * section with the biggest index in the section table (last section in
       * another sense).
       */

      *last_section = sections[h->e_shnum - 1];

      /*
       * If we're so unlucky that the section with the biggest index in the
       * section table is also the special .shstrtab, we have to update its
       * index in the ELF header as well.
       */
      if (h->e_shstrndx == h->e_shnum - 1) {
         h->e_shstrndx = last_section_index;
      }
   }

   /* Drop the last section from the section table */
   h->e_shnum--;

   /*
    * Unlink all the sections depending on this one. Yes, this is rough,
    * but it's fine. Users of this script MUST know exactly what they're doing.
    * In particular, for the main use of this feature (drop of the old symtab
    * and strtab), it is expected this function to be just used twice.
    */
   for (uint32_t i = 0; i < h->e_shnum; i++)
      if ((int)sections[i].sh_link == last_section_index)
         sections[i].sh_link = 0;

   /* Physically remove the last section from the file, by truncating it */
   if (ftruncate(nfo->fd, last_offset) < 0) {

      fprintf(stderr, "ftruncate(%i, %li) failed with '%s'\n",
              nfo->fd, last_offset, strerror(errno));

      return 1;
   }

   return 0;
}

REGISTER_CMD(
   drop_last_section,
   "--drop-last-section",
   "",
   0,
   &drop_last_section
)