/* SPDX-License-Identifier: BSD-2-Clause */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <errno.h>

#include "elfhack/basic_defs.h"
#include "elfhack/elf_utils.h"
#include "elfhack/options.h"
#include "elfhack/misc.h"
#include "elfhack/utils.h"

static int
set_sym_strval(struct elf_file_info *nfo,
               const char *section_name,
               const char *name_or_index,
               const char *val)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Shdr *section;
   Elf_Sym *sym;
   size_t len;

   if (!name_or_index || !val) {
      fprintf(stderr, "Missing arguments\n");
      return 1;
   }

   section = get_section(h, section_name, NULL);

   if (!section) {
      fprintf(stderr, "No section '%s'\n", section_name);
      return 1;
   }

   sym = get_symbol(h, name_or_index, NULL);

   if (!sym) {
      fprintf(stderr, "Unable to find the symbol '%s'\n", name_or_index);
      return 1;
   }

   if (sym->st_value < section->sh_addr ||
       sym->st_value + sym->st_size > section->sh_addr + section->sh_size)
   {
      fprintf(stderr,
              "Symbol '%s' not in section '%s'\n", name_or_index, section_name);

      return 1;
   }

   len = strlen(val) + 1;

   if (sym->st_size < len) {
      fprintf(stderr, "ERROR: Symbol '%s' [%u bytes] not big enough for value\n",
              name_or_index, (unsigned)sym->st_size);
      return 1;
   }

   const long sym_sec_off = sym->st_value - section->sh_addr;
   const long sym_file_off = section->sh_offset + sym_sec_off;
   memcpy((char *)h + sym_file_off, val, len);
   return 0;
}

REGISTER_CMD(
   set_sym_strval,
   "--set-sym-strval",
   NULL, // short opt
   "<section> <symbol> <string value>",
   3,
   &set_sym_strval
)

/* ------------------------------------------------------------------------- */

static int
dump_sym(struct elf_file_info *nfo, const char *name_or_index)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Shdr *sections = (Elf_Shdr *) ((char *)h + h->e_shoff);
   Elf_Sym *sym = get_symbol(h, name_or_index, NULL);

   if (!sym) {
      fprintf(stderr, "ERROR: Symbol '%s' not found\n", name_or_index);
      return 1;
   }

   Elf_Shdr *section = sections + sym->st_shndx;
   const long sym_sec_off = sym->st_value - section->sh_addr;
   const long sym_file_off = section->sh_offset + sym_sec_off;

   for (unsigned i = 0; i < sym->st_size; i++)
      printf("%02x ", *((unsigned char *)h + sym_file_off + i));

   printf("\n");
   return 0;
}

REGISTER_CMD(
   dump_sym,
   "--dump-sym",
   "-ds",
   "<symbol>",
   1,
   &dump_sym
)

/* ------------------------------------------------------------------------- */

static int
get_sym_value(struct elf_file_info *nfo, const char *name_or_index)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Sym *sym = get_symbol(h, name_or_index, NULL);

   if (!sym) {
      fprintf(stderr, "ERROR: Symbol '%s' not found\n", name_or_index);
      return 1;
   }

   printf("0x%08lx\n", (unsigned long)sym->st_value);
   return 0;
}

REGISTER_CMD(
   get_sym_value,
   "--get-sym-value",
   "-v", // short opt
   "<symbol>",
   1,
   &get_sym_value
)

/* ------------------------------------------------------------------------- */


static int
list_syms(struct elf_file_info *nfo)
{
   unsigned sym_count;
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Sym *syms = get_symbols_ptr(h, &sym_count);

   if (!syms) {
      fprintf(stderr, "ERROR: No symbol table\n");
      return 1;
   }

   for (unsigned i = 0; i < sym_count; i++) {
      Elf_Sym *s = syms + i;
      const char *s_name = get_symbol_name(h, s);
      printf("%5u %014llx %10llu %-10s %-10s %-10s %5u %s\n",
             i,                                 /* index                 */
             (unsigned long long)s->st_value,   /* offset within section */
             (unsigned long long)s->st_size,    /* size                  */
             sym_get_type_str(ELF_ST_TYPE(s->st_info)),
             sym_get_bind_str(ELF_ST_BIND(s->st_info)),
             sym_get_visibility_str(ELF_ST_VISIBILITY(s->st_other)),
             s->st_shndx,
             s_name);
   }

   return 0;
}

REGISTER_CMD(
   list_syms,
   "--list-syms",
   "-s", // short opt
   "List all the symbols in .symtab",
   0,
   &list_syms
)

/* ------------------------------------------------------------------------- */

static int
get_sym_info(struct elf_file_info *nfo, const char *name_or_index)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Sym *sym = get_symbol(h, name_or_index, NULL);
   Elf_Shdr *sections = (Elf_Shdr *) ((char *)h + h->e_shoff);
   Elf_Shdr *section_header_strtab = sections + h->e_shstrndx;

   if (!sym) {
      fprintf(stderr, "ERROR: Symbol '%s' not found\n", name_or_index);
      return 1;
   }

   Elf_Shdr *s = sections + sym->st_shndx;
   char *sh_name = (char *)h + section_header_strtab->sh_offset + s->sh_name;

   printf("st_info:  0x%02x # bind: %d (%s), type: %d (%s)\n",
          sym->st_info,
          ELF_ST_BIND(sym->st_info),
          sym_get_bind_str(ELF_ST_BIND(sym->st_info)),
          ELF_ST_TYPE(sym->st_info),
          sym_get_type_str(ELF_ST_TYPE(sym->st_info)));

   printf("st_other: 0x%02x # visibility: %d (%s)\n",
          sym->st_other,
          ELF_ST_VISIBILITY(sym->st_other),
          sym_get_visibility_str(ELF_ST_VISIBILITY(sym->st_other)));

   if (sym->st_shndx)
      printf("st_shndx: %d # %s\n", sym->st_shndx, sh_name);
   else
      printf("st_shndx: %d\n", sym->st_shndx);

   printf("st_value: 0x%08lx\n", (long) sym->st_value);
   printf("st_size:  0x%08lx\n", (long) sym->st_size);

   return 0;
}

REGISTER_CMD(
   get_sym_info,
   "--get-sym-info",
   "-si", // short opt
   "<symbol>",
   1,
   &get_sym_info
)

/* ------------------------------------------------------------------------- */

static int
set_sym_bind(struct elf_file_info *nfo,
             const char *name_or_index,
             const char *bind_str)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Sym *sym = get_symbol(h, name_or_index, NULL);
   const char *exp_end = bind_str + strlen(bind_str);
   char *endptr = NULL;
   unsigned long bind_n;

   if (!sym) {
      fprintf(stderr, "ERROR: Symbol '%s' not found\n", name_or_index);
      return 1;
   }

   errno = 0;
   bind_n = strtoul(bind_str, &endptr, 10);

   if (errno || endptr != exp_end) {
      fprintf(stderr, "ERROR: invalid bind param\n");
      return 1;
   }

   if (bind_n > STB_HIPROC) {
      fprintf(stderr, "ERROR: bind is too high");
      return 1;
   }

   sym->st_info = ELF_ST_INFO(bind_n, ELF_ST_TYPE(sym->st_info));
   return 0;
}

REGISTER_CMD(
   set_sym_bind,
   "--set-sym-bind",
   NULL, // short opt
   "<symbol> <bind num>",
   2,
   &set_sym_bind
)


/* ------------------------------------------------------------------------- */

static int
set_sym_type(struct elf_file_info *nfo,
             const char *name_or_index,
             const char *type_str)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Sym *sym = get_symbol(h, name_or_index, NULL);
   const char *exp_end = type_str + strlen(type_str);
   char *endptr = NULL;
   unsigned long type_n;

   if (!sym) {
      fprintf(stderr, "ERROR: Symbol '%s' not found\n", name_or_index);
      return 1;
   }

   errno = 0;
   type_n = strtoul(type_str, &endptr, 10);

   if (errno || endptr != exp_end) {
      fprintf(stderr, "ERROR: invalid type param\n");
      return 1;
   }

   if (type_n > STT_HIPROC) {
      fprintf(stderr, "ERROR: type is too high");
      return 1;
   }

   sym->st_info = ELF_ST_INFO(ELF_ST_BIND(sym->st_info), type_n);
   return 0;
}

REGISTER_CMD(
   set_sym_type,
   "--set-sym-type",
   NULL, // short opt
   "<symbol> <type num>",
   2,
   &set_sym_type
)

/* ------------------------------------------------------------------------- */

static int
undef_sym(struct elf_file_info *nfo,
          const char *name_or_index)
{
   unsigned sym_count, index;
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Sym *syms = get_symbols_ptr(h, &sym_count);

   if (!syms) {
      fprintf(stderr, "ERROR: No symbol table\n");
      return 1;
   }

   Elf_Sym *sym = get_symbol(h, name_or_index, &index);

   if (!sym) {
      fprintf(stderr, "ERROR: Symbol '%s' not found\n", name_or_index);
      return 1;
   }

   sym->st_info = ELF_ST_INFO(STB_GLOBAL, STT_NOTYPE);
   sym->st_other = 0;
   sym->st_shndx = 0;
   sym->st_value = 0;
   sym->st_size = 0;
   return 0;
}

REGISTER_CMD(
   undef_sym,
   "--undef-sym",
   "-u", // short opt
   "<symbol> (breaks the symtab sorting!)",
   1,
   &undef_sym
)

/* ------------------------------------------------------------------------- */

static int
swap_symbols(struct elf_file_info *nfo,
             const char *index1_str,
             const char *index2_str)
{
   unsigned sym_count;
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Sym *syms = get_symbols_ptr(h, &sym_count);

   if (!syms) {
      fprintf(stderr, "ERROR: No symbol table!\n");
      return 1;
   }

   int idx1 = atoi(index1_str);
   int idx2 = atoi(index2_str);

   if (idx1 <= 0) {
      fprintf(stderr, "Invalid symbol index: %s", index1_str);
      return 1;
   }
   if (idx2 <= 0) {
      fprintf(stderr, "Invalid symbol index: %s", index2_str);
      return 1;
   }

   if (idx1 > (int)sym_count) {
      fprintf(stderr, "ERROR: Symbol index %d out of bounds", idx1);
      return 1;
   }

   if (idx2 > (int)sym_count) {
      fprintf(stderr, "ERROR: Symbol index %d out of bounds", idx2);
      return 1;
   }

   swap_symbols_index(h, idx1, idx2);
   return 0;
}

REGISTER_CMD(
   swap_symbols,
   "--swap-symbols",
   NULL, // short opt
   "<index1> <index2> (EXPERIMENTAL)",
   2,
   &swap_symbols
)
