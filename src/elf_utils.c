/* SPDX-License-Identifier: BSD-2-Clause */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "elf_utils.h"

const char *
sym_get_bind_str(unsigned bind)
{
   switch (bind) {

      case STB_LOCAL:
         return "local";

      case STB_GLOBAL:
         return "global";

      case STB_WEAK:
         return "weak";

      case STB_GNU_UNIQUE:
         return "unique";

      default:

         if (STB_LOOS <= bind && bind <= STB_HIOS)
            return "os-spec-bind";

         if (STB_LOPROC <= bind && bind <= STB_HIPROC)
            return "cpu-spec-bind";
   }

   return "?";
}

const char *
sym_get_type_str(unsigned type)
{
   switch (type) {

      case STT_NOTYPE:
         return "notype";

      case STT_OBJECT:
         return "object";

      case STT_FUNC:
         return "func";

      case STT_SECTION:
         return "section";

      case STT_FILE:
         return "file";

      case STT_COMMON:
         return "common";

      case STT_TLS:
         return "tls";

      case STT_GNU_IFUNC:
         return "ifunc";

      default:

         if (STT_LOOS <= type && type <= STT_HIOS)
            return "os-spec-type";

         if (STT_LOPROC <= type && type <= STT_HIPROC)
            return "cpu-spec-type";
   }

   return "?";
}

const char *
sym_get_visibility_str(unsigned visibility)
{
   switch (visibility) {

      case STV_DEFAULT:
         return "default";

      case STV_INTERNAL:
         return "internal";

      case STV_HIDDEN:
         return "hidden";

      case STV_PROTECTED:
         return "protected";
   }

   return "?";
}

Elf_Shdr *
get_section(Elf_Ehdr *h, const char *section_name)
{
   Elf_Shdr *sections = (Elf_Shdr *) ((char *)h + h->e_shoff);
   Elf_Shdr *section_header_strtab = sections + h->e_shstrndx;

   for (uint32_t i = 0; i < h->e_shnum; i++) {

      Elf_Shdr *s = sections + i;
      char *name = (char *)h + section_header_strtab->sh_offset + s->sh_name;

      if (!strcmp(name, section_name)) {
         return s;
      }
   }

   return NULL;
}

int
get_section_index(Elf_Ehdr *h, Elf_Shdr *sec)
{
   Elf_Shdr *sections = (Elf_Shdr *) ((char *)h + h->e_shoff);
   for (uint32_t i = 0; i < h->e_shnum; i++) {

      Elf_Shdr *s = sections + i;

      if (s == sec)
         return (int)i;
   }

   return -1;
}

Elf_Sym *
get_symbols_ptr(Elf_Ehdr *h, unsigned *sym_count)
{
   Elf_Shdr *symtab;
   Elf_Sym *syms;
   symtab = get_section(h, ".symtab");

   if (!symtab) {
      return NULL;
   }

   syms = (Elf_Sym *)((char *)h + symtab->sh_offset);
   *sym_count = symtab->sh_size / symtab->sh_entsize;
   return syms;
}

int
get_symbol_index(Elf_Ehdr *h, Elf_Sym *symbol)
{
   unsigned sym_count;
   Elf_Sym *syms = get_symbols_ptr(h, &sym_count);

   if (!syms)
      return -1;

   for (unsigned i = 0; i < sym_count; i++) {
      Elf_Sym *s = syms + i;
      if (s == symbol)
         return i;
   }

   return -1;
}

const char *
get_symbol_name(Elf_Ehdr *h, Elf_Sym *s)
{
   Elf_Shdr *sections = (Elf_Shdr *) ((char *)h + h->e_shoff);
   Elf_Shdr *strtab = get_section(h, ".strtab");
   Elf_Shdr *section_header_strtab = sections + h->e_shstrndx;
   const char *name = NULL;

   if (ELF_ST_TYPE(s->st_info) == STT_SECTION) {

      Elf_Shdr *sec = sections + s->st_shndx;
      name = (char *)h + section_header_strtab->sh_offset + sec->sh_name;

   } else {

      if (strtab)
         name = (char *)h + strtab->sh_offset + s->st_name;
   }

   return name;
}

Elf_Sym *
get_symbol(Elf_Ehdr *h, const char *sym_name, unsigned *index)
{
   unsigned sym_count;
   Elf_Sym *syms = get_symbols_ptr(h, &sym_count);

   if (!syms)
      return NULL;

   for (unsigned i = 0; i < sym_count; i++) {

      Elf_Sym *s = syms + i;
      const char *s_name = get_symbol_name(h, s);

      if (!s_name)
         continue;

      if (!strcmp(s_name, sym_name)) {
         if (index) {
            *index = i;
         }
         return s;
      }
   }

   return NULL;
}

size_t
elf_calc_mem_size(Elf_Ehdr *h)
{
   Elf_Phdr *phdrs = (Elf_Phdr *)((char*)h + h->e_phoff);
   Elf_Addr min_pbegin = 0;
   Elf_Addr max_pend = 0;

   for (uint32_t i = 0; i < h->e_phnum; i++) {

      Elf_Phdr *p = phdrs + i;
      Elf_Addr pend = pow2_round_up_at(p->p_paddr + p->p_memsz, p->p_align);

      if (i == 0 || p->p_paddr < min_pbegin)
         min_pbegin = p->p_paddr;

      if (pend > max_pend)
         max_pend = pend;
   }

   return max_pend - min_pbegin;
}

Elf_Sym *
get_section_symbol_obj(Elf_Ehdr *h, Elf_Shdr *sec)
{
   int section_idx;
   unsigned sym_count;
   Elf_Sym *syms = get_symbols_ptr(h, &sym_count);

   if (!syms)
      return NULL;

   section_idx = get_section_index(h, sec);

   if (section_idx < 0)
      return NULL;

   for (unsigned i = 0; i < sym_count; i++) {

      Elf_Sym *s = syms + i;
      unsigned symType = ELF_ST_TYPE(s->st_info);

      if (symType == STT_SECTION) {

         if (s->st_shndx == section_idx)
            return s;
      }
   }

   return NULL;
}

Elf_Shdr *
get_sym_section(Elf_Ehdr *h, Elf_Sym *sym)
{
   Elf_Shdr *sections = (Elf_Shdr *) ((char *)h + h->e_shoff);
   return sections + sym->st_shndx;
}

const char *
get_section_name(Elf_Ehdr *h, Elf_Shdr *section)
{
   Elf_Shdr *sections = (Elf_Shdr *) ((char *)h + h->e_shoff);
   Elf_Shdr *section_header_strtab = sections + h->e_shstrndx;

   if (section->sh_type == SHT_NULL) {
      /* Empty entries in the section table do NOT have a name */
      return NULL;
   }

   return (const char *)h +
          section_header_strtab->sh_offset + section->sh_name;
}

Elf_Phdr *
get_phdr_for_section(Elf_Ehdr *h, Elf_Shdr *section)
{
   Elf_Phdr *phdrs = (Elf_Phdr *)((char*)h + h->e_phoff);
   Elf_Addr sh_begin = section->sh_addr;
   Elf_Addr sh_end = section->sh_addr + section->sh_size;

   for (uint32_t i = 0; i < h->e_phnum; i++) {

      Elf_Phdr *p = phdrs + i;
      Elf_Addr pend = p->p_vaddr + p->p_memsz;

      if (p->p_vaddr <= sh_begin && sh_end <= pend)
         return p;
   }

   return NULL;
}

void
remove_rel_entries_for_sym(Elf_Ehdr *h, Elf_Shdr *rela_sec, Elf_Sym *sym)
{
   if (rela_sec->sh_type != SHT_REL && rela_sec->sh_type != SHT_RELA)
      abort();

   int sym_index = get_symbol_index(h, sym);

   if (sym_index < 0)
      abort();

   if (rela_sec->sh_type == SHT_RELA) {

      Elf_Rela *rela = (void *)((char *)h + rela_sec->sh_offset);
      unsigned count = rela_sec->sh_size / rela_sec->sh_entsize;

      for (unsigned i = 0; i < count; i++) {
         Elf_Rela *r = rela + i;
         if (ELF_R_SYM(r->r_info) == (size_t)sym_index) {
            memset(r, 0, sizeof(*r));
         }
      }

   } else {

      Elf_Rel *rel = (void *)((char *)h + rela_sec->sh_offset);
      unsigned count = rela_sec->sh_size / rela_sec->sh_entsize;

      for (unsigned i = 0; i < count; i++) {
         Elf_Rel *r = rel + i;
         if (ELF_R_SYM(r->r_info) == (size_t)sym_index) {
            memset(r, 0, sizeof(*r));
         }
      }
   }
}

void
redirect_rel_internal_index(Elf_Ehdr *h,
                            Elf_Shdr *sec,
                            unsigned index1,
                            unsigned index2,
                            bool swap)
{
   if (sec->sh_type != SHT_REL && sec->sh_type != SHT_RELA)
      abort();

   if (sec->sh_type == SHT_RELA) {

      Elf_Rela *rela = (void *)((char *)h + sec->sh_offset);
      unsigned count = sec->sh_size / sec->sh_entsize;

      for (unsigned i = 0; i < count; i++) {
         Elf_Rela *r = rela + i;
         if (ELF_R_SYM(r->r_info) == index1) {
            r->r_info = ELF_R_INFO(index2, ELF_R_TYPE(r->r_info));
         } else if (swap && ELF_R_SYM(r->r_info) == index2) {
            r->r_info = ELF_R_INFO(index1, ELF_R_TYPE(r->r_info));
         }
      }

   } else {

      Elf_Rela *rel = (void *)((char *)h + sec->sh_offset);
      unsigned count = sec->sh_size / sec->sh_entsize;

      for (unsigned i = 0; i < count; i++) {
         Elf_Rela *r = rel + i;
         if (ELF_R_SYM(r->r_info) == index1) {
            r->r_info = ELF_R_INFO(index2, ELF_R_TYPE(r->r_info));
         } else if (swap && ELF_R_SYM(r->r_info) == index2) {
            r->r_info = ELF_R_INFO(index1, ELF_R_TYPE(r->r_info));
         }
      }
   }
}

void
redirect_rel_internal(Elf_Ehdr *h, Elf_Shdr *sec, Elf_Sym *s1, Elf_Sym *s2)
{
   if (sec->sh_type != SHT_REL && sec->sh_type != SHT_RELA)
      abort();

   int index1 = get_symbol_index(h, s1);
   int index2 = get_symbol_index(h, s2);

   if (index1 < 0 || index2 < 0) {
      abort();
   }

   redirect_rel_internal_index(h, sec, index1, index2, false);
}

void
swap_symbols_index(Elf_Ehdr *h, int idx1, int idx2)
{
   unsigned sym_count;
   Elf_Sym *syms = get_symbols_ptr(h, &sym_count);

   if (!syms) {
      fprintf(stderr, "ERROR: No symbol table\n");
      abort();
   }

   if (idx1 < 0 || idx1 > (int)sym_count) {
      fprintf(stderr, "ERROR: Symbol index %d out of bounds", idx1);
      abort();
   }

   if (idx2 < 0 || idx2 > (int)sym_count) {
      fprintf(stderr, "ERROR: Symbol index %d out of bounds", idx2);
      abort();
   }

   if (idx1 == idx2)
      return;

   Elf_Sym tmp = syms[idx1];
   syms[idx1] = syms[idx2];
   syms[idx2] = tmp;

   Elf_Shdr *sections = (Elf_Shdr *) ((char *)h + h->e_shoff);
   for (uint32_t i = 0; i < h->e_shnum; i++) {

      Elf_Shdr *s = sections + i;

      if (s->sh_type != SHT_REL && s->sh_type != SHT_RELA)
         continue;

      /* Rel or Rela section */
      redirect_rel_internal_index(h, s, idx1, idx2, true);
   }
}
