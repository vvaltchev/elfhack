/* SPDX-License-Identifier: BSD-2-Clause */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "elfhack/misc.h"
#include "elfhack/elf_utils.h"

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
   #define HOST_ELF_DATA      ELFDATA2LSB
#else
   #define HOST_ELF_DATA      ELFDATA2MSB
#endif

int
elf_file_map(struct elf_file_info *nfo)
{
   struct stat statbuf;
   size_t mmap_size;
   long page_size;
   void *vaddr;
   int prot;

   assert(!nfo->vaddr);

   if (fstat(nfo->fd, &statbuf) < 0) {
      perror("fstat failed");
      return 1;
   }

   /*
    * The mapping is rounded up to a whole page and the bytes past the end of
    * the file read as zeros: without this check, a truncated file would pass
    * for an ELF whose header fields are all 0.
    */
   if ((size_t)statbuf.st_size < sizeof(Elf_Ehdr)) {
      fprintf(stderr,
              "ERROR: %s is too small to be an ELF file\n", nfo->path);
      return 1;
   }

   page_size = sysconf(_SC_PAGESIZE);

   if (page_size <= 0) {
      fprintf(stderr, "Unable to get page size. Got: %ld\n", page_size);
      return 1;
   }

   mmap_size =
      pow2_round_up_at((size_t)statbuf.st_size, (unsigned long)page_size);

   prot = nfo->writable ? PROT_READ | PROT_WRITE : PROT_READ;

   vaddr = mmap(NULL,                   /* addr */
                mmap_size,              /* length */
                prot,                   /* prot */
                MAP_SHARED,             /* flags */
                nfo->fd,                /* fd */
                0);                     /* offset */

   if (vaddr == MAP_FAILED) {
      perror("mmap failed");
      return 1;
   }

   nfo->vaddr = vaddr;
   nfo->mmap_size = mmap_size;
   return 0;
}

void
elf_file_unmap(struct elf_file_info *nfo)
{
   if (!nfo->vaddr)
      return;

   if (munmap(nfo->vaddr, nfo->mmap_size) < 0)
      perror("munmap() failed");

   nfo->vaddr = NULL;
   nfo->mmap_size = 0;
}

int
elf_header_type_check(struct elf_file_info *nfo)
{
   Elf32_Ehdr *h = nfo->vaddr;

   if (h->e_ident[EI_MAG0] != ELFMAG0 ||
       h->e_ident[EI_MAG1] != ELFMAG1 ||
       h->e_ident[EI_MAG2] != ELFMAG2 ||
       h->e_ident[EI_MAG3] != ELFMAG3)
   {
      fprintf(stderr, "Not a valid ELF binary (magic doesn't match)\n");
      return 1;
   }

   /* The fields are read in the host's byte order, as they are */
   if (h->e_ident[EI_DATA] != HOST_ELF_DATA) {
      fprintf(stderr,
              "ERROR: unsupported byte order (EI_DATA: %u): only the "
              "host's byte order is supported\n", h->e_ident[EI_DATA]);
      return 1;
   }

   if (sizeof(Elf_Addr) == 4) {

      if (h->e_ident[EI_CLASS] != ELFCLASS32) {
         fprintf(stderr, "ERROR: expected 32-bit binary\n");
         return 1;
      }

   } else {

      if (h->e_ident[EI_CLASS] != ELFCLASS64) {
         fprintf(stderr, "ERROR: expected 64-bit binary\n");
         return 1;
      }
   }

   return 0;
}

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

const char *
sym_get_shndx_str(unsigned shndx)
{
   switch (shndx) {

      case SHN_UNDEF:
         return "UNDEF";

      case SHN_ABS:
         return "ABS";

      case SHN_COMMON:
         return "COMMON";

      case SHN_XINDEX:
         return "XINDEX";

      default:

         if (SHN_LOOS <= shndx && shndx <= SHN_HIOS)
            return "os-spec-index";

         if (SHN_LOPROC <= shndx && shndx <= SHN_HIPROC)
            return "cpu-spec-index";
   }

   return "?";
}

Elf_Shdr *
get_section_by_name(Elf_Ehdr *h,
                    const char *section_name,
                    unsigned *out_index)
{
   Elf_Shdr *sections = (Elf_Shdr *) ((char *)h + h->e_shoff);
   Elf_Shdr *section_header_strtab = sections + h->e_shstrndx;
   Elf_Shdr *result = NULL;

   for (uint32_t i = 0; i < h->e_shnum; i++) {

      Elf_Shdr *s = sections + i;
      char *name = (char *)h + section_header_strtab->sh_offset + s->sh_name;

      if (!strcmp(name, section_name)) {

         if (!result) {

            result = s;
            if (out_index) {
               *out_index = i;
            }
            assert(i == get_index_of_section(h, result));

         } else {

            fprintf(stderr,
                    "ERROR: multiple sections named '%s'\n",
                    section_name);
            exit(1);
         }
      }
   }

   return result;
}

unsigned
get_index_of_section(Elf_Ehdr *h, Elf_Shdr *sec)
{
   Elf_Shdr *sections = (Elf_Shdr *) ((char *)h + h->e_shoff);
   const ptrdiff_t index = sec - sections;

   if (index < 0 || index >= h->e_shnum) {
      fprintf(stderr, "ERROR: invalid section pointer %p\n", sec);
      exit(1);
   }

   return (unsigned)index;
}

Elf_Shdr *
get_section_by_index(Elf_Ehdr *h, unsigned index)
{
   Elf_Shdr *sections = (Elf_Shdr *) ((char *)h + h->e_shoff);

   if (index >= h->e_shnum) {
      fprintf(stderr, "ERROR: invalid section index %u\n", index);
      exit(1);
   }

   return sections + index;
}

Elf_Sym *
get_symbols_ptr(Elf_Ehdr *h, unsigned *sym_count)
{
   Elf_Shdr *symtab = get_section_by_name(h, ".symtab", NULL);

   if (!symtab)
      return NULL;

   /*
    * The entries are accessed as an array of Elf_Sym: any other entry size
    * would make the count and the stride disagree (and 0 would divide by 0).
    */
   if (symtab->sh_entsize != sizeof(Elf_Sym)) {
      fprintf(stderr,
              "ERROR: invalid .symtab: sh_entsize is %llu, expected %zu\n",
              (unsigned long long)symtab->sh_entsize, sizeof(Elf_Sym));
      exit(1);
   }

   *sym_count = symtab->sh_size / sizeof(Elf_Sym);
   return (Elf_Sym *)((char *)h + symtab->sh_offset);
}

bool
is_symtab_reloc_section(Elf_Ehdr *h, Elf_Shdr *sec)
{
   unsigned symtab_index;

   if (sec->sh_type != SHT_REL && sec->sh_type != SHT_RELA)
      return false;

   if (!get_section_by_name(h, ".symtab", &symtab_index))
      return false;

   return sec->sh_link == symtab_index;
}

Elf_Shdr *
get_symbols_strtab(Elf_Ehdr *h)
{
   Elf_Shdr *symtab = get_section_by_name(h, ".symtab", NULL);
   Elf_Shdr *sections = (Elf_Shdr *) ((char *)h + h->e_shoff);
   Elf_Shdr *strtab = NULL;

   if (!symtab)
      return NULL;

   if (symtab->sh_link < h->e_shnum)
      strtab = sections + symtab->sh_link;

   if (!strtab || strtab->sh_type != SHT_STRTAB) {
      fprintf(stderr,
              "ERROR: .symtab links to section %u, "
              "which is not a string table\n", symtab->sh_link);
      exit(1);
   }

   return strtab;
}

int
get_index_of_symbol(Elf_Ehdr *h, Elf_Sym *symbol)
{
   unsigned sym_count;
   Elf_Sym *syms = get_symbols_ptr(h, &sym_count);
   ptrdiff_t index;

   if (!syms)
      return -1;

   index = symbol - syms;
   if (index < 0 || index >= (ptrdiff_t)sym_count) {
      fprintf(stderr, "ERROR: Invalid symbol pointer %p\n", symbol);
      exit(1);
   }

   return (int)index;
}

const char *
get_symbol_name(Elf_Ehdr *h, Elf_Shdr *strtab, Elf_Sym *s)
{
   Elf_Shdr *sections = (Elf_Shdr *) ((char *)h + h->e_shoff);
   Elf_Shdr *section_header_strtab = sections + h->e_shstrndx;
   const char *name;

   if (ELF_ST_TYPE(s->st_info) == STT_SECTION) {

      Elf_Shdr *sec = get_sym_section(h, s);

      if (sec)
         name = (char *)h + section_header_strtab->sh_offset + sec->sh_name;
      else
         name = ""; /* a section symbol without a section: no name */

   } else {

      assert(strtab);
      name = (char *)h + strtab->sh_offset + s->st_name;
   }

   return name;
}

Elf_Sym *
get_symbol_by_index(Elf_Ehdr *h, unsigned index)
{
   unsigned sym_count;
   Elf_Sym *syms = get_symbols_ptr(h, &sym_count);

   if (!syms) {
      fprintf(stderr, "Warning: no symbol table\n");
      return NULL;
   }

   if (index >= sym_count) {
      fprintf(stderr, "ERROR: invalid symbol index %u\n", index);
      exit(1);
   }

   return syms + index;
}

Elf_Sym *
get_symbol_by_name(Elf_Ehdr *h,
                   const char *sym_name,
                   unsigned *out_index)
{
   unsigned sym_count;
   Elf_Sym *syms = get_symbols_ptr(h, &sym_count);
   Elf_Shdr *strtab = get_symbols_strtab(h);
   Elf_Sym *result = NULL;

   if (!syms)
      return NULL;

   for (unsigned i = 0; i < sym_count; i++) {

      Elf_Sym *s = syms + i;
      const char *s_name = get_symbol_name(h, strtab, s);

      if (!s_name)
         continue; // unnamed symbol: skip

      if (strcmp(s_name, sym_name))
         continue; // no match

      // the symbol name matches
      if (!result) {

         result = s;
         if (out_index) {
            *out_index = i;
         }
         assert(get_index_of_symbol(h, result) == (int)i);

      } else {
         fprintf(stderr, "ERROR: multiple symbols named '%s'\n", sym_name);
         exit(1);
      }
   }

   return result;
}


size_t
elf_calc_mem_size(Elf_Ehdr *h)
{
   Elf_Phdr *phdrs = (Elf_Phdr *)((char*)h + h->e_phoff);
   Elf_Addr min_pbegin = 0;
   Elf_Addr max_pend = 0;
   bool found = false;

   for (uint32_t i = 0; i < h->e_phnum; i++) {

      Elf_Phdr *p = phdrs + i;
      Elf_Addr align, pend;

      /*
       * Only the PT_LOAD segments occupy memory: the others (PT_GNU_STACK,
       * PT_NOTE, ...) describe something else, and PT_GNU_STACK in
       * particular has p_paddr 0, which would stretch the image down to
       * address 0.
       */
      if (p->p_type != PT_LOAD)
         continue;

      /* p_align 0 and 1 both mean "no alignment" */
      align = p->p_align ? p->p_align : 1;
      pend = pow2_round_up_at(p->p_paddr + p->p_memsz, align);

      if (!found || p->p_paddr < min_pbegin)
         min_pbegin = p->p_paddr;

      if (pend > max_pend)
         max_pend = pend;

      found = true;
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

   section_idx = get_index_of_section(h, sec);

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

   /*
    * SHN_UNDEF and the reserved indexes (SHN_ABS, SHN_COMMON, ...) are not
    * positions in the section table.
    */
   if (sym->st_shndx == SHN_UNDEF ||
       sym->st_shndx >= SHN_LORESERVE ||
       sym->st_shndx >= h->e_shnum)
   {
      return NULL;
   }

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

   int sym_index = get_index_of_symbol(h, sym);

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

      Elf_Rel *rel = (void *)((char *)h + sec->sh_offset);
      unsigned count = sec->sh_size / sec->sh_entsize;

      for (unsigned i = 0; i < count; i++) {
         Elf_Rel *r = rel + i;
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

   int index1 = get_index_of_symbol(h, s1);
   int index2 = get_index_of_symbol(h, s2);

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

   if (idx1 < 0 || idx1 >= (int)sym_count) {
      fprintf(stderr, "ERROR: Symbol index %d out of bounds\n", idx1);
      abort();
   }

   if (idx2 < 0 || idx2 >= (int)sym_count) {
      fprintf(stderr, "ERROR: Symbol index %d out of bounds\n", idx2);
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

      if (!is_symtab_reloc_section(h, s))
         continue;

      redirect_rel_internal_index(h, s, idx1, idx2, true);
   }
}
