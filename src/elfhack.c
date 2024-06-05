/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * A tool for hacking ELF binaries.
 *
 * Imported from the Tilck project:
 * https://github.com/vvaltchev/tilck
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <errno.h>

#include <elf.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define KB           (1024)
#define MB      (1024 * KB)
#define GB      (1024 * GB)

#define ARRAY_SIZE(a)        ((int)(sizeof(a)/sizeof((a)[0])))
#define TO_PTR(n)            ((void *)(unsigned long)(n))
#define UNUSED_VARIABLE(x)   (void)x

#if defined(USE_ELF32) && defined(USE_ELF64)
   #error Invalid configuration: USE_ELF32 and USE_ELF64 both defined.
#endif

#if defined(USE_ELF32) || (defined(__i386__) && !defined(USE_ELF64))

   typedef Elf32_Addr Elf_Addr;
   typedef Elf32_Ehdr Elf_Ehdr;
   typedef Elf32_Phdr Elf_Phdr;
   typedef Elf32_Shdr Elf_Shdr;
   typedef Elf32_Sym Elf_Sym;
   typedef Elf32_Off Elf_Off;
   typedef Elf32_Word Elf_Word;

   #define ELF_ST_BIND(val)         ELF32_ST_BIND (val)
   #define ELF_ST_TYPE(val)         ELF32_ST_TYPE (val)
   #define ELF_ST_INFO(bind, type)  ELF32_ST_INFO ((bind), (type))
   #define ELF_ST_VISIBILITY(o)     ELF32_ST_VISIBILITY (o)

#elif defined(USE_ELF64) || ((defined(__x86_64__) || defined(__aarch64__)) \
                             && !defined(USE_ELF32))

   typedef Elf64_Addr Elf_Addr;
   typedef Elf64_Ehdr Elf_Ehdr;
   typedef Elf64_Phdr Elf_Phdr;
   typedef Elf64_Shdr Elf_Shdr;
   typedef Elf64_Sym Elf_Sym;
   typedef Elf64_Off Elf_Off;
   typedef Elf64_Word Elf_Word;

   #define ELF_ST_BIND(val)         ELF64_ST_BIND (val)
   #define ELF_ST_TYPE(val)         ELF64_ST_TYPE (val)
   #define ELF_ST_INFO(bind, type)  ELF64_ST_INFO ((bind), (type))
   #define ELF_ST_VISIBILITY(o)     ELF64_ST_VISIBILITY (o)

#else

   #error Unknown architecture

#endif

static unsigned long
pow2_round_up_at(unsigned long n, unsigned long pow2unit)
{
   return (n + pow2unit - 1) & -pow2unit;
}

static size_t
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

static Elf_Shdr *
elf_get_section(Elf_Ehdr *h, const char *section_name)
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

struct elf_file_info {

   const char *path;
   size_t mmap_size;
   void *vaddr;
   int fd;
};

typedef int (*cmd_func_0)(struct elf_file_info *);

typedef int (*cmd_func_1)(struct elf_file_info *,
                          const char *);

typedef int (*cmd_func_2)(struct elf_file_info *,
                          const char *,
                          const char *);

typedef int (*cmd_func_3)(struct elf_file_info *,
                          const char *,
                          const char *,
                          const char *);

struct elfhack_cmd {

   const char *opt;
   const char *help;
   int nargs;
   void *func;
};

int show_help(struct elf_file_info *nfo);

/* --- Low-level ELF utility functions --- */

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

Elf_Sym *
get_symbol(Elf_Ehdr *h, const char *sym_name)
{
   Elf_Shdr *symtab;
   Elf_Shdr *strtab;
   Elf_Sym *syms;
   unsigned sym_count;

   symtab = elf_get_section(h, ".symtab");
   strtab = elf_get_section(h, ".strtab");

   if (!symtab || !strtab)
      return NULL;

   syms = (Elf_Sym *)((char *)h + symtab->sh_offset);
   sym_count = symtab->sh_size / sizeof(Elf_Sym);

   for (unsigned i = 0; i < sym_count; i++) {

      Elf_Sym *s = syms + i;
      const char *s_name = (char *)h + strtab->sh_offset + s->st_name;

      if (!strcmp(s_name, sym_name))
         return s;
   }

   return NULL;
}

/* --- Actual commands --- */

int
section_bin_dump(struct elf_file_info *nfo, const char *section_name)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Shdr *s = elf_get_section(nfo->vaddr, section_name);

   if (!s) {
      fprintf(stderr, "No section '%s'\n", section_name);
      return 1;
   }

   fwrite((char*)h + s->sh_offset, 1, s->sh_size, stdout);
   return 0;
}

int
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

   s_src = elf_get_section(nfo->vaddr, src);

   if (!s_src) {
      fprintf(stderr, "No section '%s'\n", src);
      return 1;
   }

   s_dst = elf_get_section(nfo->vaddr, dst);

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

int
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

   Elf_Shdr *s = elf_get_section(nfo->vaddr, section_name);

   if (!s) {
      fprintf(stderr, "No section '%s'\n", section_name);
      return 1;
   }

   strcpy(hc + shstrtab->sh_offset + s->sh_name, new_name);
   return 0;
}

int
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

   Elf_Shdr *a = elf_get_section(nfo->vaddr, section_name);
   Elf_Shdr *b = elf_get_section(nfo->vaddr, linked);

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

int
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

int
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

int
set_phdr_rwx_flags(struct elf_file_info *nfo,
                   const char *phdr_index,
                   const char *flags)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   errno = 0;

   char *endptr = NULL;
   unsigned long phindex = strtoul(phdr_index, &endptr, 10);

   if (errno || *endptr != '\0') {
      fprintf(stderr, "Invalid phdr index '%s'\n", phdr_index);
      return 1;
   }

   if (phindex >= h->e_phnum) {
      fprintf(stderr, "Phdr index %lu out-of-range [0, %u].\n",
              phindex, h->e_phnum - 1);
      return 1;
   }

   if (!flags) {
      fprintf(stderr, "Missing <rwx flags> argument.\n");
      return 1;
   }

   char *hc = (char *)h;
   Elf_Phdr *phdrs = (Elf_Phdr *)(hc + h->e_phoff);
   Elf_Phdr *phdr = phdrs + phindex;

   unsigned f = 0;

   while (*flags) {
      switch (*flags) {
         case 'r':
            f |= PF_R;
            break;
         case 'w':
            f |= PF_W;
            break;
         case 'x':
            f |= PF_X;
            break;
         default:
            fprintf(stderr, "Invalid flag '%c'. Allowed: r,w,x.\n", *flags);
            return 1;
      }
      flags++;
   }

   // First, clear the already set RWX flags (be keep the others!)
   phdr->p_flags &= ~(PF_R | PF_W | PF_X);

   // Then, set the new RWX flags.
   phdr->p_flags |= f;
   return 0;
}

int
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

int
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

int
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

int
set_sym_strval(struct elf_file_info *nfo,
               const char *section_name,
               const char *sym_name,
               const char *val)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Shdr *section;
   Elf_Sym *sym;
   size_t len;

   if (!sym_name || !val) {
      fprintf(stderr, "Missing arguments\n");
      return 1;
   }

   section = elf_get_section(h, section_name);

   if (!section) {
      fprintf(stderr, "No section '%s'\n", section_name);
      return 1;
   }

   sym = get_symbol(h, sym_name);

   if (!sym) {
      fprintf(stderr, "Unable to find the symbol '%s'\n", sym_name);
      return 1;
   }

   if (sym->st_value < section->sh_addr ||
       sym->st_value + sym->st_size > section->sh_addr + section->sh_size)
   {
      fprintf(stderr,
              "Symbol '%s' not in section '%s'\n", sym_name, section_name);

      return 1;
   }

   len = strlen(val) + 1;

   if (sym->st_size < len) {
      fprintf(stderr, "Symbol '%s' [%u bytes] not big enough for value\n",
              sym_name, (unsigned)sym->st_size);
      return 1;
   }

   const long sym_sec_off = sym->st_value - section->sh_addr;
   const long sym_file_off = section->sh_offset + sym_sec_off;
   memcpy((char *)h + sym_file_off, val, len);
   return 0;
}

int
dump_sym(struct elf_file_info *nfo, const char *sym_name)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Shdr *sections = (Elf_Shdr *) ((char *)h + h->e_shoff);
   Elf_Sym *sym = get_symbol(h, sym_name);

   if (!sym) {
      fprintf(stderr, "Symbol '%s' not found\n", sym_name);
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

int
get_sym(struct elf_file_info *nfo, const char *sym_name)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Sym *sym = get_symbol(h, sym_name);

   if (!sym) {
      fprintf(stderr, "Symbol '%s' not found\n", sym_name);
      return 1;
   }

   printf("0x%08lx\n", (unsigned long)sym->st_value);
   return 0;
}

int
get_text_sym(struct elf_file_info *nfo, const char *sym_name)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Shdr *sections = (Elf_Shdr *) ((char *)h + h->e_shoff);
   Elf_Shdr *section_header_strtab = sections + h->e_shstrndx;
   Elf_Sym *sym = get_symbol(h, sym_name);

   if (!sym) {
      fprintf(stderr, "Symbol '%s' not found\n", sym_name);
      return 1;
   }

   if (sym->st_shndx > h->e_shnum) {
      fprintf(stderr, "ERROR: unknown section for symbol %s\n", sym_name);
      return 1;
   }

   Elf_Shdr *s = sections + sym->st_shndx;
   char *name = (char *)h + section_header_strtab->sh_offset + s->sh_name;

   if (strcmp(name, ".text")) {
      fprintf(stderr, "ERROR: the symbol belongs to section: %s\n", name);
      return 1;
   }

   printf("0x%08lx\n", (unsigned long)sym->st_value);
   return 0;
}

int
list_text_syms(struct elf_file_info *nfo)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Shdr *sections = (Elf_Shdr *) ((char *)h + h->e_shoff);
   Elf_Shdr *text = elf_get_section(h, ".text");
   Elf_Shdr *symtab;
   Elf_Shdr *strtab;
   Elf_Sym *syms;
   unsigned sym_count;
   unsigned text_sh_index;

   if (!text) {
      fprintf(stderr, "ERROR: cannot find the .text section\n");
      return 1;
   }

   text_sh_index = text - sections;

   symtab = elf_get_section(h, ".symtab");
   strtab = elf_get_section(h, ".strtab");

   if (!symtab || !strtab) {
      fprintf(stderr, "ERROR: no .symtab or .strtab in the binary\n");
      return 1;
   }

   syms = (Elf_Sym *)((char *)h + symtab->sh_offset);
   sym_count = symtab->sh_size / sizeof(Elf_Sym);

   for (unsigned i = 0; i < sym_count; i++) {

      Elf_Sym *s = syms + i;
      const char *s_name = (char *)h + strtab->sh_offset + s->st_name;

      if (s->st_shndx != text_sh_index)
         continue;

      printf("%s\n", s_name);
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

int
get_sym_info(struct elf_file_info *nfo, const char *sym_name)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Sym *sym = get_symbol(h, sym_name);
   Elf_Shdr *sections = (Elf_Shdr *) ((char *)h + h->e_shoff);
   Elf_Shdr *section_header_strtab = sections + h->e_shstrndx;

   if (!sym) {
      fprintf(stderr, "Symbol '%s' not found\n", sym_name);
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

int
set_sym_bind(struct elf_file_info *nfo,
             const char *sym_name,
             const char *bind_str)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Sym *sym = get_symbol(h, sym_name);
   const char *exp_end = bind_str + strlen(bind_str);
   char *endptr = NULL;
   unsigned long bind_n;

   if (!sym) {
      fprintf(stderr, "Symbol '%s' not found\n", sym_name);
      return 1;
   }

   errno = 0;
   bind_n = strtoul(bind_str, &endptr, 10);

   if (errno || endptr != exp_end) {
      fprintf(stderr, "error: invalid bind param\n");
      return 1;
   }

   if (bind_n > STB_HIPROC) {
      fprintf(stderr, "error: bind is too high");
      return 1;
   }

   sym->st_info = ELF_ST_INFO(bind_n, ELF_ST_TYPE(sym->st_info));
   return 0;
}

int
set_sym_type(struct elf_file_info *nfo,
             const char *sym_name,
             const char *type_str)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Sym *sym = get_symbol(h, sym_name);
   const char *exp_end = type_str + strlen(type_str);
   char *endptr = NULL;
   unsigned long type_n;

   if (!sym) {
      fprintf(stderr, "Symbol '%s' not found\n", sym_name);
      return 1;
   }

   errno = 0;
   type_n = strtoul(type_str, &endptr, 10);

   if (errno || endptr != exp_end) {
      fprintf(stderr, "error: invalid type param\n");
      return 1;
   }

   if (type_n > STT_HIPROC) {
      fprintf(stderr, "error: type is too high");
      return 1;
   }

   sym->st_info = ELF_ST_INFO(ELF_ST_BIND(sym->st_info), type_n);
   return 0;
}

int
undef_sym(struct elf_file_info *nfo, const char *sym_name)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Sym *sym = get_symbol(h, sym_name);

   if (!sym) {
      fprintf(stderr, "Symbol '%s' not found\n", sym_name);
      return 1;
   }

   sym->st_info = ELF_ST_INFO(STB_GLOBAL, STT_NOTYPE);
   sym->st_other = 0;
   sym->st_shndx = 0;
   sym->st_value = 0;
   sym->st_size = 0;
   return 0;
}

static struct elfhack_cmd cmds_list[] =
{
   {
      .opt = "--help",
      .help = "",
      .nargs = 0,
      .func = &show_help,
   },

   {
      .opt = "--section-bin-dump",
      .help = "<section name>",
      .nargs = 1,
      .func = &section_bin_dump,
   },

   {
      .opt = "--move-metadata",
      .help = "",
      .nargs = 0,
      .func = &move_metadata,
   },

   {
      .opt = "--copy",
      .help = "<src section> <dest section>",
      .nargs = 2,
      .func = &copy_section,
   },

   {
      .opt = "--rename",
      .help = "<section> <new_name>",
      .nargs = 2,
      .func = &rename_section,
   },

   {
      .opt = "--link",
      .help = "<section> <linked_section>",
      .nargs = 2,
      .func = &link_sections,
   },

   {
      .opt = "--drop-last-section",
      .help = "",
      .nargs = 0,
      .func = &drop_last_section,
   },

   {
      .opt = "--set-phdr-rwx-flags",
      .help = "<phdr index> <rwx flags>",
      .nargs = 2,
      .func = &set_phdr_rwx_flags,
   },

   {
      .opt = "--verify-flat-elf",
      .help = "",
      .nargs = 0,
      .func = &verify_flat_elf_file,
   },

   {
      .opt = "--check-entry-point",
      .help = "<expected>",
      .nargs = 1,
      .func = &check_entry_point,
   },

   {
      .opt = "--check-mem-size",
      .help = "<expected_max> <b|kb>",
      .nargs = 2,
      .func = &check_mem_size,
   },

   {
      .opt = "--set-sym-strval",
      .help = "<section> <sym> <string value>",
      .nargs = 3,
      .func = &set_sym_strval,
   },

   {
      .opt = "--dump-sym",
      .help = "<sym_name>",
      .nargs = 1,
      .func = &dump_sym,
   },

   {
      .opt = "--get-sym",
      .help = "<sym_name>",
      .nargs = 1,
      .func = &get_sym,
   },

   {
      .opt = "--get-text-sym",
      .help = "<sym_name>",
      .nargs = 1,
      .func = &get_text_sym,
   },

   {
      .opt = "--list-text-syms",
      .help = "",
      .nargs = 0,
      .func = &list_text_syms,
   },

   {
      .opt = "--get-sym-info",
      .help = "<sym_name>",
      .nargs = 1,
      .func = &get_sym_info,
   },

   {
      .opt = "--set-sym-bind",
      .help = "<sym_name> <bind num>",
      .nargs = 2,
      .func = &set_sym_bind,
   },

   {
      .opt = "--set-sym-type",
      .help = "<sym_name> <type num>",
      .nargs = 2,
      .func = &set_sym_type,
   },

   {
      .opt = "--undef-sym",
      .help = "<sym_name>",
      .nargs = 1,
      .func = &undef_sym,
   },
};

int
show_help(struct elf_file_info *nfo)
{
   UNUSED_VARIABLE(nfo);
   fprintf(stderr, "Usage:\n");

   for (int i = 0; i < ARRAY_SIZE(cmds_list); i++) {
      struct elfhack_cmd *c = &cmds_list[i];
      fprintf(stderr, "    elfhack <file> %s %s\n", c->opt, c->help);
   }

   return 0;
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

struct elfhack_cmd *
find_cmd(const char *opt)
{
   for (int i = 0; i < ARRAY_SIZE(cmds_list); i++) {
      if (!strcmp(opt, cmds_list[i].opt)) {
         return &cmds_list[i];
      }
   }

   return NULL;
}

int
run_cmds(struct elf_file_info *nfo, int argc, char **argv)
{
   struct elfhack_cmd *cmd = NULL;
   const char *opt;
   int rc = 0;

   while (argc > 0 && argv[0]) {

      opt = argv[0];
      cmd = find_cmd(opt);
      argc--; argv++;

      if (!cmd) {

         cmd = &cmds_list[0];    /* help */

      } else {

         if (argc < cmd->nargs) {
            fprintf(stderr, "ERROR: Invalid number of arguments for %s "
                    "(expected: %d, got: %d).\n", opt, cmd->nargs, argc);
            return 1;
         }
      }

      switch (cmd->nargs) {
         case 0:
            rc = ((cmd_func_0)cmd->func)(nfo);
            break;
         case 1:
            rc = ((cmd_func_1)cmd->func)(nfo, argv[0]);
            break;
         case 2:
            rc = ((cmd_func_2)cmd->func)(nfo, argv[0], argv[1]);
            break;
         case 3:
            rc = ((cmd_func_3)cmd->func)(nfo, argv[0], argv[1], argv[2]);
            break;
         default:
            abort();
      }

      argc += cmd->nargs;
      argv += cmd->nargs;
   }

   return rc;
}

int
main(int argc, char **argv)
{
   struct elf_file_info nfo = {0};
   struct stat statbuf;
   size_t page_size;
   int rc;

   if (argc <= 1 || !strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
      show_help(NULL);
      return 1;
   }

   nfo.path = argv[1];
   nfo.fd = open(nfo.path, O_RDWR);

   if (nfo.fd < 0) {
      perror("open failed");
      return 1;
   }

   if (fstat(nfo.fd, &statbuf) < 0) {
      perror("fstat failed");
      close(nfo.fd);
      return 1;
   }

   page_size = sysconf(_SC_PAGESIZE);

   if (page_size <= 0) {
      fprintf(stderr, "Unable to get page size. Got: %ld\n", (long)page_size);
      close(nfo.fd);
      return 1;
   }

   nfo.mmap_size = pow2_round_up_at((size_t)statbuf.st_size, page_size);

   errno = 0;
   nfo.vaddr = mmap(NULL,                   /* addr */
                    nfo.mmap_size,          /* length */
                    PROT_READ | PROT_WRITE, /* prot */
                    MAP_SHARED,             /* flags */
                    nfo.fd,                 /* fd */
                    0);                     /* offset */

   if (errno) {
      perror(NULL);
      return 1;
   }

   if (elf_header_type_check(&nfo)) {
      rc = 1;
      goto end;
   }

   rc = run_cmds(&nfo, argc - 2, argv + 2);

end:
   if (munmap(nfo.vaddr, nfo.mmap_size) < 0) {
      perror("munmap() failed");
   }

   close(nfo.fd);
   return rc;
}
