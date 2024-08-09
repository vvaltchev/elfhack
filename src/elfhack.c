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
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "basic_defs.h"
#include "elf_utils.h"

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

   struct elfhack_cmd *next;

   const char *opt;
   const char *help;
   int nargs;
   void *func;
};

struct elfhack_cmd *options_head;
struct elfhack_cmd *options_tail;

void register_cmd_struct(struct elfhack_cmd *cmd)
{
   if (!options_tail) {

      assert(!options_head);
      options_head = cmd;
      options_tail = cmd;

   } else {

      options_tail->next = cmd;
      options_tail = cmd;
   }
}

#define REGISTER_CMD(name, long_opt, help_str, nargs_val, handler)   \
   static struct elfhack_cmd __cmd_##name = {                        \
      .next = NULL,                                                  \
      .opt = long_opt,                                               \
      .help = help_str,                                              \
      .nargs = nargs_val,                                            \
      .func = handler                                                \
   };                                                                \
   static void __attribute__((constructor))                          \
   __register_cmd_##name(void) {                                     \
      register_cmd_struct(&__cmd_##name);                            \
   }

int show_help(struct elf_file_info *nfo);

static int
section_bin_dump(struct elf_file_info *nfo, const char *section_name)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Shdr *s = get_section(nfo->vaddr, section_name);

   if (!s) {
      fprintf(stderr, "No section '%s'\n", section_name);
      return 1;
   }

   fwrite((char*)h + s->sh_offset, 1, s->sh_size, stdout);
   return 0;
}

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

   s_src = get_section(nfo->vaddr, src);

   if (!s_src) {
      fprintf(stderr, "No section '%s'\n", src);
      return 1;
   }

   s_dst = get_section(nfo->vaddr, dst);

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

   Elf_Shdr *s = get_section(nfo->vaddr, section_name);

   if (!s) {
      fprintf(stderr, "No section '%s'\n", section_name);
      return 1;
   }

   strcpy(hc + shstrtab->sh_offset + s->sh_name, new_name);
   return 0;
}

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

   Elf_Shdr *a = get_section(nfo->vaddr, section_name);
   Elf_Shdr *b = get_section(nfo->vaddr, linked);

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

static int
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

static int
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

   section = get_section(h, section_name);

   if (!section) {
      fprintf(stderr, "No section '%s'\n", section_name);
      return 1;
   }

   sym = get_symbol(h, sym_name, NULL);

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
      fprintf(stderr, "ERROR: Symbol '%s' [%u bytes] not big enough for value\n",
              sym_name, (unsigned)sym->st_size);
      return 1;
   }

   const long sym_sec_off = sym->st_value - section->sh_addr;
   const long sym_file_off = section->sh_offset + sym_sec_off;
   memcpy((char *)h + sym_file_off, val, len);
   return 0;
}

static int
dump_sym(struct elf_file_info *nfo, const char *sym_name)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Shdr *sections = (Elf_Shdr *) ((char *)h + h->e_shoff);
   Elf_Sym *sym = get_symbol(h, sym_name, NULL);

   if (!sym) {
      fprintf(stderr, "ERROR: Symbol '%s' not found\n", sym_name);
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

static int
get_sym(struct elf_file_info *nfo, const char *sym_name)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Sym *sym = get_symbol(h, sym_name, NULL);

   if (!sym) {
      fprintf(stderr, "ERROR: Symbol '%s' not found\n", sym_name);
      return 1;
   }

   printf("0x%08lx\n", (unsigned long)sym->st_value);
   return 0;
}

static int
get_text_sym(struct elf_file_info *nfo, const char *sym_name)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Shdr *sections = (Elf_Shdr *) ((char *)h + h->e_shoff);
   Elf_Shdr *section_header_strtab = sections + h->e_shstrndx;
   Elf_Sym *sym = get_symbol(h, sym_name, NULL);

   if (!sym) {
      fprintf(stderr, "ERROR: Symbol '%s' not found\n", sym_name);
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

static int
list_text_syms(struct elf_file_info *nfo)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Shdr *sections = (Elf_Shdr *) ((char *)h + h->e_shoff);
   Elf_Shdr *text = get_section(h, ".text");
   Elf_Shdr *strtab;
   unsigned text_sh_index;
   unsigned sym_count;
   Elf_Sym *syms = get_symbols_ptr(h, &sym_count);

   if (!syms) {
      fprintf(stderr, "ERROR: ERROR: No symbol table\n");
      return 1;
   }

   if (!text) {
      fprintf(stderr, "ERROR: cannot find the .text section\n");
      return 1;
   }

   text_sh_index = text - sections;
   strtab = get_section(h, ".strtab");

   if (!strtab) {
      fprintf(stderr, "ERROR: no .strtab in the binary\n");
      return 1;
   }

   for (unsigned i = 0; i < sym_count; i++) {

      Elf_Sym *s = syms + i;
      const char *s_name = (char *)h + strtab->sh_offset + s->st_name;

      if (s->st_shndx != text_sh_index)
         continue;

      printf("%s\n", s_name);
   }

   return 0;
}

static int
get_sym_info(struct elf_file_info *nfo, const char *sym_name)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Sym *sym = get_symbol(h, sym_name, NULL);
   Elf_Shdr *sections = (Elf_Shdr *) ((char *)h + h->e_shoff);
   Elf_Shdr *section_header_strtab = sections + h->e_shstrndx;

   if (!sym) {
      fprintf(stderr, "ERROR: Symbol '%s' not found\n", sym_name);
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

static int
set_sym_bind(struct elf_file_info *nfo,
             const char *sym_name,
             const char *bind_str)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Sym *sym = get_symbol(h, sym_name, NULL);
   const char *exp_end = bind_str + strlen(bind_str);
   char *endptr = NULL;
   unsigned long bind_n;

   if (!sym) {
      fprintf(stderr, "ERROR: Symbol '%s' not found\n", sym_name);
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

static int
set_sym_type(struct elf_file_info *nfo,
             const char *sym_name,
             const char *type_str)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Sym *sym = get_symbol(h, sym_name, NULL);
   const char *exp_end = type_str + strlen(type_str);
   char *endptr = NULL;
   unsigned long type_n;

   if (!sym) {
      fprintf(stderr, "ERROR: Symbol '%s' not found\n", sym_name);
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

static int
undef_sym(struct elf_file_info *nfo, const char *sym_name)
{
   unsigned sym_count, index;
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Sym *syms = get_symbols_ptr(h, &sym_count);

   if (!syms) {
      fprintf(stderr, "ERROR: No symbol table\n");
      return 1;
   }

   Elf_Sym *sym = get_symbol(h, sym_name, &index);

   if (!sym) {
      fprintf(stderr, "ERROR: Symbol '%s' not found\n", sym_name);
      return 1;
   }

   sym->st_info = ELF_ST_INFO(STB_GLOBAL, STT_NOTYPE);
   sym->st_other = 0;
   sym->st_shndx = 0;
   sym->st_value = 0;
   sym->st_size = 0;
   return 0;
}

static int
undef_section(struct elf_file_info *nfo, const char *section_name)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Shdr *sec = get_section(h, section_name);

   if (!sec) {
      fprintf(stderr, "Section '%s' not found\n", section_name);
      return 1;
   }

   memset(sec, 0, sizeof(*sec));
   return 0;
}

static int
redirect_reloc(struct elf_file_info *nfo, const char *sym1, const char *sym2)
{
   Elf_Ehdr *h = (Elf_Ehdr*)nfo->vaddr;
   Elf_Sym *s1 = get_symbol(h, sym1, NULL);
   Elf_Sym *s2 = get_symbol(h, sym2, NULL);

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
   help,
   "--help",
   "",
   0,
   &show_help
)

REGISTER_CMD(
   section_bin_dump,
   "--section-bin-dump",
   "<section name>",
   1,
   &section_bin_dump
)

REGISTER_CMD(
   move_metadata,
   "--move-metadata",
   "",
   0,
   &move_metadata
)

REGISTER_CMD(
   copy,
   "--copy",
   "<src section> <dest section>",
   2,
   &copy_section
)

REGISTER_CMD(
   rename,
   "--rename",
   "<section> <new_name>",
   2,
   &rename_section
)

REGISTER_CMD(
   link,
   "--link",
   "<section> <linked_section>",
   2,
   &link_sections
)

REGISTER_CMD(
   drop_last_section,
   "--drop-last-section",
   "",
   0,
   &drop_last_section
)

REGISTER_CMD(
   set_phdr_rwx_flags,
   "--set-phdr-rwx-flags",
   "<phdr index> <rwx flags>",
   2,
   &set_phdr_rwx_flags
)

REGISTER_CMD(
   verify_flat_elf,
   "--verify-flat-elf",
   "",
   0,
   &verify_flat_elf_file
)

REGISTER_CMD(
   check_entry_point,
   "--check-entry-point",
   "<expected>",
   1,
   &check_entry_point
)

REGISTER_CMD(
   check_mem_size,
   "--check-mem-size",
   "<expected_max> <b|kb>",
   2,
   &check_mem_size
)

REGISTER_CMD(
   set_sym_strval,
   "--set-sym-strval",
   "<section> <sym> <string value>",
   3,
   &set_sym_strval
)

REGISTER_CMD(
   dump_sym,
   "--dump-sym",
   "<sym_name>",
   1,
   &dump_sym
)

REGISTER_CMD(
   get_sym,
   "--get-sym",
   "<sym_name>",
   1,
   &get_sym
)

REGISTER_CMD(
   get_text_sym,
   "--get-text-sym",
   "<sym_name>",
   1,
   &get_text_sym
)

REGISTER_CMD(
   list_text_syms,
   "--list-text-syms",
   "",
   0,
   &list_text_syms
)

REGISTER_CMD(
   get_sym_info,
   "--get-sym-info",
   "<sym_name>",
   1,
   &get_sym_info
)

REGISTER_CMD(
   set_sym_bind,
   "--set-sym-bind",
   "<sym_name> <bind num>",
   2,
   &set_sym_bind
)

REGISTER_CMD(
   set_sym_type,
   "--set-sym-type",
   "<sym_name> <type num>",
   2,
   &set_sym_type
)

REGISTER_CMD(
   undef_sym,
   "--undef-sym",
   "<sym_name> REGISTER_CMD(breaks the symtab sorting!)",
   1,
   &undef_sym
)

REGISTER_CMD(
   undef_section,
   "--undef-section",
   "<section_name>",
   1,
   &undef_section
)

REGISTER_CMD(
   redirect_reloc,
   "--redirect-reloc",
   "<sym1> <sym2>",
   2,
   &redirect_reloc
)

REGISTER_CMD(
   swap_symbols,
   "--swap-symbols",
   "<index1> <index2> (EXPERIMENTAL)",
   2,
   &swap_symbols
)


int
show_help(struct elf_file_info *nfo)
{
   UNUSED_VARIABLE(nfo);
   fprintf(stderr, "Usage:\n");

   struct elfhack_cmd *c = options_head;
   while (c) {
      fprintf(stderr, "    elfhack <file> %s %s\n", c->opt, c->help);
      c = c->next;
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
   struct elfhack_cmd *cmd = options_head;
   
   while (cmd) {

      if (!strcmp(opt, cmd->opt)) {
         return cmd;
      }

      cmd = cmd->next;
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

         cmd = options_head;    /* help */

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
