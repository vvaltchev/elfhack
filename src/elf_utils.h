/* SPDX-License-Identifier: BSD-2-Clause */

#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

#include "basic_defs.h"
#include "elf_types.h"

struct elf_file_info {
   const char *path;
   size_t mmap_size;
   void *vaddr;
   int fd;
};

const char *
sym_get_bind_str(unsigned bind);

const char *
sym_get_type_str(unsigned type);

const char *
sym_get_visibility_str(unsigned visibility);

Elf_Shdr *
get_section(Elf_Ehdr *h, const char *section_name);

int
get_section_index(Elf_Ehdr *h, Elf_Shdr *sec);

Elf_Sym *
get_symbols_ptr(Elf_Ehdr *h, unsigned *sym_count);

int
get_symbol_index(Elf_Ehdr *h, Elf_Sym *symbol);

const char *
get_symbol_name(Elf_Ehdr *h, Elf_Sym *s);

Elf_Sym *
get_symbol(Elf_Ehdr *h, const char *sym_name, unsigned *index);

size_t
elf_calc_mem_size(Elf_Ehdr *h);

Elf_Sym *
get_section_symbol_obj(Elf_Ehdr *h, Elf_Shdr *sec);

Elf_Shdr *
get_sym_section(Elf_Ehdr *h, Elf_Sym *sym);

const char *
get_section_name(Elf_Ehdr *h, Elf_Shdr *section);

Elf_Phdr *
get_phdr_for_section(Elf_Ehdr *h, Elf_Shdr *section);

void
remove_rel_entries_for_sym(Elf_Ehdr *h, Elf_Shdr *rela_sec, Elf_Sym *sym);

void
redirect_rel_internal_index(Elf_Ehdr *h,
                            Elf_Shdr *sec,
                            unsigned index1,
                            unsigned index2,
                            bool swap);

void
redirect_rel_internal(Elf_Ehdr *h, Elf_Shdr *sec, Elf_Sym *s1, Elf_Sym *s2);

void
swap_symbols_index(Elf_Ehdr *h, int idx1, int idx2);

