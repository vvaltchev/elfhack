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
   bool writable;    /* opened read-write: map it read-write too */
};

/*
 * Map the whole file `nfo->fd` in memory (shared; read-write only if
 * `nfo->writable`) and set
 * `nfo->vaddr` and `nfo->mmap_size`. The file must not be mapped already.
 * Returns 0 on success; on failure, prints an error, leaves `nfo->vaddr`
 * NULL and returns 1.
 */
int
elf_file_map(struct elf_file_info *nfo);

/* Unmap the file, if mapped. Safe to call more than once. */
void
elf_file_unmap(struct elf_file_info *nfo);

int
elf_header_type_check(struct elf_file_info *nfo);

const char *
sym_get_bind_str(unsigned bind);

const char *
sym_get_type_str(unsigned type);

const char *
sym_get_visibility_str(unsigned visibility);

const char *
sym_get_shndx_str(unsigned shndx);

Elf_Shdr *
get_section_by_name(Elf_Ehdr *h, const char *name, unsigned *index);

unsigned
get_index_of_section(Elf_Ehdr *h, Elf_Shdr *sec);

Elf_Shdr *
get_section_by_index(Elf_Ehdr *h, unsigned index);

Elf_Sym *
get_symbols_ptr(Elf_Ehdr *h, unsigned *sym_count);

int
get_index_of_symbol(Elf_Ehdr *h, Elf_Sym *symbol);

Elf_Sym *
get_symbol_by_index(Elf_Ehdr *h, unsigned index);

/*
 * Is `sec` a SHT_REL or SHT_RELA section whose entries refer to .symtab
 * (its sh_link)? Dynamic relocations (.rela.dyn, .rela.plt) refer to
 * .dynsym instead: there, the same index means a different symbol.
 */
bool
is_symtab_reloc_section(Elf_Ehdr *h, Elf_Shdr *sec);

/* The string table of .symtab (its sh_link), or NULL without .symtab. */
Elf_Shdr *
get_symbols_strtab(Elf_Ehdr *h);

/* The name of `s`; `strtab` is get_symbols_strtab()'s result. */
const char *
get_symbol_name(Elf_Ehdr *h, Elf_Shdr *strtab, Elf_Sym *s);

Elf_Sym *
get_symbol_by_name(Elf_Ehdr *h, const char *sym_name, unsigned *index);

/*
 * The memory the PT_LOAD segments occupy once loaded at their physical
 * addresses: from the lowest p_paddr to the highest segment end, each
 * end rounded up to its segment's p_align. 0 without PT_LOAD segments.
 */
size_t
elf_calc_mem_size(Elf_Ehdr *h);

Elf_Sym *
get_section_symbol_obj(Elf_Ehdr *h, Elf_Shdr *sec);

/* The section `sym` is defined in, or NULL for SHN_UNDEF, SHN_ABS etc. */
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

