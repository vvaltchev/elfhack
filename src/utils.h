/* SPDX-License-Identifier: BSD-2-Clause */

#pragma once
#include "basic_defs.h"
#include "elf_utils.h"

Elf_Sym *
get_symbol(Elf_Ehdr *h, const char *name_or_index, unsigned *out_index);
