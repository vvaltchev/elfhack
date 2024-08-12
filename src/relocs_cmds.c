/* SPDX-License-Identifier: BSD-2-Clause */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <errno.h>

#include "basic_defs.h"
#include "elf_utils.h"
#include "options.h"

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

REGISTER_CMD(
   redirect_reloc,
   "--redirect-reloc",
   "-rr",
   "<sym1> <sym2>",
   2,
   &redirect_reloc
)
