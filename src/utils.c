/* SPDX-License-Identifier: BSD-2-Clause */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "basic_defs.h"
#include "elf_utils.h"
#include "options.h"
#include "utils.h"
#include "misc.h"
#include "utils.h"

enum symbol_name_format {
   symbol_format_default,
   symbol_format_name,
   symbol_format_index,
};

static const char *symbol_name_format_enum_strings[] =
{
   "default",
   "name",
   "index",
   NULL,
};

REGISTER_ENUM_FLAG(
   symbol_input_format,
   "--set-symbol-input-format",
   "-sf",
   "Set symbol format: {default, name, index}. "
   "'default' is like 'name' but '#123' means index 123",
   symbol_name_format_enum_strings
)

Elf_Sym *
get_symbol(Elf_Ehdr *h, const char *name_or_index, unsigned *out_index)
{
   enum symbol_name_format format =
      get_enum_option_val("symbol_input_format");

   if (format == symbol_format_name)
      return get_symbol_by_name(h, name_or_index, out_index);

   if (format == symbol_format_index) {

      unsigned index;

      if (!is_plain_integer(name_or_index)) {
         die_with_invalid_index_error(name_or_index);
      }

      errno = 0;
      index = strtoul(name_or_index, NULL, 10);

      if (errno) {
         die_with_invalid_index_error(name_or_index);
      }

      return get_symbol_by_index(h, index);
   }

   assert(format == symbol_format_default);

   if (is_index_string(name_or_index)) {

      /*
       * The user passed a symbol index, let's just check that by accident
       * we don't have a symbol named exactly that way.
       */

      unsigned index;
      Elf_Sym *sym = get_symbol_by_name(h, name_or_index, &index);

      if (sym) {
         fprintf(stderr,
                 "ERROR: cannot specify a symbol using the index string '%s' "
                 "because symbol at index %u has actually that name.\n",
                 name_or_index, index);
         exit(1);
      }

      errno = 0;
      index = strtoul(name_or_index + 1, NULL, 10);
      if (errno) {
         die_with_invalid_index_error(name_or_index);
      }

      sym = get_symbol_by_index(h, index);

      if (sym && out_index)
         *out_index = index;

      return sym;
   }

   // name_or_index is a regular name
   return get_symbol_by_name(h, name_or_index, out_index);
}

/* ------------------------------------------------------------------------- */

enum section_name_format {
   section_format_default,
   section_format_name,
   section_format_index,
};

static const char *section_name_format_enum_strings[] =
{
   "default",
   "name",
   "index",
   NULL,
};

REGISTER_ENUM_FLAG(
   section_input_format,
   "--set-section-input-format",
   "-Sf",
   "Set section format: {default, name, index}. "
   "'default' is like 'name' but '#123' means index 123",
   section_name_format_enum_strings
)

Elf_Shdr *
get_section(Elf_Ehdr *h, const char *name_or_index, unsigned *out_index)
{
   enum section_name_format format =
      get_enum_option_val("section_input_format");

   if (format == section_format_name)
      return get_section_by_name(h, name_or_index, out_index);

   if (format == section_format_index) {

      unsigned index;

      if (!is_plain_integer(name_or_index)) {
         die_with_invalid_index_error(name_or_index);
      }

      errno = 0;
      index = strtoul(name_or_index, NULL, 10);

      if (errno) {
         die_with_invalid_index_error(name_or_index);
      }

      return get_section_by_index(h, index);
   }

   assert(format == section_format_default);

   if (is_index_string(name_or_index)) {

      /*
       * The user passed a section index, let's just check that by accident
       * we don't have a section named exactly that way.
       */

      unsigned index;
      Elf_Shdr *sec = get_section_by_name(h, name_or_index, &index);

      if (sec) {
         fprintf(stderr,
                 "ERROR: cannot specify a section using the index string '%s' "
                 "because section at index %u has actually that name.\n",
                 name_or_index, index);
         exit(1);
      }

      errno = 0;
      index = strtoul(name_or_index + 1, NULL, 10);
      if (errno) {
         die_with_invalid_index_error(name_or_index);
      }

      sec = get_section_by_index(h, index);

      if (sec && out_index)
         *out_index = index;

      return sec;
   }

   // name_or_index is a regular name
   return get_section_by_name(h, name_or_index, out_index);
}
