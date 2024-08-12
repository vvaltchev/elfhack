/* SPDX-License-Identifier: BSD-2-Clause */

#include <ctype.h>
#include <stdbool.h>

bool
is_plain_integer(const char *str)
{
   for (const char *p = str; *p != '\0'; p++) {
      if (!isdigit(*p))
         return false;
   }

   return true;
}

bool
is_index_string(const char *str)
{
   if (*str != '#')
      return false;

   if (!isdigit(*(str + 1)))
      return false; /* not even a single digit after '#' */

   return is_plain_integer(str + 1);
}

