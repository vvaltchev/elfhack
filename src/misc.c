/* SPDX-License-Identifier: BSD-2-Clause */

#include <ctype.h>
#include <stdbool.h>

bool
is_index_string(const char *str)
{
   const char *digits;

   if (*str != '#')
      return false;

   digits = str + 1;

   if (!isdigit(*digits))
      return false; /* not even a single digit after '#' */

   for (const char *p = digits; *p != '\0'; p++) {
      if (!isdigit(*p))
         return false;
   }

   return true;
}