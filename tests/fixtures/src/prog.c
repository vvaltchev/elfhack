/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * Source of the linked executable fixtures (prog32, prog64): no libc, no
 * start files, just an entry point and a data symbol with room for a string.
 */

char version[32] = "unset";

void
_start(void)
{
   for (;;) { }
}
