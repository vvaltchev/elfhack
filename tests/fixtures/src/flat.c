/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * Source of the flat fixtures (flat32, flat64), linked with flat.ld: see
 * there for the layout. `_start` goes first in .text, so that the entry point
 * is the lowest address of the image.
 */

const char banner[] = "flat fixture";
char version[32] = "unset";
char scratch[0x1234];

__attribute__((section(".text.entry"))) void
_start(void)
{
   for (;;) { }
}
