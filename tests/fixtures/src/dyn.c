/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * Source of the dynamically linked fixtures (dyn32, dyn64): they have two
 * symbol tables, .symtab and .dynsym. The calls into the shared library
 * produce dynamic relocations (.rel[a].plt), whose symbol indexes refer to
 * .dynsym; linking with --emit-relocs also keeps the static ones
 * (.rel[a].text), whose indexes refer to .symtab.
 */

int lib_foo(int);
int lib_bar(int);
int lib_baz(int);

static int local_counter;

int
caller(int x)
{
   local_counter++;
   return lib_foo(x) + lib_bar(x) + lib_foo(x + 1) + lib_baz(x);
}

void
_start(void)
{
   caller(local_counter);
   for (;;) { }
}
