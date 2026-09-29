/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * Source of the relocatable object fixtures (obj32.o, obj64.o).
 *
 * The calls to the undefined functions produce relocations: SHT_REL
 * (.rel.text) on ELF32, SHT_RELA (.rela.text) on ELF64. `foo` is called
 * twice, so that a redirection has more than one entry to rewrite.
 */

extern int foo(int);
extern int bar(int);
extern int baz(int);

int counter = 42;
char label[16] = "unset";

int
caller(int x)
{
   return foo(x) + bar(x) + foo(x + 1) + baz(x);
}
