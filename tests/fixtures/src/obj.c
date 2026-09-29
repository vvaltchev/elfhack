/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * Source of the relocatable object fixtures (obj32.o, obj64.o).
 *
 * The calls to the undefined functions produce relocations: SHT_REL
 * (.rel.text) on ELF32, SHT_RELA (.rela.text) on ELF64. `foo` is called
 * twice, so that a redirection has more than one entry to rewrite.
 *
 * The symbols cover every kind of st_shndx: a regular section (.data, .text),
 * SHT_NOBITS (.bss: `zeroed`), SHN_COMMON (`shared`), SHN_UNDEF (`foo`, ...)
 * and SHN_ABS (the STT_FILE symbol of this file).
 *
 * `priv_ptr` points to a static variable: its relocation refers to the .data
 * section symbol, so the object has an STT_SECTION symbol too.
 */

extern int foo(int);
extern int bar(int);
extern int baz(int);

int counter = 42;
char label[16] = "unset";
int zeroed;
int shared __attribute__((common));

static int priv = 7;
int *priv_ptr = &priv;

int
caller(int x)
{
   return foo(x) + bar(x) + foo(x + 1) + baz(x);
}
