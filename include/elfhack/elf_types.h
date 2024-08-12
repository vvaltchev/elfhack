/* SPDX-License-Identifier: BSD-2-Clause */

#pragma once
#include <elf.h>

#if defined(USE_ELF32) && defined(USE_ELF64)
   #error Invalid configuration: USE_ELF32 and USE_ELF64 both defined.
#endif

#if defined(USE_ELF32) || (defined(__i386__) && !defined(USE_ELF64))

   typedef Elf32_Addr Elf_Addr;
   typedef Elf32_Ehdr Elf_Ehdr;
   typedef Elf32_Phdr Elf_Phdr;
   typedef Elf32_Shdr Elf_Shdr;
   typedef Elf32_Sym Elf_Sym;
   typedef Elf32_Off Elf_Off;
   typedef Elf32_Word Elf_Word;
   typedef Elf32_Rel Elf_Rel;
   typedef Elf32_Rela Elf_Rela;

   #define ELF_ST_BIND(val)         ELF32_ST_BIND (val)
   #define ELF_ST_TYPE(val)         ELF32_ST_TYPE (val)
   #define ELF_ST_INFO(bind, type)  ELF32_ST_INFO ((bind), (type))
   #define ELF_ST_VISIBILITY(o)     ELF32_ST_VISIBILITY (o)

   #define ELF_R_SYM(val)           ELF32_R_SYM(val)
   #define ELF_R_TYPE(val)          ELF32_R_TYPE(val)
   #define ELF_R_INFO(sym, type)    ELF32_R_INFO(sym, type)

#elif defined(USE_ELF64) || ((defined(__x86_64__) || defined(__aarch64__)) \
                             && !defined(USE_ELF32))

   typedef Elf64_Addr Elf_Addr;
   typedef Elf64_Ehdr Elf_Ehdr;
   typedef Elf64_Phdr Elf_Phdr;
   typedef Elf64_Shdr Elf_Shdr;
   typedef Elf64_Sym Elf_Sym;
   typedef Elf64_Off Elf_Off;
   typedef Elf64_Word Elf_Word;
   typedef Elf64_Rel Elf_Rel;
   typedef Elf64_Rela Elf_Rela;

   #define ELF_ST_BIND(val)         ELF64_ST_BIND (val)
   #define ELF_ST_TYPE(val)         ELF64_ST_TYPE (val)
   #define ELF_ST_INFO(bind, type)  ELF64_ST_INFO ((bind), (type))
   #define ELF_ST_VISIBILITY(o)     ELF64_ST_VISIBILITY (o)

   #define ELF_R_SYM(val)           ELF64_R_SYM(val)
   #define ELF_R_TYPE(val)          ELF64_R_TYPE(val)
   #define ELF_R_INFO(sym, type)    ELF64_R_INFO(sym, type)

#else

   #error Unknown architecture

#endif