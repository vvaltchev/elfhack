# Elfhack - a tool for hacking ELF binaries
![Linux](https://github.com/vvaltchev/elfhack/workflows/Linux/badge.svg)
![macOS](https://github.com/vvaltchev/elfhack/workflows/macOS/badge.svg)
![FreeBSD](https://github.com/vvaltchev/elfhack/workflows/FreeBSD/badge.svg)

## What is elfhack?
A tool for hacking ELF binaries, in ways compatible with the ELF format but
beyond what the GNU Binutils tools support: renaming, copying and dropping
sections, moving the ELF metadata, patching symbols and relocations,
checking the layout of "flat" binaries.

## Disclaimer
**WARNING**: this tool allows you to do **completely unsafe hacks**,
potentially breaking a binary or an object file in very subtle ways, if you
don't know what you are doing. There is a good reason why `objcopy` prevents
users from doing many things and does plenty of safety checks before
proceeding with any request. Elfhack performs **no safety checks** instead.
A wrong operation on a linked binary can cause the application to crash or
behave in an unexpected way. A wrong operation on an object file can cause
the linker to fail or, worse, it can cause the linker to succeed linking an
*incorrect* program. Such a program can crash or behave in a weird way. This
is the realm of undefined behavior. Make sure you really understand what you
are doing.

## Building

Requirements: CMake and a C compiler (gcc or clang). Linux, FreeBSD and
macOS are supported.

```bash
make                                  # builds in build/
make install DESTDIR=<dir>            # installs into <dir>/usr/local/bin
```

or, with CMake directly:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cmake --install build --prefix <dir>  # installs into <dir>/bin
```

The build produces **two binaries**: `elfhack32` works on ELFCLASS32 files
and `elfhack64` on ELFCLASS64 ones, whatever the bitness of the host. Each
one refuses files of the other class. Only files in the host's byte order
are supported.

To run the tests, see [TESTING.md](TESTING.md).

## Usage

```
elfhack32 <file> [<action> [<args>...]]... [<modifier> <value>]...
elfhack64 <file> [<action> [<args>...]]... [<modifier> <value>]...
```

The actions run in the order given on the command line, on the same file.
By default, the file is **modified in place**; with `-o <output>`, the input
is left untouched and the result goes to `<output>`.

The file is opened read-only when none of the actions on the command line
modifies it, so read-only files can be inspected.

### Actions on sections

| Action | Arguments | What it does |
|---|---|---|
| `-d`, `--section-bin-dump` | `<section>` | Write the section's raw contents to stdout |
| `--copy` | `<src> <dest>` | Copy the contents of `<src>` into `<dest>`, which must be large enough; `<dest>` also takes `<src>`'s size, type, flags, `sh_info` and `sh_entsize` |
| `--rename` | `<section> <new name>` | Rename a section; the new name cannot be longer than the old one |
| `--link` | `<section> <linked>` | Set the section's `sh_link` to the index of `<linked>` |
| `-U`, `--undef-section` | `<section>` | Zero the section's header |
| `--drop-last-section` | | Remove the section that comes last in the file and truncate the file; fails if that is `.shstrtab` |
| `--move-metadata` | | Move the program headers, the section headers and `.shstrtab` right after the ELF header |

### Actions on symbols and relocations

These work on the static symbol table, `.symtab`.

| Action | Arguments | What it does |
|---|---|---|
| `-s`, `--list-syms` | | List the symbols: index, value, size, type, bind, visibility, section index, name |
| `-si`, `--get-sym-info` | `<symbol>` | Show the symbol's fields, decoded |
| `-v`, `--get-sym-value` | `<symbol>` | Print the symbol's value |
| `-ds`, `--dump-sym` | `<symbol>` | Print the bytes of the symbol's data, in hex. Fails for symbols without data in the file (undefined, absolute, common, in `.bss`) |
| `--set-sym-strval` | `<section> <symbol> <string>` | Write a NUL-terminated string into the symbol's data, which must be in `<section>` and large enough |
| `--set-sym-bind` | `<symbol> <bind>` | Set the symbol's binding (a number: 0 local, 1 global, 2 weak, ...) |
| `--set-sym-type` | `<symbol> <type>` | Set the symbol's type (a number: 0 notype, 1 object, 2 func, ...) |
| `-u`, `--undef-sym` | `<symbol>` | Make the symbol an undefined global one (this can break the ordering of `.symtab`, locals first) |
| `--swap-symbols` | `<index1> <index2>` | Swap two entries of `.symtab`, updating the relocations that refer to them (experimental) |
| `-rr`, `--redirect-reloc` | `<symbol1> <symbol2>` | Make the relocations against `<symbol1>` refer to `<symbol2>` |

`--swap-symbols` and `--redirect-reloc` only rewrite the relocation sections
that refer to `.symtab`: in a dynamically linked binary, `.rela.dyn` and
`.rela.plt` refer to `.dynsym` and are left alone.

### Actions on segments and layout checks

| Action | Arguments | What it does |
|---|---|---|
| `--set-phdr-rwx-flags` | `<phdr index> <flags>` | Set a program header's R/W/X flags, e.g. `rx` (the other flags are kept) |
| `--check-entry-point` | `<address>` | Fail unless the entry point is `<address>` (hex) |
| `--check-mem-size` | `<max> <b\|kb>` | Fail if the loaded image is larger than `<max>` bytes or kilobytes; see below |
| `--verify-flat-elf` | | Fail unless the file is a "flat" binary; see below |

`--check-mem-size` measures the memory the image occupies when each
`PT_LOAD` segment is copied to its physical address (`p_paddr`), as a
bootloader loading a kernel does: from the lowest `p_paddr` to the end of
the last segment, each end rounded up to the segment's alignment. `<max>`
may be decimal or hex (`0x...`).

A **flat** binary is an ELF file that can also be run as a raw image by
skipping its headers: loaded as a whole file, it works because every
loaded section's offset in the file equals its distance, in memory, from
where the start of the file lands, and because the entry point is its
lowest address. `--verify-flat-elf` checks exactly that.

### Modifiers

| Modifier | Values | What it does |
|---|---|---|
| `-sf`, `--set-symbol-input-format` | `default`, `name`, `index` | How the actions after it read their `<symbol>` arguments |
| `-Sf`, `--set-section-input-format` | `default`, `name`, `index` | How the actions after it read their `<section>` arguments |
| `-o`, `--output` | `<file>` | Write the result to `<file>` instead of modifying the input |

Symbols and sections are named by **name** or by **index** in their table.
With the `default` format, `#N` means index `N` and anything else is a name;
`name` and `index` force one reading. A name that matches more than one
symbol or section is an error.

`-sf` and `-Sf` apply only to the actions after them, so they can change
along the command line. `-o` applies to the whole run, wherever it appears.

### Exit status

0 if every action succeeded. At the first failing action, elfhack prints
the reason on stderr, stops, and exits with 1. With `-o`, a failed run
leaves the output file untouched (the actions run on a temporary copy,
renamed over the output only on success); without it, the actions before
the failing one have already modified the file.

### Examples

```bash
# List the symbols of a 32-bit object file
elfhack32 foo.o --list-syms

# Point the calls to foo() at bar() instead, in a copy of the object file
elfhack64 obj.o -o patched.o --redirect-reloc foo bar

# Write a version string into a binary, then check it
elfhack64 app --set-sym-strval .data version "1.2.3" --dump-sym version

# Several actions in one run: rename a section, then read a symbol by index
elfhack64 obj.o --rename .comment .cmnt -sf index --get-sym-info 3
```

## Extending elfhack

Every action is a C function registered with `REGISTER_CMD`
(`include/elfhack/options.h`), which also declares whether the action
modifies the file. To add actions without changing elfhack's sources, pass
your own C files to the build:

```bash
cmake -S . -B build -DELFHACK_EXTRA_SOURCES="/path/to/my_cmds.c"
```

```c
#include <stdio.h>
#include "elfhack/elf_utils.h"
#include "elfhack/options.h"

static int
hello(struct elf_file_info *nfo, const char *who)
{
   Elf_Ehdr *h = nfo->vaddr;
   printf("hello %s: %u sections\n", who, (unsigned)h->e_shnum);
   return 0;
}

REGISTER_CMD(
   hello,                  /* internal name */
   "--hello",              /* long option */
   NULL,                   /* short option */
   "<who>",                /* help */
   1,                      /* number of arguments */
   ELFHACK_READS_FILE,     /* or ELFHACK_WRITES_FILE */
   &hello
)
```

## History
The `elfhack` tool was first introduced in 2018 in the
[Tilck](https://github.com/vvaltchev/tilck) project and has been exported
to a dedicated repository in 2024.
