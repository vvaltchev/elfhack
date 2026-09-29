# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

`elfhack` is a small C tool for low-level ELF edits that binutils refuses
to do (rename/copy/link sections, drop the last section, move metadata,
patch symbols and relocations). It was extracted from Tilck
(`~/dev/tilck`, `scripts/build_apps/elfhack.c`) in June 2024 and has
diverged since: commands now self-register through `REGISTER_CMD`
(`include/elfhack/options.h`), several actions can run in one invocation,
and there are short options, typed modifiers and `-o`.

**Goal:** Tilck will consume this repo as a pkgmgr host package
(`host_elfhack`) instead of building its own copy. Before that, the
defects below must be fixed. Everything in "Fix list" is a known,
verified problem; none of it is speculative.

## Build

```bash
make                        # fake Makefile: runs cmake into build/ then make
make install DESTDIR=<dir>  # installs into <dir>/usr/local/bin
cmake -S . -B build && cmake --build build
cmake --install build --prefix <dir>   # installs into <dir>/bin
./build/elfhack32 <file> --help        # ELFCLASS32 files
./build/elfhack64 <file> --help        # ELFCLASS64 files
```

The ELF class is fixed at compile time: every source is built twice,
once with `USE_ELF32` (`elfhack32`) and once with `USE_ELF64`
(`elfhack64`), independent of the host's bitness. A binary refuses
files of the other class.

`CMAKE_C_STANDARD 99` with extensions ON, so the code builds as `gnu99`.
With strict `-std=c99` it fails: `ftruncate` is not declared unless a
POSIX feature macro is defined.

## Conventions

- License: BSD-2-Clause (`LICENSE`). SPDX header in every file.
- Third-party code lives in `include/3rd_party/` and every item is
  recorded in `NOTICE`, in the same format Tilck uses. Never copy code
  from GPL or other copyleft sources.
- Coding style is Tilck's (`~/dev/tilck/docs/contributing.md`): 3-space
  indent, 80 columns, braces for functions on their own line, return
  type on its own line, `/* */` comments.
- Host portability: Linux (x86_64, aarch64), FreeBSD, macOS (aarch64).
  macOS has no `<elf.h>` at all.

## Fix list

Ordered by priority. P0 blocks Tilck integration outright.

### P0: blockers

None left.

### P1: wrong behaviour

1. **Special section indexes used as array indexes.** `sections +
   sym->st_shndx` for `SHN_UNDEF`/`SHN_ABS`/`SHN_COMMON` (and anything
   `>= SHN_LORESERVE`) reads out of the section table:
   `get_sym_section()` (`src/elf_utils.c:447`), `dump_sym()`
   (`src/symbol_cmds.c:92`), `get_sym_info()` (`src/symbol_cmds.c:194`).
   `dump_sym()` on an `SHT_NOBITS` (`.bss`) symbol dumps unrelated file
   bytes; it should refuse.

2. **String table found by name, not by link.** `get_symbol_name()`
   (`src/elf_utils.c:307`) looks up `.strtab` by name; it must use the
   symbol table's `sh_link`. `get_symbols_ptr()` (`src/elf_utils.c:273`)
   finds `.symtab` by name (acceptable) but divides by `sh_entsize`
   without checking for 0. `get_symbol_name()` also re-scans the section
   table for every symbol (O(symbols x sections)), and
   `get_symbol_by_name()` always scans the whole table to detect
   duplicates.

3. **Help omits string flags.** `show_help()` dumps ACTION, FLAG and
   ENUM options (`src/elfhack.c:80-85`) but not `ELFHACK_STRING`, so
   `-o/--output` never appears in `--help`.

4. **`--check-mem-size <max> <unit>`** (`src/misc_cmds.c:197`) accepts
   any unit and silently treats everything except `kb` as bytes.
   Validate `b|kb`.

5. **`include/elfhack/basic_defs.h:8`**: `#define GB (1024 * GB)` is
   self-referential (should be `1024 * MB`). `pow2_round_up_at()` is a
   non-inline `static` function in a header, which is why
   `-Wno-unused-function` is needed; make it `static inline` and drop the
   flag.

6. **Diagnostics.** "option not recognized" goes to stdout
   (`src/elfhack.c:381`); a few messages lack a trailing `\n`
   (`validate_tool_options()` at `src/elfhack.c:434`, "bind is too
   high", "type is too high", the `swap_symbols` errors).
   `is_plain_integer("")` returns true, so an empty index parses as 0.

7. **The input is always opened `O_RDWR`** (`src/elfhack.c:466`), even
   for read-only actions, so a read-only file cannot be inspected. Open
   read-only when no mutating action is on the command line (needs a
   `mutates` bit on `struct elfhack_option`). No `EI_DATA` check either:
   a big-endian ELF is silently misread.

### P2: build, CI, docs

8. `Makefile:6` lists `$(TCROOT)` as a prerequisite, a Tilck leftover.
   Remove it.
9. `CMakeLists.txt`: `-ggdb` is forced on every build type; no
   `ELFHACK_EXTRA_SOURCES` hook (see "Tilck integration").
10. CI (`.github/workflows/linux.yml`): `ubuntu-20.04` runners are
    retired; `-DTESTS=1` is passed but there are no tests. Add macOS
    and FreeBSD jobs.
11. **No tests at all.** Add a test suite with small committed ELF32
    and ELF64 fixtures (object files and a linked binary) so it runs on
    hosts that cannot produce 32-bit output (macOS). Every P0/P1 item
    above gets a regression test; exit codes are checked for every
    failure path.
12. README: fix the typos ("Disclamer", "what are you going") and
    document the command line (actions, modifiers, multiple actions per
    run, `#N` indexes, `-o`).

## Tilck integration: what Tilck needs from this repo

Tilck calls these options today, all present here with the same name
and arguments: `--copy`, `--link`, `--rename`, `--move-metadata`,
`--drop-last-section`, `--set-phdr-rwx-flags`, `--set-sym-strval`,
`--verify-flat-elf`, `--check-entry-point <addr>`, `--dump-sym`.

Missing, used by Tilck's `scripts/templates/weaken_syms`:
`--list-text-syms` (names of the symbols defined in `.text`) and
`--get-text-sym <sym>` (value of a symbol, failing unless it is in
`.text`). Both were removed in commit 64fb07a. They are generic, not
Tilck-specific: add them back in a general form, e.g. a section filter
for symbol listing with a names-only output, and a way to make
`--get-sym-value` require a given section.

If Tilck ever needs a truly Tilck-specific command, it will ship it as a
pkgmgr patch that adds a source file using `REGISTER_CMD`. To keep such a
patch free of CMake hunks, `CMakeLists.txt` should accept extra sources
(`ELFHACK_EXTRA_SOURCES`) or glob `src/*.c`. Extensions must be compiled
into the executable directly: constructor-based registration is silently
lost if the objects go into a static library, because the linker drops
unreferenced archive members.

Behaviour change to keep in mind: name lookups now exit with an error
when a name matches more than one symbol or section. The names Tilck
queries are expected to be unique.
