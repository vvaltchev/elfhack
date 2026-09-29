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
cmake -S . -B build && cmake --build build
./build/elfhack <file> --help
```

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

1. **Action failures always exit with 0.** `process_all_options()`
   (`src/elfhack.c:403`) calls `opt->proc(...)` and discards the return
   value, so `rc` is never set and the `if (rc) break;` right after it is
   dead code. Verified: `--check-entry-point 0x1234` on a mismatching
   binary prints `ERROR: entry point ... != expected` and exits 0; a
   missing symbol for `--get-sym-value` also exits 0. Tilck's build
   relies on non-zero exits from `--verify-flat-elf`,
   `--check-entry-point` and `--set-sym-strval`. Fix: `rc = opt->proc(...)`
   and stop at the first failure. The same bug hides enum-parse errors
   during the const pass.

2. **`-o/--output` is broken** (`file_copy()`, `src/misc.c:72`).
   - `src/misc.c:101`: `open(dest, statbuf.st_mode | O_CREAT | O_WRONLY)`
     passes the permission bits as *open flags* and omits the mode
     argument. `0755` contains `0200` = `O_EXCL`, so a second run onto an
     existing output fails with "File exists" (verified). The created
     file's mode is garbage from the stack. Missing `O_TRUNC`.
   - `src/misc.c:80` prints `file copy A -> B` to **stdout**, corrupting
     the output of stdout actions (`--dump-sym`, `--section-bin-dump`).
   - Read and write errors are printed but `file_copy()` returns 0
     (`src/misc.c:136`); `write_chunk_to_file()` always returns 0
     (`src/misc.c:68`).
   - No handling of `dest == src` (with `O_TRUNC` added, that would
     destroy the input).
   - A failed run leaves a partial output behind, which `make` then
     treats as up to date. Write to a temp file next to the destination
     and `rename()` it only when every action succeeded.

3. **Only one binary, for the host's bitness.** `CMakeLists.txt` builds
   a single `elfhack` with neither `USE_ELF32` nor `USE_ELF64`, so
   `elf_types.h` picks from the host arch, and on any host other than
   i386/x86_64/aarch64 it hits `#error Unknown architecture`
   (`include/elfhack/elf_types.h:55`). Tilck needs both classes on the
   same host. Build `elfhack32` and `elfhack64` (the `USE_ELF*`
   switches already exist), drop the host-arch fallback, and add
   `install()` rules. Runtime dispatch on `EI_CLASS` in one binary is
   a larger refactor (compiling the commands twice registers every
   option twice, and `validate_tool_options()` aborts on duplicates);
   not needed now.

### P1: wrong behaviour

4. **`SHT_REL` handled with the `Elf_Rela` layout.**
   `redirect_rel_internal_index()` (`src/elf_utils.c:478`), the
   `SHT_REL` branch, declares `Elf_Rela *rel` and walks REL entries with
   RELA stride (12 vs 8 bytes on ELF32, 24 vs 16 on ELF64), so the loop
   reads and rewrites the wrong fields. Affects `--redirect-reloc` and
   `--swap-symbols` on i386 objects, which use `.rel.*`.

5. **mmap failure checked through `errno`** (`src/elfhack.c:518`).
   Compare against `MAP_FAILED`. An empty file makes `mmap` fail with
   size 0; a file shorter than an ELF header is read out of bounds by
   `elf_header_type_check()`.

6. **`--drop-last-section` truncates a file that is still mapped**
   (`src/section_cmds.c:287`). Tilck's version unmaps first (the
   comment about WSL got lost). With multiple actions per run, any later
   action touching the dropped range dies with SIGBUS, and
   `nfo->mmap_size` is stale. Unmap, truncate, remap, and update
   `mmap_size`.

7. **Off-by-one bounds checks on symbol indexes.** `index > sym_count`
   must be `>=` in `get_index_of_symbol()` (`src/elf_utils.c:226`),
   `get_symbol_by_index()` (`src/elf_utils.c:272`),
   `swap_symbols_index()` (`src/elf_utils.c:519` and the `idx2` twin),
   `swap_symbols()` (`src/symbol_cmds.c:385` and the `idx2` twin).
   `get_index_of_symbol()` also returns `-1` through an `unsigned`
   return type, and callers test it with `< 0` after storing it in an
   `int`.

8. **Special section indexes used as array indexes.** `sections +
   sym->st_shndx` for `SHN_UNDEF`/`SHN_ABS`/`SHN_COMMON` (and anything
   `>= SHN_LORESERVE`) reads out of the section table:
   `get_sym_section()` (`src/elf_utils.c:378`), `dump_sym()`
   (`src/symbol_cmds.c:92`), `get_sym_info()` (`src/symbol_cmds.c:194`).
   `dump_sym()` on an `SHT_NOBITS` (`.bss`) symbol dumps unrelated file
   bytes; it should refuse.

9. **String table found by name, not by link.** `get_symbol_name()`
   (`src/elf_utils.c:238`) looks up `.strtab` by name; it must use the
   symbol table's `sh_link`. `get_symbols_ptr()` (`src/elf_utils.c:204`)
   finds `.symtab` by name (acceptable) but divides by `sh_entsize`
   without checking for 0. `get_symbol_name()` also re-scans the section
   table for every symbol (O(symbols x sections)), and
   `get_symbol_by_name()` always scans the whole table to detect
   duplicates.

10. **Help omits string flags.** `show_help()` dumps ACTION, FLAG and
    ENUM options (`src/elfhack.c:80-85`) but not `ELFHACK_STRING`, so
    `-o/--output` never appears in `--help`.

11. **`--check-mem-size <max> <unit>`** (`src/misc_cmds.c:197`) accepts
    any unit and silently treats everything except `kb` as bytes.
    Validate `b|kb`.

12. **`include/elfhack/basic_defs.h:8`**: `#define GB (1024 * GB)` is
    self-referential (should be `1024 * MB`). `pow2_round_up_at()` is a
    non-inline `static` function in a header, which is why
    `-Wno-unused-function` is needed; make it `static inline` and drop the
    flag.

13. **Diagnostics.** "option not recognized" goes to stdout
    (`src/elfhack.c:381`); a few messages lack a trailing `\n`
    (`validate_tool_options()` at `src/elfhack.c:434`, "bind is too
    high", "type is too high", the `swap_symbols` errors).
    `is_plain_integer("")` returns true, so an empty index parses as 0.

14. **The input is always opened `O_RDWR`** (`src/elfhack.c:487`), even
    for read-only actions, so a read-only file cannot be inspected. Open
    read-only when no mutating action is on the command line (needs a
    `mutates` bit on `struct elfhack_option`). No `EI_DATA` check either:
    a big-endian ELF is silently misread.

### P2: build, CI, docs

15. `Makefile:6` lists `$(TCROOT)` as a prerequisite, a Tilck leftover.
    Remove it.
16. `CMakeLists.txt`: `-ggdb` is forced on every build type; no
    `install()`; no `ELFHACK_EXTRA_SOURCES` hook (see "Tilck
    integration").
17. CI (`.github/workflows/linux.yml`): `ubuntu-20.04` runners are
    retired; `-DTESTS=1` is passed but there are no tests. Build both
    classes with gcc and clang, and add macOS and FreeBSD jobs.
18. **No tests at all.** Add a test suite with small committed ELF32
    and ELF64 fixtures (object files and a linked binary) so it runs on
    hosts that cannot produce 32-bit output (macOS). Every P0/P1 item
    above gets a regression test; exit codes are checked for every
    failure path.
19. README: fix the typos ("Disclamer", "what are you going") and
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
