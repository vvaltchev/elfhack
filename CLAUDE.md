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

## Testing

Read `TESTING.md` before touching the tests. In short:

```bash
make test                    # build, then run the whole suite (~0.1s)
tests/run_tests -f <name>    # only the matching tests
make coverage                # instrumented build in build-coverage/ + lcov
```

Python `unittest`, Linux only, no dependencies beyond python3, cmake,
gcc and (for coverage) lcov. Results are checked with
`tests/lib/elf_reader.py`, never with elfhack itself.

**Every fix comes with a test that fails before the fix and passes
after it.** Run the test against the unfixed binary to see it fail.

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
- Every action declares in `REGISTER_CMD` whether it writes the ELF file
  (`ELFHACK_WRITES_FILE`) or only reads it (`ELFHACK_READS_FILE`): the
  file is opened and mapped read-only unless some action on the command
  line writes it, so a reader that writes crashes. When unsure, declare
  it a writer. Add every new reader to `READ_ONLY_ACTIONS` in
  `tests/test_cli.py`.

## Fix list

Ordered by priority. P0 blocks Tilck integration outright.

### P0: blockers

None left.

### P1: wrong behaviour

None left.

### P2: build, CI, docs

1. README: fix the typos ("Disclamer", "what are you going") and
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
source file using `REGISTER_CMD` (via a pkgmgr patch) and build elfhack
with `-DELFHACK_EXTRA_SOURCES=<file.c>`, so no CMake hunk is needed.
Extensions must be compiled into the executable directly, which the hook
does: constructor-based registration is silently lost if the objects go
into a static library, because the linker drops unreferenced archive
members.

Behaviour change to keep in mind: name lookups now exit with an error
when a name matches more than one symbol or section. The names Tilck
queries are expected to be unique.
