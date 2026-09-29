# Testing elfhack

The test suite runs the `elfhack32` and `elfhack64` binaries on copies of
small ELF files and checks the results. It runs **on Linux and FreeBSD**:
on any other OS, the runner prints a message and exits successfully without
running anything.

## Requirements

| Package   | Needed for                                             |
|-----------|--------------------------------------------------------|
| `python3` | running the tests (standard library only, no `pip`)    |
| `cmake`   | building elfhack                                       |
| `gcc`     | building elfhack (`clang` works too, except coverage)  |
| `lcov`    | coverage reports only (`lcov` and `genhtml`)           |

To install them (on Arch Linux, Python 3 is the `python` package):

```bash
sudo apt install python3 cmake gcc lcov      # Debian, Ubuntu
sudo dnf install python3 cmake gcc lcov      # Fedora
sudo pacman -S python cmake gcc lcov         # Arch Linux
```

No 32-bit libraries (e.g. `gcc-multilib`) are needed, not even to regenerate
the fixtures.

## Running the tests

```bash
make test                   # build elfhack in build/, then run all the tests
```

Or, with more control, call the runner directly:

```bash
tests/run_tests                       # run all the tests on build/
tests/run_tests -v                    # print each test as it runs
tests/run_tests -l                    # list the tests
tests/run_tests -f redirect           # only the tests whose name contains
                                      # "redirect" (repeatable, wildcards ok)
tests/run_tests -b /path/to/build     # test the binaries of another build
```

From any build directory, `ctest` (or `make test`) runs the whole suite on
that directory's binaries.

## Coverage

```bash
make coverage               # or: tests/run_tests --coverage
```

This configures and builds an instrumented copy of elfhack in
`build-coverage/` (always with gcc: the counters are read with `gcov`), runs
the tests on it, and then prints a per-file summary and writes an HTML report
to `build-coverage/coverage-html/index.html`. The counters are reset before
every run. The report includes only elfhack's own sources (`src/` and
`include/elfhack/`).

## How the tests are organized

```
tests/
   run_tests            the runner (Python's unittest)
   test_*.py            the tests, one file per area
   lib/
      elfhack_test.py   ElfhackTestCase: fixtures, running the tool, asserts
      elf_reader.py     a minimal ELF parser to check results
   fixtures/
      obj32.o obj64.o   relocatable objects (SHT_REL / SHT_RELA relocations)
      prog32 prog64     linked executables, no libc
      flat32 flat64     "flat" executables: runnable as raw images by
                        skipping the headers (like Tilck's elf_stage3),
                        only PT_LOAD segments (like Tilck's kernel)
      dyn32 dyn64       dynamically linked executables: .symtab and .dynsym,
                        static (--emit-relocs) and dynamic relocations
      src/              their sources
      generate          the script that rebuilds them
```

Every test works on a private copy of the fixtures in its own temporary
directory, so the committed files never change. Tests that apply to both
ELF classes loop over them with `self.subTest(bits=...)`.

Results are checked with `tests/lib/elf_reader.py`, not with elfhack itself
nor by parsing the output of `readelf`: a bug in elfhack cannot hide itself
that way, and the tests depend on nothing beyond Python.

A run of elfhack that is killed by a signal (e.g. a segfault) always fails
the test, even when the test expects the command to fail: `run_tool()` checks
that before returning.

## Writing a test

```python
from elfhack_test import ElfhackTestCase, ELF_CLASSES

class TestSomething(ElfhackTestCase):

   def test_something(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):
            f = self.fixture(f'obj{bits}.o')       # private copy
            r = self.run_tool(bits, f, '--some-action', 'arg')
            self.assert_ok(r)                       # or assert_fails(r, msg)
            elf = self.elf(f)                       # check the result
            ...
```

Every bug fix comes with a test that fails before the fix and passes after.

## Regenerating the fixtures

The fixtures are committed, so this is needed only to change them:

```bash
tests/fixtures/generate
```

It needs only `gcc` and `binutils`: the sources are compiled freestanding,
without any system header, and linked without libc, start files or libgcc.
After regenerating, run the tests: they read expected values (symbol values,
entry points, section contents) from the fixtures themselves, so they do not
depend on the exact bytes the compiler produced.
