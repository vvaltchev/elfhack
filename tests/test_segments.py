# SPDX-License-Identifier: BSD-2-Clause

"""Actions on the program headers and the in-memory layout."""

from elf_reader import PT_LOAD
from elfhack_test import ElfhackTestCase, ELF_CLASSES


def loaded_mem_size(elf):
   """
   The memory the loadable segments occupy once loaded at their physical
   addresses: from the lowest p_paddr to the highest segment end, each end
   rounded up to the segment's alignment (0 and 1 mean none). This is what a
   bootloader copying the image to memory as it is has to reserve.
   """
   loads = [s for s in elf.segments if s.type == PT_LOAD]

   if not loads:
      return 0

   def end(s):
      align = max(s.align, 1)
      return (s.paddr + s.memsz + align - 1) // align * align

   return max(end(s) for s in loads) - min(s.paddr for s in loads)


class TestMemSize(ElfhackTestCase):

   def smallest_accepted_limit(self, bits, f, unit, fmt='{}'):
      """
      The smallest <expected_max> that --check-mem-size accepts in `unit`,
      found by bisection: the test does not depend on how elfhack computes
      the in-memory size, only on the limit being applied consistently.
      """
      lo, hi = 0, 1 << 40      # lo is rejected, hi is accepted

      self.assert_fails(self.run_tool(bits, f, '--check-mem-size',
                                      fmt.format(lo), unit))
      self.assert_ok(self.run_tool(bits, f, '--check-mem-size',
                                   fmt.format(hi), unit))

      while hi - lo > 1:
         mid = (lo + hi) // 2
         r = self.run_tool(bits, f, '--check-mem-size', fmt.format(mid), unit)
         if r.rc == 0:
            hi = mid
         else:
            self.assert_fails(r, 'max in-memory size')
            lo = mid

      return hi

   def test_limits_in_bytes_and_kilobytes_agree(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):
            f = self.fixture(f'prog{bits}')
            in_bytes = self.smallest_accepted_limit(bits, f, 'b')
            in_kb = self.smallest_accepted_limit(bits, f, 'kb')
            in_hex = self.smallest_accepted_limit(bits, f, 'b', '{:#x}')
            self.assertEqual(in_kb, (in_bytes + 1023) // 1024)
            self.assertEqual(in_hex, in_bytes)

   def test_invalid_unit_is_rejected(self):
      for bits in ELF_CLASSES:
         for unit in ('mb', 'B', 'k', ''):
            with self.subTest(bits=bits, unit=unit):
               f = self.fixture(f'prog{bits}')
               r = self.run_tool(bits, f, '--check-mem-size', '1', unit)
               self.assert_fails(r, f"Invalid unit '{unit}'")

   def test_invalid_limit_is_rejected(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):
            f = self.fixture(f'prog{bits}')
            r = self.run_tool(bits, f, '--check-mem-size', 'lots', 'b')
            self.assert_fails(r, "Invalid value 'lots'")

   def assert_mem_size(self, bits, f, expected):
      """--check-mem-size accepts exactly the limits >= expected."""
      self.assert_ok(self.run_tool(bits, f, '--check-mem-size',
                                   str(expected), 'b'))
      if expected > 0:
         r = self.run_tool(bits, f, '--check-mem-size', str(expected - 1), 'b')
         self.assert_fails(r, f'max in-memory size ({expected})')

   def test_mem_size_is_the_span_of_the_loadable_segments(self):
      # flat: only PT_LOAD, like Tilck's kernel. prog: also PT_NOTE,
      # PT_GNU_PROPERTY and a PT_GNU_STACK at address 0, like any userspace
      # executable and Tilck's legacy bootloader (elf_stage3). obj: no
      # program headers at all.
      for bits in ELF_CLASSES:
         for name in (f'flat{bits}', f'prog{bits}', f'obj{bits}.o'):
            with self.subTest(file=name):
               f = self.fixture(name)
               self.assert_mem_size(bits, f, loaded_mem_size(self.elf(f)))

   def test_mem_size_of_the_flat_fixtures(self):
      # Laid out by tests/fixtures/src/flat.ld: loaded at 0x100000, the
      # data segment (p_align 0x1000) ends at 0x103254, so the image spans
      # 0x100000 - 0x104000.
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):
            self.assert_mem_size(bits, self.fixture(f'flat{bits}'), 0x4000)

   def test_mem_size_with_unaligned_segments(self):
      # p_align 0 means "no alignment", like 1: the segment ends where it
      # ends, not at 0.
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):

            f = self.fixture(f'flat{bits}')
            elf = self.elf(f)

            for seg in elf.segments:
               offset, size = elf.segment_header_field(seg.index, 'align')
               self.patch_bytes(f, offset, bytes(size))

            self.assertEqual(loaded_mem_size(self.elf(f)), 0x3254)
            self.assert_mem_size(bits, f, 0x3254)


class TestFlat(ElfhackTestCase):

   def test_verify_flat_elf(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):

            r = self.run_tool(bits, self.fixture(f'flat{bits}'),
                              '--verify-flat-elf')
            self.assert_ok(r)

            # The entry point of prog is not its lowest address
            r = self.run_tool(bits, self.fixture(f'prog{bits}'),
                              '--verify-flat-elf')
            self.assert_fails(r, 'flat ELF check FAILED')

   def test_check_entry_point_of_a_flat_binary(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):
            f = self.fixture(f'flat{bits}')
            entry = self.elf(f).entry
            self.assertEqual(entry, self.elf(f).section('.text').addr)
            self.assert_ok(self.run_tool(bits, f, '--check-entry-point',
                                         hex(entry)))
