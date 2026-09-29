# SPDX-License-Identifier: BSD-2-Clause

"""Actions on the program headers and the in-memory layout."""

from elfhack_test import ElfhackTestCase, ELF_CLASSES


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
