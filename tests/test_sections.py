# SPDX-License-Identifier: BSD-2-Clause

"""Actions on sections."""

from elfhack_test import ElfhackTestCase, ELF_CLASSES


class TestSections(ElfhackTestCase):

   def test_section_bin_dump_prints_the_section_contents(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):
            f = self.fixture(f'obj{bits}.o')
            r = self.run_tool(bits, f, '--section-bin-dump', '.comment')
            self.assert_ok(r)
            self.assertEqual(r.stdout, self.elf(f).section_data('.comment'))

   def test_rename_section(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):

            f = self.fixture(f'obj{bits}.o')
            before = [s.name for s in self.elf(f).sections]

            self.assert_ok(self.run_tool(bits, f, '--rename', '.comment',
                                         '.cmnt'))

            expected = ['.cmnt' if n == '.comment' else n for n in before]
            self.assertEqual([s.name for s in self.elf(f).sections], expected)

   def test_rename_to_a_longer_name_fails_and_changes_nothing(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):

            f = self.fixture(f'obj{bits}.o')
            before = self.read_bytes(f)

            r = self.run_tool(bits, f, '--rename', '.data', '.data_longer')
            self.assert_fails(r, 'length > old one NOT supported')
            self.assertEqual(self.read_bytes(f), before)

