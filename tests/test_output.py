# SPDX-License-Identifier: BSD-2-Clause

"""The -o/--output option."""

import os
import shutil

from elfhack_test import ElfhackTestCase, ELF_CLASSES


class TestOutput(ElfhackTestCase):

   def test_output_equals_in_place_and_keeps_the_input(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):

            f = self.fixture(f'obj{bits}.o')
            original = self.read_bytes(f)
            in_place = self.path('in_place.o')
            out = self.path('out.o')

            shutil.copyfile(f, in_place)
            os.chmod(f, 0o751)

            self.assert_ok(self.run_tool(bits, in_place,
                                         '--rename', '.comment', '.cmnt'))
            self.assert_ok(self.run_tool(bits, f, '-o', out,
                                         '--rename', '.comment', '.cmnt'))

            self.assertEqual(self.read_bytes(f), original)
            self.assertEqual(self.read_bytes(out), self.read_bytes(in_place))
            self.assertEqual(os.stat(out).st_mode & 0o7777, 0o751)

   def test_output_onto_an_existing_file(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):

            f = self.fixture(f'obj{bits}.o')
            out = self.path('out.o')

            for _ in range(2):
               self.assert_ok(self.run_tool(bits, f, '-o', out,
                                            '--rename', '.comment', '.cmnt'))

            self.assertIn('.cmnt', [s.name for s in self.elf(out).sections])

   def test_output_only_carries_the_action_output_on_stdout(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):
            f = self.fixture(f'obj{bits}.o')
            r = self.run_tool(bits, f, '-o', self.path('out.o'),
                              '--section-bin-dump', '.comment')
            self.assert_ok(r)
            self.assertEqual(r.stdout, self.elf(f).section_data('.comment'))

   def test_failed_run_leaves_the_output_untouched(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):

            f = self.fixture(f'obj{bits}.o')
            out = self.path('out.o')

            with open(out, 'wb') as fh:
               fh.write(b'previous contents')

            r = self.run_tool(bits, f, '-o', out,
                              '--rename', '.comment', '.cmnt',
                              '--get-sym-value', 'no_such_symbol')

            self.assert_fails(r)
            self.assertEqual(self.read_bytes(out), b'previous contents')

            # No temporary copy (out.o.XXXXXX) left behind
            leftovers = [n for n in os.listdir(self.tmp)
                         if n.startswith('out.o.')]
            self.assertEqual(leftovers, [])

