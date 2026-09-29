# SPDX-License-Identifier: BSD-2-Clause

"""Command line handling, input validation and exit codes."""

from elfhack_test import ElfhackTestCase, ELF_CLASSES


class TestCli(ElfhackTestCase):

   def test_help_lists_the_actions(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):
            r = self.run_tool(bits, '--help')
            self.assertIn('Usage:', r.stderr)
            self.assertIn('--rename', r.stderr)

   def test_help_lists_every_kind_of_option(self):
      # One option per type: action, enum modifier, string modifier
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):
            r = self.run_tool(bits, '--help')
            words = r.stderr.split()
            for opt in ('--list-syms', '--set-symbol-input-format',
                        '--output', '-o'):
               self.assertTrue(opt in words, f'{opt} missing from --help')

   def test_unknown_option_fails(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):
            f = self.fixture(f'obj{bits}.o')
            self.assert_fails(self.run_tool(bits, f, '--no-such-option'))

   def test_unknown_option_is_reported_on_stderr(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):
            f = self.fixture(f'obj{bits}.o')
            r = self.run_tool(bits, f, '--no-such-option')
            self.assert_fails(r, "option '--no-such-option' not recognized")
            self.assertEqual(r.stdout, b'')

   def test_empty_index_is_rejected(self):
      for bits in ELF_CLASSES:
         f = self.fixture(f'obj{bits}.o')
         for args in (('-sf', 'index', '--get-sym-value', ''),
                      ('-Sf', 'index', '--section-bin-dump', '')):
            with self.subTest(bits=bits, option=args[0]):
               r = self.run_tool(bits, f, *args)
               self.assert_fails(r, "invalid index ''")
               self.assertEqual(r.stdout, b'')

   def test_wrong_elf_class_is_rejected(self):
      for bits, other in ((32, 64), (64, 32)):
         with self.subTest(bits=bits):
            f = self.fixture(f'obj{other}.o')
            r = self.run_tool(bits, f, '--list-syms')
            self.assert_fails(r, f'expected {bits}-bit binary')

   def test_file_shorter_than_elf_header_is_rejected(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):

            f = self.path('short.elf')

            with open(f, 'wb') as fh:
               fh.write(b'\x7fELF\x01\x01\x01')

            r = self.run_tool(bits, f, '--check-entry-point', '0')
            self.assert_fails(r, 'too small to be an ELF file')

   def test_failing_action_exits_with_1(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):
            f = self.fixture(f'obj{bits}.o')
            r = self.run_tool(bits, f, '--get-sym-value', 'no_such_symbol')
            self.assert_fails(r, 'not found')

   def test_processing_stops_at_the_first_failing_action(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):

            f = self.fixture(f'obj{bits}.o')
            r = self.run_tool(bits, f,
                              '--rename', '.comment', '.cmnt',
                              '--get-sym-value', 'no_such_symbol',
                              '--rename', '.cmnt', '.cm')

            self.assert_fails(r)
            names = [s.name for s in self.elf(f).sections]
            self.assertIn('.cmnt', names)
            self.assertNotIn('.cm', names)

