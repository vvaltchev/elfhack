# SPDX-License-Identifier: BSD-2-Clause

"""Command line handling, input validation and exit codes."""

import os
import shutil

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

   def test_other_byte_order_is_rejected(self):
      for bits in ELF_CLASSES:
         for ei_data in (0, 2):           # ELFDATANONE, ELFDATA2MSB
            with self.subTest(bits=bits, ei_data=ei_data):
               f = self.fixture(f'obj{bits}.o')
               self.patch_bytes(f, 5, bytes([ei_data]))  # e_ident[EI_DATA]
               r = self.run_tool(bits, f, '--list-syms')
               self.assert_fails(r, 'byte order')
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



class TestReadOnlyFiles(ElfhackTestCase):

   # Actions that only read the file, with their arguments, per fixture
   READ_ONLY_ACTIONS = (
      ('obj', ('--section-bin-dump', '.comment')),
      ('obj', ('--dump-sym', 'label')),
      ('obj', ('--get-sym-value', 'caller')),
      ('obj', ('--list-syms',)),
      ('obj', ('--get-sym-info', 'caller')),
      ('obj', ('--list-section-syms', '.text')),
      ('obj', ('--get-section-sym-value', '.text', 'caller')),
      ('prog', ('--check-mem-size', '0x10000000000', 'b')),
      ('prog', ('--check-entry-point', 'ENTRY')),
      ('prog', ('--verify-flat-elf',)),
   )

   def setUp(self):
      super().setUp()
      if os.geteuid() == 0:
         self.skipTest('root can write to read-only files')

   def read_only_copy(self, name):
      """A read-only copy of fixture `name`, next to the writable one."""
      f = self.path(f'ro-{name}')
      if not os.path.exists(f):
         shutil.copyfile(self.fixture(name), f)
         os.chmod(f, 0o444)
      return f

   def test_read_only_actions_work_on_read_only_files(self):
      for bits in ELF_CLASSES:
         for fixture, args in self.READ_ONLY_ACTIONS:
            with self.subTest(bits=bits, action=args[0]):

               name = f'{fixture}{bits}' + ('.o' if fixture == 'obj' else '')
               writable = self.fixture(name)
               entry = hex(self.elf(writable).entry)
               args = tuple(entry if a == 'ENTRY' else a for a in args)

               expected = self.run_tool(bits, writable, *args)
               f = self.read_only_copy(name)
               original = self.read_bytes(f)
               r = self.run_tool(bits, f, *args)

               # Same outcome as on the writable copy, down to the messages
               self.assertEqual(
                  (r.rc, r.stdout, r.stderr.replace(f, writable)),
                  (expected.rc, expected.stdout, expected.stderr)
               )
               self.assertEqual(self.read_bytes(f), original)

   def test_writing_actions_fail_on_read_only_files(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):
            f = self.read_only_copy(f'obj{bits}.o')
            original = self.read_bytes(f)
            r = self.run_tool(bits, f, '--list-syms',
                              '--rename', '.comment', '.cmnt')
            self.assert_fails(r, 'Permission denied')
            self.assertEqual(r.stdout, b'')
            self.assertEqual(self.read_bytes(f), original)
