# SPDX-License-Identifier: BSD-2-Clause

"""Actions on symbols and relocations."""

from elfhack_test import ElfhackTestCase, ELF_CLASSES


class TestSymbols(ElfhackTestCase):

   def test_get_sym_value(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):
            f = self.fixture(f'prog{bits}')
            r = self.run_tool(bits, f, '--get-sym-value', 'version')
            self.assert_ok(r)
            value = self.elf(f).symbol('version').value
            self.assertEqual(r.stdout.decode(), f'0x{value:08x}\n')

   def test_set_sym_strval(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):

            f = self.fixture(f'prog{bits}')
            r = self.run_tool(bits, f,
                              '--set-sym-strval', '.data', 'version', '1.2.3')
            self.assert_ok(r)

            elf = self.elf(f)
            sym = elf.symbol('version')
            sec = elf.sections[sym.shndx]
            off = sec.offset + (sym.value - sec.addr)
            self.assertEqual(elf.data[off:off + 6], b'1.2.3\0')

   def test_symbol_index_out_of_range_is_rejected(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):

            f = self.fixture(f'obj{bits}.o')
            count = len(self.elf(f).symbols())

            r = self.run_tool(bits, f, '--get-sym-info', f'#{count - 1}')
            self.assert_ok(r)

            r = self.run_tool(bits, f, '--get-sym-info', f'#{count}')
            self.assert_fails(r, f'invalid symbol index {count}')

   def test_check_entry_point(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):

            f = self.fixture(f'prog{bits}')
            entry = self.elf(f).entry

            r = self.run_tool(bits, f, '--check-entry-point', hex(entry))
            self.assert_ok(r)

            r = self.run_tool(bits, f, '--check-entry-point', hex(entry + 1))
            self.assert_fails(r, 'entry point')

   def test_redirect_reloc(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):

            f = self.fixture(f'obj{bits}.o')
            rel = '.rel.text' if bits == 32 else '.rela.text'
            elf = self.elf(f)
            foo = elf.symbol('foo').index
            bar = elf.symbol('bar').index
            before = elf.relocations(rel)

            self.assertEqual(sum(1 for r in before if r.sym == foo), 2)
            self.assert_ok(self.run_tool(bits, f,
                                         '--redirect-reloc', 'foo', 'bar'))

            expected = [
               r._replace(sym=bar) if r.sym == foo else r for r in before
            ]
            self.assertEqual(self.elf(f).relocations(rel), expected)

