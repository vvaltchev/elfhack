# SPDX-License-Identifier: BSD-2-Clause

"""Actions on symbols and relocations."""

from elf_reader import SHN_ABS, SHN_COMMON, SHN_UNDEF, STT_SECTION
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


   def test_dump_sym_prints_the_symbol_bytes(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):

            f = self.fixture(f'obj{bits}.o')
            elf = self.elf(f)
            sym = elf.symbol('label')
            sec = elf.sections[sym.shndx]
            off = sec.offset + (sym.value - sec.addr)
            data = elf.data[off:off + sym.size]

            r = self.run_tool(bits, f, '--dump-sym', 'label')
            self.assert_ok(r)
            self.assertEqual(r.stdout.decode(),
                             ''.join(f'{b:02x} ' for b in data) + '\n')

   def test_dump_sym_refuses_symbols_without_data_in_the_file(self):
      cases = (
         ('foo', 'not defined in a section'),      # SHN_UNDEF
         ('shared', 'not defined in a section'),   # SHN_COMMON
         ('obj.c', 'not defined in a section'),    # SHN_ABS
         ('zeroed', 'has no data in the file'),    # .bss, SHT_NOBITS
      )
      for bits in ELF_CLASSES:
         for name, message in cases:
            with self.subTest(bits=bits, symbol=name):
               f = self.fixture(f'obj{bits}.o')
               r = self.run_tool(bits, f, '--dump-sym', name)
               self.assert_fails(r, message)
               self.assertEqual(r.stdout, b'')

   def test_get_sym_info_names_the_section_index(self):
      cases = (
         ('foo', f'st_shndx: {SHN_UNDEF} # UNDEF'),
         ('shared', f'st_shndx: {SHN_COMMON} # COMMON'),
         ('obj.c', f'st_shndx: {SHN_ABS} # ABS'),
      )
      for bits in ELF_CLASSES:
         f = self.fixture(f'obj{bits}.o')
         elf = self.elf(f)
         data = elf.symbol('label').shndx

         for name, line in cases + (
            ('label', f'st_shndx: {data} # {elf.sections[data].name}'),
         ):
            with self.subTest(bits=bits, symbol=name):
               r = self.run_tool(bits, f, '--get-sym-info', name)
               self.assert_ok(r)
               self.assertIn(line, r.stdout.decode().splitlines())

   def test_get_sym_info_names_the_reserved_section_indexes(self):
      for bits in ELF_CLASSES:
         f = self.fixture(f'obj{bits}.o')
         shnum = len(self.elf(f).sections)

         for shndx, name in ((0xff00, 'cpu-spec-index'),
                             (0xff20, 'os-spec-index'),
                             (0xffff, 'XINDEX'),
                             (0xfff5, '?'),      # reserved, unassigned
                             (shnum, '?')):      # past the section table
            with self.subTest(bits=bits, shndx=hex(shndx)):
               self.patch_symbol_shndx(f, 'counter', shndx)
               r = self.run_tool(bits, f, '--get-sym-info', 'counter')
               self.assert_ok(r)
               self.assertIn(f'st_shndx: {shndx} # {name}',
                             r.stdout.decode().splitlines())

   def test_list_syms_names_section_symbols_by_their_section(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):

            f = self.fixture(f'obj{bits}.o')
            elf = self.elf(f)
            sym = next(s for s in elf.symbols()
                       if s.info & 0xf == STT_SECTION)

            r = self.run_tool(bits, f, '--list-syms')
            self.assert_ok(r)
            line = r.stdout.decode().splitlines()[sym.index].split()
            self.assertEqual(line[-1], elf.sections[sym.shndx].name)

            # A section symbol whose section is not in the table: no name,
            # and no read out of the section table.
            elf_shndx = elf.symbol_shndx_offset(sym.index)
            self.patch_bytes(f, elf_shndx, SHN_ABS.to_bytes(2, 'little'))

            r = self.run_tool(bits, f, '--list-syms')
            self.assert_ok(r)
            line = r.stdout.decode().splitlines()[sym.index].split()
            self.assertEqual(line[0], str(sym.index))
            self.assertEqual(line[-1], str(SHN_ABS))  # shndx, then no name

   def test_symbol_names_come_from_the_linked_string_table(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):

            f = self.fixture(f'obj{bits}.o')
            value = self.elf(f).symbol('caller').value

            # .symtab still links to it: only the name of the section changes
            self.rename_section_raw(f, '.strtab', '.strtaX')

            r = self.run_tool(bits, f, '--get-sym-value', 'caller')
            self.assert_ok(r)
            self.assertEqual(r.stdout.decode(), f'0x{value:08x}\n')

   def test_symtab_not_linked_to_a_string_table_is_rejected(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):
            f = self.fixture(f'obj{bits}.o')
            text = self.elf(f).section('.text').index
            self.patch_section_header(f, '.symtab', 'link', text)
            r = self.run_tool(bits, f, '--get-sym-value', 'caller')
            self.assert_fails(r, 'not a string table')

   def test_symtab_with_a_wrong_entry_size_is_rejected(self):
      for bits in ELF_CLASSES:
         f = self.fixture(f'obj{bits}.o')
         good = self.elf(f).section('.symtab').entsize

         for entsize in (0, good + 1):
            with self.subTest(bits=bits, entsize=entsize):
               self.patch_section_header(f, '.symtab', 'entsize', entsize)
               r = self.run_tool(bits, f, '--list-syms')
               self.assert_fails(r, 'sh_entsize')

   def test_file_without_a_symbol_table(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):

            f = self.fixture(f'obj{bits}.o')
            self.rename_section_raw(f, '.symtab', '.symtaX')

            self.assert_fails(self.run_tool(bits, f, '--list-syms'),
                              'No symbol table')
            self.assert_fails(self.run_tool(bits, f, '--get-sym-value',
                                            'caller'), 'not found')

   def test_set_sym_bind_and_type(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):

            f = self.fixture(f'obj{bits}.o')

            self.assert_ok(self.run_tool(bits, f, '--set-sym-bind',
                                         'caller', '2'))     # STB_WEAK
            self.assert_ok(self.run_tool(bits, f, '--set-sym-type',
                                         'caller', '1'))     # STT_OBJECT

            info = self.elf(f).symbol('caller').info
            self.assertEqual((info >> 4, info & 0xf), (2, 1))

   def test_set_sym_bind_and_type_reject_values_too_high(self):
      for bits in ELF_CLASSES:
         for action, what in (('--set-sym-bind', 'bind'),
                              ('--set-sym-type', 'type')):
            with self.subTest(bits=bits, action=action):
               f = self.fixture(f'obj{bits}.o')
               before = self.read_bytes(f)
               r = self.run_tool(bits, f, action, 'caller', '16')
               self.assert_fails(r, f'{what} is too high')
               self.assertEqual(self.read_bytes(f), before)

   def test_swap_symbols(self):
      for bits in ELF_CLASSES:
         with self.subTest(bits=bits):

            f = self.fixture(f'obj{bits}.o')
            rel = '.rel.text' if bits == 32 else '.rela.text'
            elf = self.elf(f)
            foo, baz = elf.symbol('foo'), elf.symbol('baz')
            relocs = elf.relocations(rel)

            r = self.run_tool(bits, f, '--swap-symbols',
                              str(foo.index), str(baz.index))
            self.assert_ok(r)

            # The entries swapped places, and the relocations followed them
            elf = self.elf(f)
            self.assertEqual(elf.symbol('foo').index, baz.index)
            self.assertEqual(elf.symbol('baz').index, foo.index)
            swap = {foo.index: baz.index, baz.index: foo.index}
            self.assertEqual(
               elf.relocations(rel),
               [r._replace(sym=swap.get(r.sym, r.sym)) for r in relocs]
            )

   def test_swap_symbols_rejects_invalid_indexes(self):
      for bits in ELF_CLASSES:
         f = self.fixture(f'obj{bits}.o')
         count = len(self.elf(f).symbols())
         for args, message in ((('0', '1'), 'Invalid symbol index: 0'),
                               (('1', '0'), 'Invalid symbol index: 0'),
                               (('1', str(count)), 'out of bounds'),
                               ((str(count), '1'), 'out of bounds')):
            with self.subTest(bits=bits, indexes=args):
               before = self.read_bytes(f)
               r = self.run_tool(bits, f, '--swap-symbols', *args)
               self.assert_fails(r, message)
               self.assertEqual(self.read_bytes(f), before)

   # The dynamic fixtures have static relocations (.rel[a].text, indexes into
   # .symtab) and dynamic ones (.rel[a].plt, indexes into .dynsym). Actions on
   # .symtab symbols must rewrite the former and leave the latter alone.

   def dyn_reloc_sections(self, bits):
      rela = '' if bits == 32 else 'a'
      return f'.rel{rela}.text', f'.rel{rela}.plt'

   def test_redirect_reloc_leaves_dynamic_relocations_alone(self):
      for bits in ELF_CLASSES:
         static, dynamic = self.dyn_reloc_sections(bits)

         # lib_foo -> lib_bar: the calls in .text are redirected. #2 -> #3:
         # .symtab entries whose indexes are lib_foo's and lib_bar's in
         # .dynsym, as used by .rel[a].plt.
         for sym1, sym2 in (('lib_foo', 'lib_bar'), ('#2', '#3')):
            with self.subTest(bits=bits, symbols=(sym1, sym2)):

               f = self.fixture(f'dyn{bits}')
               elf = self.elf(f)
               i1 = int(sym1[1:]) if sym1[0] == '#' else elf.symbol(sym1).index
               i2 = int(sym2[1:]) if sym2[0] == '#' else elf.symbol(sym2).index
               before = elf.relocations(static)
               dyn_before = elf.section_data(dynamic)

               self.assert_ok(self.run_tool(bits, f, '--redirect-reloc',
                                            sym1, sym2))

               elf = self.elf(f)
               self.assertEqual(
                  elf.relocations(static),
                  [r._replace(sym=i2) if r.sym == i1 else r for r in before]
               )
               self.assertEqual(elf.section_data(dynamic), dyn_before)

   def test_swap_symbols_leaves_dynamic_relocations_alone(self):
      for bits in ELF_CLASSES:
         static, dynamic = self.dyn_reloc_sections(bits)
         elf = self.elf(self.fixture(f'dyn{bits}'))
         foo, baz = elf.symbol('lib_foo').index, elf.symbol('lib_baz').index

         for i1, i2 in ((foo, baz), (2, 3)):
            with self.subTest(bits=bits, indexes=(i1, i2)):

               f = self.fixture(f'dyn{bits}')
               elf = self.elf(f)
               syms = elf.symbols()
               before = elf.relocations(static)
               dyn_before = elf.section_data(dynamic)

               self.assert_ok(self.run_tool(bits, f, '--swap-symbols',
                                            str(i1), str(i2)))

               elf = self.elf(f)
               swap = {i1: i2, i2: i1}
               self.assertEqual(elf.symbols()[i1].name, syms[i2].name)
               self.assertEqual(elf.symbols()[i2].name, syms[i1].name)
               self.assertEqual(
                  elf.relocations(static),
                  [r._replace(sym=swap.get(r.sym, r.sym)) for r in before]
               )
               self.assertEqual(elf.section_data(dynamic), dyn_before)
