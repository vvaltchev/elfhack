# SPDX-License-Identifier: BSD-2-Clause

"""
A minimal, read-only ELF parser used by the tests to check what elfhack did,
independently from elfhack's own code. It covers only what the tests need:
the file header, section headers, symbols and relocations of little-endian
ELF32 and ELF64 files.
"""

import struct
from collections import namedtuple

ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1

SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_NOBITS = 8
SHT_REL = 9

SHN_UNDEF = 0
SHN_ABS = 0xfff1
SHN_COMMON = 0xfff2

STT_SECTION = 3

# Offset of st_shndx inside a symbol table entry, per ELF class
_SYM_SHNDX_OFFSET = {ELFCLASS32: 14, ELFCLASS64: 6}

Section = namedtuple(
   'Section',
   'index name type flags addr offset size link info entsize'
)

Symbol = namedtuple('Symbol', 'index name value size info other shndx')
Reloc = namedtuple('Reloc', 'offset sym type addend')

# struct formats, per ELF class
_FORMATS = {
   ELFCLASS32: {
      'ehdr': '<16sHHIIIIIHHHHHH',
      'shdr': '<IIIIIIIIII',
      'sym': '<IIIBBH',
      'rel': '<II',
      'rela': '<IIi',
   },
   ELFCLASS64: {
      'ehdr': '<16sHHIQQQIHHHHHH',
      'shdr': '<IIQQQQIIQQ',
      'sym': '<IBBHQQ',
      'rel': '<QQ',
      'rela': '<QQq',
   },
}


class ElfFile:

   def __init__(self, path):

      with open(path, 'rb') as f:
         self.data = f.read()

      if self.data[:4] != b'\x7fELF':
         raise ValueError(f'{path}: not an ELF file')

      self.elf_class = self.data[4]

      if self.elf_class not in _FORMATS:
         raise ValueError(f'{path}: unknown ELF class {self.elf_class}')

      if self.data[5] != ELFDATA2LSB:
         raise ValueError(f'{path}: only little-endian files are supported')

      self.bits = 32 if self.elf_class == ELFCLASS32 else 64
      self._fmt = _FORMATS[self.elf_class]
      self._parse_header()
      self._parse_sections()

   def _unpack(self, fmt, offset):
      return struct.unpack_from(self._fmt[fmt], self.data, offset)

   def _parse_header(self):
      (_, self.type, self.machine, _, self.entry, self.phoff, self.shoff,
       self.flags, _, self.phentsize, self.phnum, self.shentsize,
       self.shnum, self.shstrndx) = self._unpack('ehdr', 0)

   def _parse_sections(self):

      raw = []

      for i in range(self.shnum):
         raw.append(self._unpack('shdr', self.shoff + i * self.shentsize))

      shstrtab_offset = raw[self.shstrndx][4] if raw else 0
      self.sections = []

      for i, (name, type_, flags, addr, offset, size,
              link, info, _, entsize) in enumerate(raw):

         self.sections.append(Section(
            i, self._cstring(shstrtab_offset + name), type_, flags, addr,
            offset, size, link, info, entsize
         ))

   def _cstring(self, offset):
      end = self.data.index(b'\0', offset)
      return self.data[offset:end].decode()

   def section(self, name):
      """The section named `name`; fails if there is not exactly one."""
      found = [s for s in self.sections if s.name == name]

      if len(found) != 1:
         raise KeyError(f'{len(found)} sections named {name!r}')

      return found[0]

   def section_data(self, name):
      s = self.section(name)
      return self.data[s.offset:s.offset + s.size]

   def symbols(self):
      """All the symbols of the SHT_SYMTAB section, in table order."""
      symtab = next(s for s in self.sections if s.type == SHT_SYMTAB)
      strtab = self.sections[symtab.link]
      result = []

      for i in range(symtab.size // symtab.entsize):

         fields = self._unpack('sym', symtab.offset + i * symtab.entsize)

         if self.elf_class == ELFCLASS32:
            name, value, size, info, other, shndx = fields
         else:
            name, info, other, shndx, value, size = fields

         result.append(Symbol(
            i, self._cstring(strtab.offset + name), value, size, info,
            other, shndx
         ))

      return result

   def symbol_shndx_offset(self, index):
      """The file offset of the st_shndx field of symbol `index`."""
      symtab = next(s for s in self.sections if s.type == SHT_SYMTAB)
      return (symtab.offset + index * symtab.entsize +
              _SYM_SHNDX_OFFSET[self.elf_class])

   def symbol(self, name):
      """The symbol named `name`; fails if there is not exactly one."""
      found = [s for s in self.symbols() if s.name == name]

      if len(found) != 1:
         raise KeyError(f'{len(found)} symbols named {name!r}')

      return found[0]

   def relocations(self, section_name):
      """The entries of a SHT_REL or SHT_RELA section."""
      sec = self.section(section_name)

      if sec.type not in (SHT_REL, SHT_RELA):
         raise ValueError(f'{section_name} is not a relocation section')

      fmt = 'rela' if sec.type == SHT_RELA else 'rel'
      sym_shift = 8 if self.elf_class == ELFCLASS32 else 32
      type_mask = (1 << sym_shift) - 1
      result = []

      for i in range(sec.size // sec.entsize):

         fields = self._unpack(fmt, sec.offset + i * sec.entsize)
         offset, info = fields[0], fields[1]
         addend = fields[2] if fmt == 'rela' else None

         result.append(Reloc(
            offset, info >> sym_shift, info & type_mask, addend
         ))

      return result
