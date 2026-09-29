# SPDX-License-Identifier: BSD-2-Clause

"""
Common infrastructure for the elfhack tests: where the binaries and the
fixtures are, a scratch directory per test, and a way to run the tool that
never lets a crash pass as an ordinary failure.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from collections import namedtuple

from elf_reader import ElfFile

TESTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES_DIR = os.path.join(TESTS_DIR, 'fixtures')

# Both the ELF classes the tool is built for.
ELF_CLASSES = (32, 64)

# Seconds: the tool works on tiny files, anything slower is a hang.
TIMEOUT = 10

Result = namedtuple('Result', 'rc stdout stderr')


def build_dir():
   """The directory containing elfhack32 and elfhack64 (set by run_tests)."""
   path = os.environ.get('ELFHACK_BUILD_DIR')

   if not path:
      raise RuntimeError('ELFHACK_BUILD_DIR not set: use tests/run_tests')

   return path


class ElfhackTestCase(unittest.TestCase):

   def setUp(self):
      self._tmp = tempfile.TemporaryDirectory(prefix='elfhack-test-')
      self.tmp = self._tmp.name

   def tearDown(self):
      self._tmp.cleanup()

   def tool(self, bits):
      return os.path.join(build_dir(), f'elfhack{bits}')

   def fixture(self, name):
      """
      A private copy of the fixture `name` in the test's scratch directory:
      the tool modifies its input in place, the originals must never change.
      """
      dest = os.path.join(self.tmp, name)
      shutil.copyfile(os.path.join(FIXTURES_DIR, name), dest)
      return dest

   def path(self, name):
      """A path in the test's scratch directory."""
      return os.path.join(self.tmp, name)

   def run_tool(self, bits, *args):
      """
      Run elfhack<bits> with `args`. Stdout is returned as bytes (some
      actions dump binary data), stderr as text. A run killed by a signal
      fails the test right away, whatever the test expected.
      """
      p = subprocess.run(
         [self.tool(bits), *args],
         capture_output=True,
         timeout=TIMEOUT,
      )

      if p.returncode < 0:
         self.fail(
            f'elfhack{bits} {" ".join(args)} was killed by signal '
            f'{-p.returncode}\nstderr: {p.stderr.decode(errors="replace")}'
         )

      return Result(p.returncode, p.stdout, p.stderr.decode(errors='replace'))

   def assert_ok(self, result):
      self.assertEqual(
         result.rc, 0, f'expected success, got exit code {result.rc}\n'
                       f'stderr: {result.stderr}'
      )

   def assert_fails(self, result, message=None):
      """
      The run failed with exit code 1 and, if given, printed `message` on
      stderr.
      """
      self.assertEqual(
         result.rc, 1, f'expected exit code 1, got {result.rc}\n'
                       f'stderr: {result.stderr}'
      )

      if message is not None:
         self.assertIn(message, result.stderr)

   def elf(self, path):
      return ElfFile(path)

   def read_bytes(self, path):
      with open(path, 'rb') as f:
         return f.read()
