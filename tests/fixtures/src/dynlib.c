/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * The shared library the dynamic fixtures (dyn32, dyn64) are linked
 * against. Only needed to link them: it is not committed, and the fixtures
 * are never run.
 */

int lib_foo(int x) { return x + 1; }
int lib_bar(int x) { return x + 2; }
int lib_baz(int x) { return x + 3; }
