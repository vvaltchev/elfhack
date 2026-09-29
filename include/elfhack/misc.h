/* SPDX-License-Identifier: BSD-2-Clause */

#pragma once
#include "basic_defs.h"

bool
is_index_string(const char *str);

bool
is_plain_integer(const char *str);

void
die_with_invalid_index_error(const char *str);

/*
 * Copy `src` to a new temporary file next to `dest`, with the same mode.
 * Returns the temporary file's path (to be freed by the caller), or NULL on
 * failure, after printing an error.
 */
char *
file_copy_to_temp(const char *src, const char *dest);

/*
 * Rename `tmp_path` over `dest` if rc == 0; otherwise remove it. Returns the
 * final exit code: `rc`, or 1 if the rename failed.
 */
int
file_commit_temp(const char *tmp_path, const char *dest, int rc);
