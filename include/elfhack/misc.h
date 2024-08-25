/* SPDX-License-Identifier: BSD-2-Clause */

#pragma once
#include "basic_defs.h"

bool
is_index_string(const char *str);

bool
is_plain_integer(const char *str);

void
die_with_invalid_index_error(const char *str);

int
file_copy(const char *src, const char *dest);
