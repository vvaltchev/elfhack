/* SPDX-License-Identifier: BSD-2-Clause */

#pragma once
#include <stdbool.h>

#define KB           (1024)
#define MB      (1024 * KB)
#define GB      (1024 * GB)

#define ARRAY_SIZE(a)        ((int)(sizeof(a)/sizeof((a)[0])))
#define TO_PTR(n)            ((void *)(unsigned long)(n))
#define UNUSED_VARIABLE(x)   (void)x


static unsigned long
pow2_round_up_at(unsigned long n, unsigned long pow2unit)
{
   return (n + pow2unit - 1) & -pow2unit;
}
