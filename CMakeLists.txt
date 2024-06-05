# SPDX-License-Identifier: BSD-2-Clause
cmake_minimum_required(VERSION 3.8)

project(elfhack C)

set(CMAKE_VERBOSE_MAKEFILE off)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

list(APPEND

   SOURCES
   "src/elfhack.c"
)

add_compile_options(-Wall -Wextra -ggdb)
add_executable(elfhack ${SOURCES})
