# SPDX-License-Identifier: BSD-2-Clause
cmake_minimum_required(VERSION 3.8)

project(elfhack C)

set(CMAKE_VERBOSE_MAKEFILE off)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

list(APPEND

   SOURCES
   "src/elfhack.c"
   "src/elf_utils.c"
   "src/section_cmds.c"
   "src/symbol_cmds.c"
   "src/segment_cmds.c"
   "src/misc_cmds.c"
   "src/relocs_cmds.c"
   "src/utils.c"
   "src/misc.c"
)

add_compile_options(-Wall -Wextra -Werror -Wno-unused-function -ggdb)
add_executable(elfhack ${SOURCES})

target_include_directories(elfhack PUBLIC include)
