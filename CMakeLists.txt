# SPDX-License-Identifier: BSD-2-Clause
cmake_minimum_required(VERSION 3.10)

project(elfhack C)

set(CMAKE_VERBOSE_MAKEFILE OFF)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

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

# The ELF class is fixed at compile time (USE_ELF32 / USE_ELF64), so each
# class gets its own binary: elfhack32 for ELFCLASS32 files and elfhack64
# for ELFCLASS64 ones, whatever the bitness of the host.

foreach(bits 32 64)
   add_executable(elfhack${bits} ${SOURCES})
   target_compile_definitions(elfhack${bits} PRIVATE USE_ELF${bits})
   target_include_directories(elfhack${bits} PRIVATE include)
endforeach()

include(GNUInstallDirs)
install(TARGETS elfhack32 elfhack64 DESTINATION ${CMAKE_INSTALL_BINDIR})
