# SPDX-License-Identifier: BSD-2-Clause
cmake_minimum_required(VERSION 3.10)

project(elfhack C)

set(CMAKE_VERBOSE_MAKEFILE OFF)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Without a build type, CMake adds neither optimization nor debug flags:
# default to Debug, which gives debug info. Release, RelWithDebInfo etc.
# get exactly their own flags.
if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
   set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

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

add_compile_options(-Wall -Wextra -Werror)

# Coverage instrumentation (gcov). Normally not set by hand: `tests/run_tests
# --coverage` makes its own build with it (see TESTING.md).
option(COVERAGE "Build with gcov coverage instrumentation" OFF)

if (COVERAGE)
   add_compile_options(--coverage -O0)
   set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
endif()

# The ELF class is fixed at compile time (USE_ELF32 / USE_ELF64), so each
# class gets its own binary: elfhack32 for ELFCLASS32 files and elfhack64
# for ELFCLASS64 ones, whatever the bitness of the host.

# Extra C sources compiled into both binaries, e.g. to add commands with
# REGISTER_CMD without patching this file. A ;-separated list of paths,
# absolute or relative to this directory. They are compiled into the
# executables directly: never put them in a static library, the linker would
# drop the unreferenced objects and their constructor-based registration.
set(ELFHACK_EXTRA_SOURCES "" CACHE STRING
    "Extra C sources compiled into elfhack32 and elfhack64 (;-separated)")

foreach(bits 32 64)
   add_executable(elfhack${bits} ${SOURCES} ${ELFHACK_EXTRA_SOURCES})
   target_compile_definitions(elfhack${bits} PRIVATE USE_ELF${bits})
   target_include_directories(elfhack${bits} PRIVATE include)
endforeach()

include(GNUInstallDirs)
install(TARGETS elfhack32 elfhack64 DESTINATION ${CMAKE_INSTALL_BINDIR})

# `ctest` (or `make test`) runs the test suite on this build's binaries.
enable_testing()
add_test(
   NAME elfhack_tests
   COMMAND ${CMAKE_SOURCE_DIR}/tests/run_tests --build-dir ${CMAKE_BINARY_DIR}
)
