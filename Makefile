# This is a commodity fake Makefile that allows people to run the build from the
# project's root directory, instead of entering in the build/ directory first.

MAKEFLAGS += --no-print-directory

PREREQUISITES := $(TCROOT) build/CMakeCache.txt

all: $(PREREQUISITES)
	@$(MAKE) -C build

clean: $(PREREQUISITES)
	@$(MAKE) -C build clean

build/CMakeCache.txt:
	@echo No CMakeCache.txt found: running CMake first.
	@mkdir -p build && cd build && cmake ..

.PHONY: all clean
