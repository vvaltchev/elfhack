# This is a commodity fake Makefile that allows people to run the build from the
# project's root directory, instead of entering in the build/ directory first.

MAKEFLAGS += --no-print-directory

PREREQUISITES := $(TCROOT) build/CMakeCache.txt

all: $(PREREQUISITES)
	@$(MAKE) -C build

clean: $(PREREQUISITES)
	@$(MAKE) -C build clean

install: $(PREREQUISITES)
	@$(MAKE) -C build install

test: all
	@tests/run_tests

coverage:
	@tests/run_tests --coverage

build/CMakeCache.txt:
	@echo No CMakeCache.txt found: running CMake first.
	@mkdir -p build && cd build && cmake ..

.PHONY: all clean install test coverage
