# Makefile — Build vulnerable CTF-style target binaries
#
# These binaries are intentionally compiled WITHOUT security protections
# to demonstrate vulnerability analysis.
#
# Flags:
#   -fno-stack-protector  → disable stack canaries
#   -g                    → include debug symbols for GDB analysis
#
# On Linux, additional flags are available:
#   -no-pie, -z execstack
#
# Usage:
#   make          — build all targets
#   make clean    — remove compiled binaries
#
# AUTHORIZED TESTING ONLY

CC = gcc
UNAME := $(shell uname -s)

# Base flags (work on both macOS and Linux)
CFLAGS_BASE = -fno-stack-protector -g -Wall -Wno-deprecated-declarations

# Linux-specific flags
ifeq ($(UNAME),Linux)
    CFLAGS_BASE += -no-pie
    CFLAGS_BOF = $(CFLAGS_BASE) -z execstack
else
    CFLAGS_BOF = $(CFLAGS_BASE)
endif

CFLAGS_VULN = $(CFLAGS_BASE)

TARGETS = vuln_bof vuln_fmt vuln_uaf vuln_heap

.PHONY: all clean info

all: $(TARGETS)
	@echo ""
	@echo "Built $(words $(TARGETS)) vulnerable targets:"
	@for t in $(TARGETS); do echo "  ./$$t"; done
	@echo ""
	@echo "WARNING: These are intentionally vulnerable binaries."
	@echo "         Use only in authorized testing environments."

vuln_bof: vuln_bof.c
	$(CC) $(CFLAGS_BOF) -o $@ $<
	@echo "  [OK] $@ — stack buffer overflow (gets)"

vuln_fmt: vuln_fmt.c
	$(CC) $(CFLAGS_VULN) -o $@ $<
	@echo "  [OK] $@ — format string (printf)"

vuln_uaf: vuln_uaf.c
	$(CC) $(CFLAGS_VULN) -o $@ $<
	@echo "  [OK] $@ — use-after-free (malloc/free)"

vuln_heap: vuln_heap.c
	$(CC) $(CFLAGS_VULN) -o $@ $<
	@echo "  [OK] $@ — heap buffer overflow (strcpy)"

clean:
	rm -f $(TARGETS)
	@echo "Cleaned up binaries."

info:
	@echo "Target binaries and their vulnerability classes:"
	@echo "  vuln_bof  — Stack buffer overflow via gets()"
	@echo "  vuln_fmt  — Format string via printf(user_input)"
	@echo "  vuln_uaf  — Use-after-free via dangling pointer"
	@echo "  vuln_heap — Heap overflow via strcpy() into small buffer"
