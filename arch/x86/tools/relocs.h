/* SPDX-License-Identifier: GPL-2.0 */
#ifndef RELOCS_H
#define RELOCS_H

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <elf.h>
#include <byteswap.h>
#define USE_BSD
#include <endian.h>
#include <regex.h>
#include <tools/le_byteshift.h>

__attribute__((__format__(printf, 1, 2)))
void die(char *fmt, ...) __attribute__((noreturn));

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

enum symtype {
	S_ABS,
	S_REL,
	S_SEG,
	S_LIN,
	S_NSYMTYPES
};

struct opts {
	bool use_real_mode;
	bool as_text;
	bool show_absolute_syms;
	bool show_absolute_relocs;
	bool show_reloc_info;
	bool keep_relocs;
};

extern struct opts opts;

void process_32(FILE *fp);
void process_64(FILE *fp);
#endif /* RELOCS_H */
