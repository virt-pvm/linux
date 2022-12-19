// SPDX-License-Identifier: GPL-2.0
#include "relocs.h"

struct opts opts;

void die(char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	exit(1);
}

static void usage(void)
{
	die("relocs [--abs-syms|--abs-relocs|--reloc-info|--text|--realmode|--keep]" \
	    " vmlinux\n");
}

int main(int argc, char **argv)
{
	const char *fname;
	FILE *fp;
	int i;
	unsigned char e_ident[EI_NIDENT];

	fname = NULL;
	for (i = 1; i < argc; i++) {
		char *arg = argv[i];
		if (*arg == '-') {
			if (strcmp(arg, "--abs-syms") == 0) {
				opts.show_absolute_syms = true;
				continue;
			}
			if (strcmp(arg, "--abs-relocs") == 0) {
				opts.show_absolute_relocs = true;
				continue;
			}
			if (strcmp(arg, "--reloc-info") == 0) {
				opts.show_reloc_info = true;
				continue;
			}
			if (strcmp(arg, "--text") == 0) {
				opts.as_text = true;
				continue;
			}
			if (strcmp(arg, "--realmode") == 0) {
				opts.use_real_mode = true;
				continue;
			}
			if (strcmp(arg, "--keep") == 0) {
				opts.keep_relocs = true;
				continue;
			}
		}
		else if (!fname) {
			fname = arg;
			continue;
		}
		usage();
	}
	if (!fname) {
		usage();
	}
	if (opts.keep_relocs)
		fp = fopen(fname, "r+");
	else
		fp = fopen(fname, "r");
	if (!fp) {
		die("Cannot open %s: %s\n", fname, strerror(errno));
	}
	if (fread(&e_ident, 1, EI_NIDENT, fp) != EI_NIDENT) {
		die("Cannot read %s: %s", fname, strerror(errno));
	}
	rewind(fp);
	if (e_ident[EI_CLASS] == ELFCLASS64)
		process_64(fp);
	else
		process_32(fp);
	fclose(fp);
	return 0;
}
