/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_MODULE_H
#define _ASM_X86_MODULE_H

#include <asm-generic/module.h>
#include <asm/orc_types.h>

#ifdef CONFIG_X86_PIE
struct mod_section {
	unsigned int shndx;
	unsigned int num_entries;
	unsigned int max_entries;
};
#endif

struct mod_arch_specific {
#ifdef CONFIG_UNWINDER_ORC
	unsigned int num_orcs;
	int *orc_unwind_ip;
	struct orc_entry *orc_unwind;
#endif
#ifdef CONFIG_X86_PIE
	struct mod_section got;
#endif
};

#endif /* _ASM_X86_MODULE_H */
