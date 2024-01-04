/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_SWITCHER_H
#define _ASM_X86_SWITCHER_H

#ifdef CONFIG_X86_64
#include <asm/processor-flags.h>

#define SWITCH_EXIT_REASONS_SYSCALL		1024
#define SWITCH_EXIT_REASONS_FAILED_VMETNRY	1025

/* Bits allowed to be set in the underlying eflags */
#define SWITCH_ENTER_EFLAGS_ALLOWED	(X86_EFLAGS_FIXED | X86_EFLAGS_IF |\
					 X86_EFLAGS_TF | X86_EFLAGS_RF |\
					 X86_EFLAGS_AC | X86_EFLAGS_OF | \
					 X86_EFLAGS_DF | X86_EFLAGS_SF | \
					 X86_EFLAGS_ZF | X86_EFLAGS_AF | \
					 X86_EFLAGS_PF | X86_EFLAGS_CF | \
					 X86_EFLAGS_ID | X86_EFLAGS_NT)

/* Bits must be set in the underlying eflags */
#define SWITCH_ENTER_EFLAGS_FIXED	(X86_EFLAGS_FIXED | X86_EFLAGS_IF)

#ifndef __ASSEMBLY__
#include <linux/cache.h>

struct pt_regs;

/*
 * Extra per CPU control structure lives in the struct tss_struct.
 *
 * The page-size-aligned struct tss_struct has enough room to accommodate
 * this extra data without increasing its size.
 *
 * The extra data is also in the first page of struct tss_struct whose
 * read-write mapping (percpu cpu_tss_rw) is in the KPTI's user pagetable,
 * so that it can even be accessible via cpu_tss_rw in the entry code.
 */
struct tss_extra {
	/* Saved host CR3 to be loaded after VM exit. */
	unsigned long host_cr3;
	/*
	 * Saved host stack to be loaded after VM exit. This also serves as a
	 * flag to indicate that it is entering the guest world in the switcher
	 * or has been in the guest world in the host entries.
	 */
	unsigned long host_rsp;
	/* Prepared guest CR3 to be loaded before VM enter. */
	unsigned long enter_cr3;
} ____cacheline_aligned;

extern struct pt_regs *switcher_enter_guest(void);
extern const char entry_SYSCALL_64_switcher[];
extern const char entry_SYSCALL_64_switcher_safe_stack[];
extern const char entry_SYSRETQ_switcher_unsafe_stack[];
#endif /* __ASSEMBLY__ */

#endif /* CONFIG_X86_64 */

#endif /* _ASM_X86_SWITCHER_H */
