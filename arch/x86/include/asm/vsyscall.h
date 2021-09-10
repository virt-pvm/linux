/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_VSYSCALL_H
#define _ASM_X86_VSYSCALL_H

#include <asm/pgtable.h>
#include <linux/seqlock.h>
#include <uapi/asm/vsyscall.h>

#ifdef CONFIG_X86_VSYSCALL_EMULATION
extern void map_vsyscall(void);
extern void set_vsyscall_pgtable_user_bits(pgd_t *root);

/*
 * Called on instruction fetch fault in vsyscall page.
 * Returns true if handled.
 */
extern bool emulate_vsyscall(unsigned long error_code,
			     struct pt_regs *regs, unsigned long address);
static inline void native_set_vsyscall_page(phys_addr_t phys, pgprot_t flags)
{
	pgprot_val(flags) &= __default_kernel_pte_mask;
	set_pte_vaddr(VSYSCALL_ADDR, pfn_pte(phys >> PAGE_SHIFT, flags));
}

#ifndef CONFIG_PARAVIRT_XXL
#define __set_vsyscall_page	native_set_vsyscall_page
#else
#include <asm/paravirt.h>
#endif

#else
static inline void map_vsyscall(void) {}
static inline bool emulate_vsyscall(unsigned long error_code,
				    struct pt_regs *regs, unsigned long address)
{
	return false;
}
#endif

#endif /* _ASM_X86_VSYSCALL_H */
