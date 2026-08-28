#ifndef __KVM_X86_PVM_SWITCHER_H
#define __KVM_X86_PVM_SWITCHER_H

#include <asm/ibt.h>
#include "switcher.h"

#define PVM_IDT_ALIGN	(16 * (1 + HAS_KERNEL_IBT))

#ifndef __ASSEMBLY__
#include <linux/smp.h>

extern char pvm_entries_start[];

asmlinkage void switcher_double_fault(void);
asmlinkage void switcher_nmi(void);
asmlinkage void switcher_debug(void);
asmlinkage void switcher_mce(void);
asmlinkage void entry_pvm_SYSCALL32_ignore(void);

/*
 * OOT PVM cannot extend struct tss_struct with struct tss_extra.  Store the
 * switcher state in the unused tail padding of the per-CPU TSS allocation.
 */
#define TSS_EX_OFFSET		(sizeof(struct tss_struct) - sizeof(struct tss_extra))

static __always_inline struct tss_extra *per_cpu_tss_extra(int cpu)
{
	BUILD_BUG_ON(TSS_EX_OFFSET < offsetofend(struct tss_struct, io_bitmap));
	BUILD_BUG_ON(TSS_EX_OFFSET + sizeof(struct tss_extra) >
		    sizeof(struct tss_struct));

	return (struct tss_extra *)((unsigned long)per_cpu_ptr(&cpu_tss_rw.x86_tss, cpu) +
				   TSS_EX_OFFSET);
}

static __always_inline struct tss_extra *current_tss_extra(void)
{
	return (struct tss_extra *)((unsigned long)this_cpu_ptr(&cpu_tss_rw.x86_tss) +
				   TSS_EX_OFFSET);
}
#endif /* __ASSEMBLY__ */

#endif
