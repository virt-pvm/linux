#ifndef __KVM_X86_PVM_SWITCHER_H
#define __KVM_X86_PVM_SWITCHER_H

#include <linux/smp.h>
#include <asm/switcher.h>

/*
 * OOT PVM cannot extend struct tss_struct with struct tss_extra.  Store the
 * switcher state in the unused tail padding of the per-CPU TSS allocation.
 */
#define TSS_EX_OFFSET		(sizeof(struct tss_struct) - sizeof(struct tss_extra))

static __always_inline struct tss_extra *current_tss_extra(void)
{
	BUILD_BUG_ON(TSS_EX_OFFSET < offsetofend(struct tss_struct, io_bitmap));
	BUILD_BUG_ON(TSS_EX_OFFSET + sizeof(struct tss_extra) >
		    sizeof(struct tss_struct));

	return (struct tss_extra *)((unsigned long)this_cpu_ptr(&cpu_tss_rw.x86_tss) +
		                  TSS_EX_OFFSET);
}

#endif
