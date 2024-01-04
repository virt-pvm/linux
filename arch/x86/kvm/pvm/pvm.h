/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_PVM_H
#define __KVM_X86_PVM_H

#define PT_L4_SHIFT		39
#define PT_L4_SIZE		(1UL << PT_L4_SHIFT)
#define DEFAULT_RANGE_L4_SIZE	(32 * PT_L4_SIZE)

#define PT_L5_SHIFT		48
#define PT_L5_SIZE		(1UL << PT_L5_SHIFT)
#define DEFAULT_RANGE_L5_SIZE	(32 * PT_L5_SIZE)

extern u32 pml4_index_start;
extern u32 pml4_index_end;
extern u32 pml5_index_start;
extern u32 pml5_index_end;

extern u64 *host_mmu_root_pgd;

void host_mmu_destroy(void);
int host_mmu_init(void);

#endif /* __KVM_X86_PVM_H */
