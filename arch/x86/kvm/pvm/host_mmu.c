// SPDX-License-Identifier: GPL-2.0-only
/*
 * PVM host mmu implementation
 *
 * Copyright (C) 2020 Ant Group
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/vmalloc.h>

#include <asm/cpufeature.h>
#include <asm/vsyscall.h>
#include <asm/pgtable.h>

#include "mmu.h"
#include "mmu/spte.h"
#include "pvm.h"

#define L4_PT_INDEX(address)	__PT_INDEX(address, 4, 9)
#define L5_PT_INDEX(address)	__PT_INDEX(address, 5, 9)

#define PVM_GUEST_MAPPING_START		(-1UL << 47)

static struct vm_struct *pvm_va_range;

u32 pml4_index_start;
u32 pml4_index_end;
u32 pml5_index_start;
u32 pml5_index_end;

static int __init guest_address_space_init(void)
{
	if (IS_ENABLED(CONFIG_KASAN_VMALLOC)) {
		pr_warn("CONFIG_KASAN_VMALLOC is not compatible with PVM");
		return -1;
	}

	if (pgtable_l5_enabled()) {
		if (IS_ENABLED(CONFIG_KASAN)) {
			pr_warn("CONFIG_KASAN is not compatible with PVM on 5-level paging mode");
			return -1;
		}

		BUILD_BUG_ON(PVM_GUEST_MAPPING_START != VADDR_END_L5);

		pml4_index_start = L4_PT_INDEX(PVM_GUEST_MAPPING_START);
		pml4_index_end = L4_PT_INDEX(RAW_CPU_ENTRY_AREA_BASE);

		pvm_va_range = get_vm_area_align(DEFAULT_RANGE_L5_SIZE, PT_L5_SIZE,
						 VM_ALLOC|VM_NO_GUARD);
		if (!pvm_va_range) {
			pml5_index_start = 0x1ff;
			pml5_index_end = 0x1ff;
		} else {
			pml5_index_start = L5_PT_INDEX((u64)pvm_va_range->addr);
			pml5_index_end = L5_PT_INDEX((u64)pvm_va_range->addr +
						     (u64)pvm_va_range->size);
		}
	} else {
		pvm_va_range = get_vm_area_align(DEFAULT_RANGE_L4_SIZE, PT_L4_SIZE,
						 VM_ALLOC|VM_NO_GUARD);
		if (!pvm_va_range)
			return -1;

		pml4_index_start = L4_PT_INDEX((u64)pvm_va_range->addr);
		pml4_index_end = L4_PT_INDEX((u64)pvm_va_range->addr + (u64)pvm_va_range->size);
		pml5_index_start = 0x1ff;
		pml5_index_end = 0x1ff;
	}

	return 0;
}

static __init void clone_host_mmu(u64 *spt, u64 *host, int index_start, int index_end)
{
	int i;

	for (i = PTRS_PER_PGD/2; i < PTRS_PER_PGD; i++) {
		/* clone only the range that doesn't belong to guest */
		if (i >= index_start && i < index_end)
			continue;

		/* remove userbit from host mmu, which also disable VSYSCALL page */
		spt[i] = host[i] & ~(_PAGE_USER | SPTE_MMU_PRESENT_MASK);
	}
}

u64 *host_mmu_root_pgd;
u64 *host_mmu_la57_top_p4d;

int __init host_mmu_init(void)
{
	u64 *host_pgd;

	if (guest_address_space_init() < 0)
		return -ENOMEM;

	if (!boot_cpu_has(X86_FEATURE_PTI))
		host_pgd = (void *)current->active_mm->pgd;
	else
		host_pgd = (void *)kernel_to_user_pgdp(current->active_mm->pgd);

	host_mmu_root_pgd = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);

	if (!host_mmu_root_pgd) {
		host_mmu_destroy();
		return -ENOMEM;
	}
	if (pgtable_l5_enabled()) {
		host_mmu_la57_top_p4d = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
		if (!host_mmu_la57_top_p4d) {
			host_mmu_destroy();
			return -ENOMEM;
		}

		clone_host_mmu(host_mmu_root_pgd, host_pgd, pml5_index_start, pml5_index_end);
		clone_host_mmu(host_mmu_la57_top_p4d, __va(host_pgd[511] & SPTE_BASE_ADDR_MASK),
				pml4_index_start, pml4_index_end);
		host_mmu_root_pgd[511] = (host_pgd[511] & ~SPTE_BASE_ADDR_MASK) |
					  __pa(host_mmu_la57_top_p4d);
		host_mmu_root_pgd[511] &= ~(_PAGE_USER | SPTE_MMU_PRESENT_MASK);
	} else {
		clone_host_mmu(host_mmu_root_pgd, host_pgd, pml4_index_start, pml4_index_end);
	}

	return 0;
}

void host_mmu_destroy(void)
{
	if (pvm_va_range)
		free_vm_area(pvm_va_range);
	if (host_mmu_root_pgd)
		free_page((unsigned long)(void *)host_mmu_root_pgd);
	if (host_mmu_la57_top_p4d)
		free_page((unsigned long)(void *)host_mmu_la57_top_p4d);
	pvm_va_range = NULL;
	host_mmu_root_pgd = NULL;
	host_mmu_la57_top_p4d = NULL;
}
