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

#include <asm/cpufeature.h>
#include <asm/vsyscall.h>
#include <asm/pgtable.h>
#include <asm/setup.h>

#include "mmu.h"
#include "mmu/spte.h"
#include "pvm.h"
#include "pvm_switcher.h"

#define PT_L4_INDEX(address)	__PT_INDEX(address, 4, 9)
#define PT_L5_INDEX(address)	__PT_INDEX(address, 5, 9)

#define PVM_KASAN_L4_SHADOW_START	_AC(0xffffec0000000000, UL)
#define PVM_KASAN_L5_SHADOW_START	_AC(0xffdf000000000000, UL)

#define PVM_GUEST_L4_MAPPING_END	_AC(0xfffffc0000000000, UL)
#define PVM_GUEST_L4_MAPPING_START	(PVM_GUEST_L4_MAPPING_END - DEFAULT_RANGE_L4_SIZE)
#define PVM_GUEST_L5_MAPPING_END	_AC(0xffff000000000000, UL)
#define PVM_GUEST_L5_MAPPING_START	(PVM_GUEST_L5_MAPPING_END - DEFAULT_RANGE_L5_SIZE)

u32 pml4_index_start;
u32 pml4_index_end;
u32 pml5_index_start;
u32 pml5_index_end;

/*
 * kaslr_memory_enabled() is not exported, so check VMEMMAP_START
 * instead.
 */
static bool __init host_kaslr_enabled(void)
{
	if (pgtable_l5_enabled())
		return VMEMMAP_START != __VMEMMAP_BASE_L5;

	return VMEMMAP_START != __VMEMMAP_BASE_L4;
}

static int __init guest_address_space_init(void)
{
	if (IS_ENABLED(CONFIG_KASAN)) {
		pr_warn("CONFIG_KASAN is not compatible with PVM");
		return -1;
	}
	if (host_kaslr_enabled()) {
		pr_warn("KASLR memory randomization is not compatible with PVM");
		return -1;
	}

	/*
	 * Use the fixed x86 KASAN shadow hole as the PVM guest address window.
	 * KASAN disables KASLR because its shadow mappings rely on PGD
	 * alignment, and the same property makes the range suitable for PVM.
	 */
	BUILD_BUG_ON(PVM_GUEST_L4_MAPPING_START < PVM_KASAN_L4_SHADOW_START);
	BUILD_BUG_ON(PVM_GUEST_L5_MAPPING_START < PVM_KASAN_L5_SHADOW_START);
	BUILD_BUG_ON(PVM_GUEST_L4_MAPPING_START < PVM_KASAN_L5_SHADOW_START);
	BUILD_BUG_ON(PVM_GUEST_L4_MAPPING_END > CPU_ENTRY_AREA_BASE);
	BUILD_BUG_ON(PVM_GUEST_L5_MAPPING_END > CPU_ENTRY_AREA_BASE);

	pml4_index_start = PT_L4_INDEX(PVM_GUEST_L4_MAPPING_START);
	pml4_index_end = PT_L4_INDEX(PVM_GUEST_L4_MAPPING_END);

	if (pgtable_l5_enabled()) {
		pml5_index_start = PT_L5_INDEX(PVM_GUEST_L5_MAPPING_START);
		pml5_index_end = PT_L5_INDEX(PVM_GUEST_L5_MAPPING_END);
	} else {
		pml5_index_start = 0x1ff;
		pml5_index_end = 0x1ff;
	}

	return 0;
}

static void __init clone_host_mmu(u64 *spt, u64 *host, int index_start, int index_end)
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

unsigned long pvm_host_idt_entries[NR_VECTORS];

static void __init oot_switcher_init(void)
{
	struct desc_ptr dt;
	gate_desc *idt_base;
	int i, cpu;

	store_idt(&dt);
	idt_base = (gate_desc *)dt.address;

	for (i = 0; i < NR_VECTORS; i++)
		pvm_host_idt_entries[i] = gate_offset(idt_base + i);

	for_each_possible_cpu(cpu) {
		struct tss_extra *tss_ex = per_cpu_tss_extra(cpu);

		tss_ex->host_gs_base = cpu_kernelmode_gs_base(cpu);
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

	oot_switcher_init();

	return 0;
}

void host_mmu_destroy(void)
{
	if (host_mmu_root_pgd)
		free_page((unsigned long)(void *)host_mmu_root_pgd);
	if (host_mmu_la57_top_p4d)
		free_page((unsigned long)(void *)host_mmu_la57_top_p4d);
	host_mmu_root_pgd = NULL;
	host_mmu_la57_top_p4d = NULL;
}
