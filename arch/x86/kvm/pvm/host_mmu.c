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
#include <asm/traps.h>

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

u64 *host_mmu_root_pgd;
u64 *host_mmu_la57_top_p4d;

static gate_desc switcher_idt_table[NR_VECTORS] __aligned(PAGE_SIZE);
unsigned long pvm_host_idt_entries[NR_VECTORS];

static u64 *idt_p4d;
static u64 *idt_pud;
static u64 *idt_pmd;
static u64 *idt_pte;
static bool idt_global_cleared;
static bool idt_global_was_set;

static bool __init clone_level(u64 *parent, u64 idx, u64 **new_child)
{
	u64 e = parent[idx];
	u64 *old_base;
	u64 *new_base;
	u64 flags;

	if ((e & (_PAGE_PSE | _PAGE_PRESENT)) != _PAGE_PRESENT)
		return false;

	old_base = (u64 *)__va(e & PTE_PFN_MASK);
	new_base = (u64 *)__get_free_page(GFP_KERNEL);
	if (!new_base)
		return false;

	memcpy(new_base, old_base, PAGE_SIZE);
	flags = e & PTE_FLAGS_MASK;
	flags &= ~(_PAGE_USER | SPTE_MMU_PRESENT_MASK);
	parent[idx] = virt_to_phys(new_base) | flags;

	*new_child = new_base;
	return true;
}

/* __flush_tlb_all() is exported symbol but flush_tlb_all() is not. */
static void do_flush_tlb_all(void *info)
{
	__flush_tlb_all();
}

static void pvm_flush_tlb_all(void)
{
	on_each_cpu(do_flush_tlb_all, NULL, 1);
}

static void free_idt_page_table(void)
{
	free_page((unsigned long)idt_p4d);
	free_page((unsigned long)idt_pud);
	free_page((unsigned long)idt_pmd);
	free_page((unsigned long)idt_pte);
	idt_p4d = NULL;
	idt_pud = NULL;
	idt_pmd = NULL;
	idt_pte = NULL;
}

static int __init remap_idt(u64 *idt_pgd, void *idt_va)
{
	unsigned long va = CPU_ENTRY_AREA_RO_IDT;
	unsigned long pa = slow_virt_to_phys((void *)idt_va);
	u64 e, flags;

	if (pgtable_l5_enabled()) {
		if (!clone_level(idt_pgd, pgd_index(va), &idt_p4d))
			return -ENOMEM;
		if (!clone_level(idt_p4d, p4d_index(va), &idt_pud))
			return -ENOMEM;
	} else if (!clone_level(idt_pgd, pgd_index(va), &idt_pud)) {
		return -ENOMEM;
	}

	if (!clone_level(idt_pud, pud_index(va), &idt_pmd))
		return -ENOMEM;
	if (!clone_level(idt_pmd, pmd_index(va), &idt_pte))
		return -ENOMEM;

	e = idt_pte[pte_index(va)];
	flags = e & PTE_FLAGS_MASK;
	flags &= ~_PAGE_GLOBAL;
	idt_pte[pte_index(va)] = pa | flags;

	return 0;
}

static bool set_idt_global(bool set)
{
	unsigned long va = CPU_ENTRY_AREA_RO_IDT;
	pgd_t *pgd = current->active_mm->pgd;
	pgd_t *pgdp;
	p4d_t *p4dp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep;
	unsigned long v, old;

	pgdp = pgd + pgd_index(va);
	p4dp = p4d_offset(pgdp, va);
	pudp = pud_offset(p4dp, va);
	pmdp = pmd_offset(pudp, va);
	ptep = pte_offset_kernel(pmdp, va);

	old = pte_val(*ptep);
	v = old;
	if (set)
		v |= _PAGE_GLOBAL;
	else
		v &= ~_PAGE_GLOBAL;

	if (v != old) {
		set_pte(ptep, __pte(v));
		pvm_flush_tlb_all();
	}

	return old & _PAGE_GLOBAL;
}

static int __init switcher_setup_idt_table(void)
{
	gate_desc *e;
	unsigned long addr;
	int i;

	for (i = 0; i < NR_VECTORS; i++) {
		addr = (unsigned long)(void *)pvm_entries_start + PVM_IDT_ALIGN * i;
		e = &switcher_idt_table[i];
		if (e->bits.ist == IST_INDEX_DF + 1) {
			if (WARN_ON(i != X86_TRAP_DF))
				return -EINVAL;
			addr = (unsigned long)(void *)switcher_double_fault;
		}
		if (e->bits.ist == IST_INDEX_NMI + 1) {
			if (WARN_ON(i != X86_TRAP_NMI))
				return -EINVAL;
			addr = (unsigned long)(void *)switcher_nmi;
		}
		if (e->bits.ist == IST_INDEX_DB + 1) {
			if (WARN_ON(i != X86_TRAP_DB))
				return -EINVAL;
			addr = (unsigned long)(void *)switcher_debug;
		}
		if (e->bits.ist == IST_INDEX_MCE + 1) {
			if (WARN_ON(i != X86_TRAP_MC))
				return -EINVAL;
			addr = (unsigned long)(void *)switcher_mce;
		}
		if (WARN_ON((i >= 32) && (i != IA32_SYSCALL_VECTOR) && e->bits.dpl))
			return -EINVAL;

		e->offset_low		= (u16) addr;
		e->offset_middle	= (u16) (addr >> 16);
		e->offset_high		= (u32) (addr >> 32);
	}

	return 0;
}

static int __init oot_switcher_init(void)
{
	struct desc_ptr dt;
	gate_desc *idt_base;
	int i, cpu, r;

	store_idt(&dt);
	idt_base = (gate_desc *)dt.address;

	for (i = 0; i < NR_VECTORS; i++)
		pvm_host_idt_entries[i] = gate_offset(idt_base + i);

	for_each_possible_cpu(cpu) {
		struct tss_extra *tss_ex = per_cpu_tss_extra(cpu);

		tss_ex->host_gs_base = cpu_kernelmode_gs_base(cpu);
	}

	memcpy(switcher_idt_table, idt_base, sizeof(switcher_idt_table));
	r = switcher_setup_idt_table();
	if (r)
		return r;

	r = remap_idt(host_mmu_root_pgd, switcher_idt_table);
	if (r) {
		free_idt_page_table();
		return r;
	}

	idt_global_was_set = set_idt_global(false);
	idt_global_cleared = true;

	return 0;
}

static void oot_switcher_destroy(void)
{
	free_idt_page_table();

	if (idt_global_cleared) {
		set_idt_global(idt_global_was_set);
		idt_global_cleared = false;
	}
}

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

	return oot_switcher_init();
}

void host_mmu_destroy(void)
{
	oot_switcher_destroy();

	if (host_mmu_root_pgd)
		free_page((unsigned long)(void *)host_mmu_root_pgd);
	if (host_mmu_la57_top_p4d)
		free_page((unsigned long)(void *)host_mmu_la57_top_p4d);
	host_mmu_root_pgd = NULL;
	host_mmu_la57_top_p4d = NULL;
}
