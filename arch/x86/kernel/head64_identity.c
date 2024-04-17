// SPDX-License-Identifier: GPL-2.0
/*
 *  prepare to run common code
 *
 *  Copyright (C) 2000 Andrea Arcangeli <andrea@suse.de> SuSE
 */

#define DISABLE_BRANCH_PROFILING

/* cpu_feature_enabled() cannot be used this early */
#define USE_EARLY_PGTABLE_L5

#include <linux/linkage.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/pgtable.h>

#include <asm/desc.h>
#include <asm/sections.h>
#include <asm/trapnr.h>
#include <asm/sev.h>
#include <asm/init.h>
#include <asm/pvm_para.h>

extern pmd_t early_dynamic_pgts[EARLY_DYNAMIC_PAGE_TABLES][PTRS_PER_PMD];
extern unsigned int next_early_pgt;
extern gate_desc bringup_idt_table[NUM_EXCEPTION_VECTORS];
extern struct desc_ptr bringup_idt_descr;

/*
 * GDT used on the boot CPU before switching to virtual addresses.
 */
static struct desc_struct startup_gdt[GDT_ENTRIES] __initdata = {
	[GDT_ENTRY_KERNEL32_CS]         = GDT_ENTRY_INIT(0xc09b, 0, 0xfffff),
	[GDT_ENTRY_KERNEL_CS]           = GDT_ENTRY_INIT(0xa09b, 0, 0xfffff),
	[GDT_ENTRY_KERNEL_DS]           = GDT_ENTRY_INIT(0xc093, 0, 0xfffff),
};

/*
 * Address needs to be set at runtime because it references the startup_gdt
 * while the kernel still uses a direct mapping.
 */
static struct desc_ptr startup_gdt_descr __initdata = {
	.size = sizeof(startup_gdt)-1,
	.address = 0,
};

#ifdef CONFIG_X86_5LEVEL
static bool __head check_la57_support(void)
{
	if (__pgtable_l5_enabled)
		return true;

	/*
	 * 5-level paging is detected and enabled at kernel decompression
	 * stage. Only check if it has been enabled there.
	 */
	if (!(native_read_cr4() & X86_CR4_LA57))
		return false;

	__pgtable_l5_enabled = 1;
	pgdir_shift = 48;
	ptrs_per_p4d = 512;
	page_offset_base = __PAGE_OFFSET_BASE_L5;
	vmalloc_base = __VMALLOC_BASE_L5;
	vmemmap_base = __VMEMMAP_BASE_L5;

	return true;
}
#else
static bool __head check_la57_support(void)
{
	return false;
}
#endif

#ifdef CONFIG_X86_PIE
static void __head set_kernel_map_base(unsigned long text_base)
{
	kernel_map_base = text_base & PUD_MASK;
}
#else
static void __head set_kernel_map_base(unsigned long text_base)
{
}
#endif

static unsigned long __head sme_postprocess_startup(struct boot_params *bp, pmdval_t *pmd)
{
	unsigned long vaddr, vaddr_end;
	int i;

	/* Encrypt the kernel and related (if SME is active) */
	sme_encrypt_kernel(bp);

	/*
	 * Clear the memory encryption mask from the .bss..decrypted section.
	 * The bss section will be memset to zero later in the initialization so
	 * there is no need to zero it after changing the memory encryption
	 * attribute.
	 */
	if (sme_get_me_mask()) {
		vaddr = SYM_ABS_VA(__start_bss_decrypted);
		vaddr_end = SYM_ABS_VA(__end_bss_decrypted);

		for (; vaddr < vaddr_end; vaddr += PMD_SIZE) {
			/*
			 * On SNP, transition the page to shared in the RMP table so that
			 * it is consistent with the page table attribute change.
			 *
			 * __start_bss_decrypted has a virtual address in the high range
			 * mapping (kernel .text). PVALIDATE, by way of
			 * early_snp_set_memory_shared(), requires a valid virtual
			 * address but the kernel is currently running off of the identity
			 * mapping so use __pa() to get a *currently* valid virtual address.
			 */
			early_snp_set_memory_shared(__pa(vaddr), __pa(vaddr), PTRS_PER_PMD);

			i = pmd_index(vaddr);
			pmd[i] -= sme_get_me_mask();
		}
	}

	/*
	 * Return the SME encryption mask (if SME is active) to be used as a
	 * modifier for the initial pgdir entry programmed into CR3.
	 */
	return sme_get_me_mask();
}

unsigned long __head __startup_64(unsigned long physaddr,
				  struct boot_params *bp)
{
	unsigned long load_delta, *p;
	unsigned long pgtable_flags;
	unsigned long text_base = SYM_ABS_VA(_text);
	unsigned long kernel_map_base_offset;
	pgdval_t *pgd;
	p4dval_t *p4d;
	pudval_t *pud;
	pmdval_t *pmd, pmd_entry;
	bool la57;
	int i;

	la57 = check_la57_support();

	/* Is the address too large? */
	if (physaddr >> MAX_PHYSMEM_BITS)
		for (;;);

	/*
	 * Compute the delta between the address I am compiled to run at
	 * and the address I am actually running at.
	 */
	load_delta = physaddr - (text_base - __START_KERNEL_map);

	/* Is the address not 2M aligned? */
	if (load_delta & ~PMD_MASK)
		for (;;);

	/* Include the SME encryption mask in the fixup value */
	load_delta += sme_get_me_mask();

	/* Fixup the physical addresses in the page table */

	pgd = (pgdval_t *)early_top_pgt;
	p = pgd + pgd_index(text_base);
	if (la57)
		*p = (unsigned long)level4_kernel_pgt;
	else
		*p = (unsigned long)level3_kernel_pgt;
	*p += _PAGE_TABLE_NOENC + sme_get_me_mask();

	if (la57) {
		p4d = (p4dval_t *)level4_kernel_pgt;
		p4d[511] += load_delta;
		if (IS_ENABLED(CONFIG_X86_PIE)) {
			i = p4d_index(text_base);

			if (i != 511) {
				p4d[i] = p4d[511];
				p4d[511] = 0;
			}
		}
	}

	level3_kernel_pgt[510].pud += load_delta;
	level3_kernel_pgt[511].pud += load_delta;
	if (IS_ENABLED(CONFIG_X86_PIE)) {
		i = pud_index(text_base);

		if (i != 510) {
			level3_kernel_pgt[i].pud = level3_kernel_pgt[510].pud;
			level3_kernel_pgt[i + 1].pud = level3_kernel_pgt[511].pud;
			level3_kernel_pgt[510].pud = 0;
			level3_kernel_pgt[511].pud = 0;
		}
	}

	set_kernel_map_base(text_base);
	kernel_map_base_offset = KERNEL_MAP_BASE - __START_KERNEL_map;
	__FIXADDR_TOP += kernel_map_base_offset;

	for (i = FIXMAP_PMD_TOP; i > FIXMAP_PMD_TOP - FIXMAP_PMD_NUM; i--)
		level2_fixmap_pgt[i].pmd += load_delta;

	/*
	 * Set up the identity mapping for the switchover.  These
	 * entries should *NOT* have the global bit set!  This also
	 * creates a bunch of nonsense entries but that is fine --
	 * it avoids problems around wraparound.
	 */

	pud = (pudval_t *)early_dynamic_pgts[next_early_pgt++];
	pmd = (pmdval_t *)early_dynamic_pgts[next_early_pgt++];

	pgtable_flags = _KERNPG_TABLE_NOENC + sme_get_me_mask();

	if (la57) {
		p4d = (p4dval_t *)early_dynamic_pgts[next_early_pgt++];

		i = (physaddr >> PGDIR_SHIFT) % PTRS_PER_PGD;
		pgd[i + 0] = (pgdval_t)p4d + pgtable_flags;
		pgd[i + 1] = (pgdval_t)p4d + pgtable_flags;

		i = physaddr >> P4D_SHIFT;
		p4d[(i + 0) % PTRS_PER_P4D] = (pgdval_t)pud + pgtable_flags;
		p4d[(i + 1) % PTRS_PER_P4D] = (pgdval_t)pud + pgtable_flags;
	} else {
		i = (physaddr >> PGDIR_SHIFT) % PTRS_PER_PGD;
		pgd[i + 0] = (pgdval_t)pud + pgtable_flags;
		pgd[i + 1] = (pgdval_t)pud + pgtable_flags;
	}

	i = physaddr >> PUD_SHIFT;
	pud[(i + 0) % PTRS_PER_PUD] = (pudval_t)pmd + pgtable_flags;
	pud[(i + 1) % PTRS_PER_PUD] = (pudval_t)pmd + pgtable_flags;

	pmd_entry = __PAGE_KERNEL_LARGE_EXEC & ~_PAGE_GLOBAL;
	/* Filter out unsupported __PAGE_KERNEL_* bits: */
	pmd_entry &= __supported_pte_mask;
	pmd_entry += sme_get_me_mask();
	pmd_entry +=  physaddr;

	for (i = 0; i < DIV_ROUND_UP(_end - _text, PMD_SIZE); i++) {
		int idx = i + (physaddr >> PMD_SHIFT);

		pmd[idx % PTRS_PER_PMD] = pmd_entry + i * PMD_SIZE;
	}

	/*
	 * Fixup the kernel text+data virtual addresses. Note that
	 * we might write invalid pmds, when the kernel is relocated
	 * cleanup_highmap() fixes this up along with the mappings
	 * beyond _end.
	 *
	 * Only the region occupied by the kernel image has so far
	 * been checked against the table of usable memory regions
	 * provided by the firmware, so invalidate pages outside that
	 * region. A page table entry that maps to a reserved area of
	 * memory would allow processor speculation into that area,
	 * and on some hardware (particularly the UV platform) even
	 * speculative access to some reserved areas is caught as an
	 * error, causing the BIOS to halt the system.
	 */
	pmd = (pmdval_t *)level2_kernel_pgt;

	/* invalidate pages before the kernel image */
	for (i = 0; i < pmd_index(text_base); i++)
		pmd[i] &= ~_PAGE_PRESENT;

	/* fixup pages that are part of the kernel image */
	for (; i <= pmd_index(SYM_ABS_VA(_end)); i++)
		if (pmd[i] & _PAGE_PRESENT)
			pmd[i] += load_delta + kernel_map_base_offset;

	/* invalidate pages after the kernel image */
	for (; i < PTRS_PER_PMD; i++)
		pmd[i] &= ~_PAGE_PRESENT;

	/*
	 * Fixup phys_base - remove the memory encryption mask to obtain
	 * the true physical address.
	 */
	phys_base += load_delta + kernel_map_base_offset - sme_get_me_mask();

	return sme_postprocess_startup(bp, pmd);
}

/* This runs while still in the direct mapping */
static void __head startup_64_load_idt(void)
{
	/* VMM Communication Exception */
	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT))
		set_bringup_idt_handler(bringup_idt_table, X86_TRAP_VC, vc_no_ghcb);

	bringup_idt_descr.address = (unsigned long)bringup_idt_table;
	native_load_idt(&bringup_idt_descr);
}

/*
 * Setup boot CPU state needed before kernel switches to virtual addresses.
 */
void __head startup_64_setup_env(void)
{
	/* Load GDT */
	startup_gdt_descr.address = (unsigned long)startup_gdt;
	native_load_gdt(&startup_gdt_descr);

	/* New GDT is live - reload data segment registers */
	asm volatile("movl %%eax, %%ds\n"
		     "movl %%eax, %%ss\n"
		     "movl %%eax, %%es\n" : : "a"(__KERNEL_DS) : "memory");

	startup_64_load_idt();
}

#ifdef CONFIG_RELOCATABLE_UNCOMPRESSED_KERNEL
extern u8 __relocation_end[];

static bool __head is_in_pvh_pgtable(unsigned long ptr)
{
#ifdef CONFIG_PVH
	if (ptr >= (unsigned long)init_top_pgt &&
	    ptr < (unsigned long)init_top_pgt + PAGE_SIZE)
		return true;
	if (ptr >= (unsigned long)level3_ident_pgt &&
	    ptr < (unsigned long)level3_ident_pgt + PAGE_SIZE)
		return true;
#endif
	return false;
}

void __head __relocate_kernel(unsigned long physbase, unsigned long virtbase)
{
	int *reloc = (int *)__relocation_end;
	unsigned long ptr;
	unsigned long delta = virtbase - __START_KERNEL_map;
	unsigned long map = physbase - __START_KERNEL;
	long extended;

	/*
	 * Relocation had happended in bootloader,
	 * don't do it again.
	 */
	if (SYM_ABS_VA(_text) != __START_KERNEL)
		return;

	if (!delta)
		return;

	/*
	 * Format is:
	 *
	 * kernel bits...
	 * 0 - zero terminator for 64 bit relocations
	 * 64 bit relocation repeated
	 * 0 - zero terminator for inverse 32 bit relocations
	 * 32 bit inverse relocation repeated
	 * 0 - zero terminator for 32 bit relocations
	 * 32 bit relocation repeated
	 *
	 * So we work backwards from the end of .data.relocs section, see
	 * handle_relocations() in arch/x86/boot/compressed/misc.c.
	 */
	while (*--reloc) {
		extended = *reloc;
		ptr = (unsigned long)(extended + map);
		*(uint32_t *)ptr += delta;
	}

	while (*--reloc) {
		extended = *reloc;
		ptr = (unsigned long)(extended + map);
		*(int32_t *)ptr -= delta;
	}

	while (*--reloc) {
		extended = *reloc;
		ptr = (unsigned long)(extended + map);
		if (is_in_pvh_pgtable(ptr))
			continue;
		*(uint64_t *)ptr += delta;
	}
}
#endif

#ifdef CONFIG_PVM_GUEST
extern unsigned long pvm_range_start;
extern unsigned long pvm_range_end;

static void __head detect_pvm_range(void)
{
	unsigned long msr_val;
	unsigned long index_start, index_end;

	msr_val = __rdmsr(MSR_PVM_LINEAR_ADDRESS_RANGE);

	if (check_la57_support()) {
		index_start = (msr_val >> 32) & 0x1ff;
		index_end = (msr_val >> 48) & 0x1ff;
		pvm_range_start = (0xfe00 | index_start) * PGDIR_SIZE;
		pvm_range_end = (0xfe00 | index_end) * PGDIR_SIZE;
	} else {
		index_start = msr_val & 0x1ff;
		index_end = (msr_val >> 16) & 0x1ff;
		pvm_range_start = (0x1fffe00 | index_start) * P4D_SIZE;
		pvm_range_end = (0x1fffe00 | index_end) * P4D_SIZE;

		/*
		 * If the host is in 5-level paging mode and the guest is in
		 * 4-level paging mode, clear the L5 range for migration.
		 */
		if (((msr_val >> 32) & 0x1ff) != 0x1ff)
			msr_val |= (0x1ffUL << 32) | (0x1ffUL << 48);
	}
	native_wrmsrl(MSR_PVM_LINEAR_ADDRESS_RANGE, msr_val);

	/*
	 * early page fault would map page into directing mapping area,
	 * so we should modify 'page_offset_base' here early.
	 */
	page_offset_base = pvm_range_start;
}

void __head pvm_relocate_kernel(unsigned long physbase)
{
	if (!pvm_detect())
		return;

	detect_pvm_range();
	__relocate_kernel(physbase, pvm_range_end - (2UL << 30));
}
#endif
