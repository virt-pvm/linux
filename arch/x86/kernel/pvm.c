// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * KVM PVM paravirt_ops implementation
 *
 * Copyright (C) 2020 Ant Group
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */
#define pr_fmt(fmt) "pvm-guest: " fmt

#include <linux/mm_types.h>

#include <asm/cpufeature.h>
#include <asm/cpu_entry_area.h>
#include <asm/pvm_para.h>

unsigned long pvm_range_start __initdata;
unsigned long pvm_range_end __initdata;

void __init pvm_early_setup(void)
{
	if (!pvm_range_end)
		return;

	setup_force_cpu_cap(X86_FEATURE_KVM_PVM_GUEST);
}

#define TB_SHIFT	40
#define PB_SHIFT	50

#define HOLE_L4_SIZE	(1UL << 39)
#define HOLE_L5_SIZE	(1UL << 48)

#define PVM_DIRECT_MAPPING_L4_SIZE	(8UL << TB_SHIFT)
#define PVM_DIRECT_MAPPING_L5_SIZE	(4UL << PB_SHIFT)
#define PVM_VMALLOC_L4_SIZE		(5UL << TB_SHIFT)
#define PVM_VMALLOC_L5_SIZE		(3UL << PB_SHIFT)
#define PVM_VMEM_MAPPING_L4_SIZE	HOLE_L4_SIZE
#define PVM_VMEM_MAPPING_L5_SIZE	HOLE_L5_SIZE

#define PVM_CPU_ENTRY_AREA_MAP_SIZE	(1UL << 39)
#define PVM_IDENTICAL_AREA_SIZE		(1UL << 40)

/*
 * For a PVM guest, the hypervisor would provide one valid virtual address
 * range for the guest kernel. The guest kernel needs to adjust its layout,
 * including the direct mapping area, vmalloc area, vmemmap area, and CPU entry
 * area, to be within this range. If the range start is 0xffffd90000000000, the
 * PVM guest kernel with 4-level page tables could arrange its layout as
 * follows:
 *
 * ffff800000000000 - ffff87ffffffffff (=8 TB) guard hole, reserved for hypervisor
 * ... host kernel used ...  guest kernel range start
 * ffffd90000000000 - ffffe0ffffffffff (=8 TB) directing mapping of all physical memory
 * ffffe10000000000 - ffffe17fffffffff (=0.5 TB) hole
 * ffffe18000000000 - ffffe67fffffffff (=5 TB) vmalloc/ioremap space
 * ffffe68000000000 - ffffe6ffffffffff (=0.5 TB) hole
 * ffffe70000000000 - ffffe77fffffffff (=0.5 TB) virtual memory map
 * ffffe78000000000 - ffffe7ffffffffff (=0.5 TB) hole
 * ffffe80000000000 - ffffe87fffffffff (=0.5 TB) cpu_entry_area mapping
 * ffffe88000000000 - ffffe8ff7fffffff (=510 GB) hole
 * ffffe8ff80000000 - ffffe8ffffffffff (=2 GB) kernel image
 * ... host kernel used ... guest kernel range end
 *
 * If the range start is 0xff50000000000000, the PVM guest kernel with 5-level
 * page tables could arrange its layout as follows:
 *
 * ff00000000000000 - ff0fffffffffffff (=4 PB) guard hole, reserved for hypervisor
 * ... host kernel used ...  guest kernel range start
 * ff50000000000000 - ff5fffffffffffff (=4 PB) directing mapping of all physical memory
 * ff60000000000000 - ff60ffffffffffff (=0.25 PB) hole
 * ff61000000000000 - ff6cffffffffffff (=3 PB) vmalloc/ioremap space
 * ff6d000000000000 - ff6dffffffffffff (=0.25 PB) hole
 * ff6e000000000000 - ff6effffffffffff (=0.25 PB) virtual memory map
 * ff6f000000000000 - ff6ffeffffffffff (=255 TB) hole
 *
 * ... Identical layout to the 4-level page tables from here on ...
 * ff6fff0000000000 - ff6fff7fffffffff (=0.5 TB) cpu_entry_area mapping
 * ff6fff8000000000 - ff6fffff7fffffff (=510 GB) hole
 * ff6fffff80000000 - ff6fffffffffffff (=2 GB) kernel image
 * ... host kernel used ... guest kernel range end
 *
 */
bool __init pvm_kernel_layout_relocate(void)
{
	unsigned long area_size;
	unsigned long direct_mapping_size, vmalloc_size;
	unsigned long vmem_mapping_size, hole_size;

	if (!boot_cpu_has(X86_FEATURE_KVM_PVM_GUEST)) {
		vmemory_end = VMALLOC_START + (VMALLOC_SIZE_TB << TB_SHIFT) - 1;
		return false;
	}

	if (!IS_ALIGNED(pvm_range_start, PGDIR_SIZE))
		panic("The start of the allowed range is not aligned");

	if (pgtable_l5_enabled()) {
		direct_mapping_size = PVM_DIRECT_MAPPING_L5_SIZE;
		vmalloc_size = PVM_VMALLOC_L5_SIZE;
		vmem_mapping_size = PVM_VMEM_MAPPING_L5_SIZE;
		hole_size = HOLE_L5_SIZE;
	} else {
		direct_mapping_size = PVM_DIRECT_MAPPING_L4_SIZE;
		vmalloc_size = PVM_VMALLOC_L4_SIZE;
		vmem_mapping_size = PVM_VMEM_MAPPING_L4_SIZE;
		hole_size = HOLE_L4_SIZE;
	}

	area_size = max_pfn << PAGE_SHIFT;
	if (area_size > direct_mapping_size)
		panic("The memory size is too large for directing mapping area");
	physmem_end = direct_mapping_size;

	vmalloc_base = page_offset_base + direct_mapping_size + hole_size;
	vmemory_end = vmalloc_base + vmalloc_size;

	vmemmap_base = vmemory_end + hole_size;
	area_size = max_pfn * sizeof(struct page);
	if (area_size > vmem_mapping_size)
		panic("The memory size is too large for virtual memory mapping area");

	/*
	 * This ensures that the CPU entry area is in the same PGD as the
	 * kernel image area.
	 */
	cpu_entry_area_base = pvm_range_end - PVM_IDENTICAL_AREA_SIZE;
	BUILD_BUG_ON(CPU_ENTRY_AREA_MAP_SIZE > PVM_CPU_ENTRY_AREA_MAP_SIZE);
	if (cpu_entry_area_base < vmemmap_base + vmem_mapping_size)
		panic("The size of the allowed range is too small");

	return true;
}
