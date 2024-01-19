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
#define HOLE_SIZE	(1UL << 39)

#define PVM_DIRECT_MAPPING_SIZE		(8UL << TB_SHIFT)
#define PVM_VMALLOC_SIZE		(5UL << TB_SHIFT)
#define PVM_VMEM_MAPPING_SIZE		(1UL << TB_SHIFT)

/*
 * For a PVM guest, the hypervisor would provide one valid virtual address
 * range for the guest kernel. The guest kernel needs to adjust its layout,
 * including the direct mapping area, vmalloc area, vmemmap area, and CPU entry
 * area, to be within this range. If the range start is 0xffffd90000000000, the
 * PVM guest kernel with 4-level page tables could arrange its layout as
 * follows:
 *
 * ffff800000000000 - ffff87ffffffffff (=43 bits) guard hole, reserved for hypervisor
 * ... host kernel used ...  guest kernel range start
 * ffffd90000000000 - ffffe0ffffffffff (=8 TB) directing mapping of all physical memory
 * ffffe10000000000 - ffffe17fffffffff (=39 bit) hole
 * ffffe18000000000 - ffffe67fffffffff (=5 TB) vmalloc/ioremap space
 * ffffe68000000000 - ffffe6ffffffffff (=39 bit) hole
 * ffffe70000000000 - ffffe7ffffffffff (=40 bit) virtual memory map (1TB)
 * ffffe80000000000 - ffffe87fffffffff (=39 bit) cpu_entry_area mapping
 * ffffe88000000000 - ffffe8ff7fffffff (=510 G) hole
 * ffffe8ff80000000 - ffffe8ffffffffff (=2 G) kernel image
 * ... host kernel used ... guest kernel range end
 *
 */
bool __init pvm_kernel_layout_relocate(void)
{
	unsigned long area_size;

	if (!boot_cpu_has(X86_FEATURE_KVM_PVM_GUEST)) {
		vmemory_end = VMALLOC_START + (VMALLOC_SIZE_TB << 40) - 1;
		return false;
	}

	if (!IS_ALIGNED(pvm_range_start, PGDIR_SIZE))
		panic("The start of the allowed range is not aligned");

	area_size = max_pfn << PAGE_SHIFT;
	if (area_size > PVM_DIRECT_MAPPING_SIZE)
		panic("The memory size is too large for directing mapping area");

	vmalloc_base = page_offset_base + PVM_DIRECT_MAPPING_SIZE + HOLE_SIZE;
	vmemory_end = vmalloc_base + PVM_VMALLOC_SIZE;

	vmemmap_base = vmemory_end + HOLE_SIZE;
	area_size = max_pfn * sizeof(struct page);
	if (area_size > PVM_VMEM_MAPPING_SIZE)
		panic("The memory size is too large for virtual memory mapping area");

	cpu_entry_area_base = vmemmap_base + PVM_VMEM_MAPPING_SIZE;
	BUILD_BUG_ON(CPU_ENTRY_AREA_MAP_SIZE > (1UL << 39));

	if (cpu_entry_area_base + (2UL << 39) > pvm_range_end)
		panic("The size of the allowed range is too small");

	return true;
}
