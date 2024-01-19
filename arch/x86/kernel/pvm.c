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
#include <linux/nospec.h>

#include <asm/cpufeature.h>
#include <asm/cpu_entry_area.h>
#include <asm/desc.h>
#include <asm/pvm_para.h>
#include <asm/setup.h>
#include <asm/traps.h>

DEFINE_PER_CPU_PAGE_ALIGNED(struct pvm_vcpu_struct, pvm_vcpu_struct);

unsigned long pvm_range_start __initdata;
unsigned long pvm_range_end __initdata;

static bool early_traps_setup __initdata;

static __always_inline long pvm_hypercall0(unsigned int nr)
{
	long ret;

	asm volatile("call pvm_hypercall"
		     : "=a"(ret)
		     : "a"(nr)
		     : "memory");
	return ret;
}

static __always_inline long pvm_hypercall1(unsigned int nr, unsigned long p1)
{
	long ret;

	asm volatile("call pvm_hypercall"
		     : "=a"(ret)
		     : "a"(nr), "b"(p1)
		     : "memory");
	return ret;
}

static __always_inline long pvm_hypercall2(unsigned int nr, unsigned long p1,
					   unsigned long p2)
{
	long ret;

	asm volatile("call pvm_hypercall"
		     : "=a"(ret)
		     : "a"(nr), "b"(p1), "c"(p2)
		     : "memory");
	return ret;
}

static __always_inline long pvm_hypercall3(unsigned int nr, unsigned long p1,
					   unsigned long p2, unsigned long p3)
{
	long ret;

	asm volatile("call pvm_hypercall"
		     : "=a"(ret)
		     : "a"(nr), "b"(p1), "c"(p2), "d"(p3)
		     : "memory");
	return ret;
}

void __init pvm_early_event(struct pt_regs *regs)
{
	int vector = regs->orig_ax >> 32;

	if (!early_traps_setup) {
		do_early_exception(regs, vector);
		return;
	}

	switch (vector) {
	case X86_TRAP_DB:
		exc_debug(regs);
		return;
	case X86_TRAP_BP:
		exc_int3(regs);
		return;
	case X86_TRAP_PF:
		exc_page_fault(regs, regs->orig_ax);
		return;
	default:
		do_early_exception(regs, vector);
		return;
	}
}

void __init pvm_setup_early_traps(void)
{
	early_traps_setup = true;
}

static noinstr void pvm_bad_event(struct pt_regs *regs, unsigned long vector,
				  unsigned long error_code)
{
	irqentry_state_t irq_state = irqentry_nmi_enter(regs);

	instrumentation_begin();

	/* Panic on events from a high stack level */
	if (!user_mode(regs)) {
		pr_emerg("PANIC: invalid or fatal PVM event;"
			 "vector %lu error 0x%lx at %04lx:%016lx\n",
			 vector, error_code, regs->cs, regs->ip);
		die("invalid or fatal PVM event", regs, error_code);
		panic("invalid or fatal PVM event");
	} else {
		unsigned long flags = oops_begin();
		int sig = SIGKILL;

		pr_alert("BUG: invalid or fatal FRED event;"
			 "vector %lu error 0x%lx at %04lx:%016lx\n",
			 vector, error_code, regs->cs, regs->ip);

		if (__die("Invalid or fatal FRED event", regs, error_code))
			sig = 0;

		oops_end(flags, regs, sig);
	}
	instrumentation_end();
	irqentry_nmi_exit(regs, irq_state);
}

DEFINE_IDTENTRY_RAW(pvm_exc_debug)
{
	/*
	 * There's no IST on PVM. but we still need to sipatch
	 * to the correct handler.
	 */
	if (user_mode(regs))
		noist_exc_debug(regs);
	else
		exc_debug(regs);
}

#ifdef CONFIG_X86_MCE
DEFINE_IDTENTRY_RAW(pvm_exc_machine_check)
{
	/*
	 * There's no IST on PVM, but we still need to dispatch
	 * to the correct handler.
	 */
	if (user_mode(regs))
		noist_exc_machine_check(regs);
	else
		exc_machine_check(regs);
}
#endif

static noinstr void pvm_exception(struct pt_regs *regs, unsigned long vector,
				  unsigned long error_code)
{
	/* Optimize for #PF. That's the only exception which matters performance wise */
	if (likely(vector == X86_TRAP_PF)) {
		exc_page_fault(regs, error_code);
		return;
	}

	switch (vector) {
	case X86_TRAP_DE: return exc_divide_error(regs);
	case X86_TRAP_DB: return pvm_exc_debug(regs);
	case X86_TRAP_NMI: return exc_nmi(regs);
	case X86_TRAP_BP: return exc_int3(regs);
	case X86_TRAP_OF: return exc_overflow(regs);
	case X86_TRAP_BR: return exc_bounds(regs);
	case X86_TRAP_UD: return exc_invalid_op(regs);
	case X86_TRAP_NM: return exc_device_not_available(regs);
	case X86_TRAP_DF: return exc_double_fault(regs, error_code);
	case X86_TRAP_TS: return exc_invalid_tss(regs, error_code);
	case X86_TRAP_NP: return exc_segment_not_present(regs, error_code);
	case X86_TRAP_SS: return exc_stack_segment(regs, error_code);
	case X86_TRAP_GP: return exc_general_protection(regs, error_code);
	case X86_TRAP_MF: return exc_coprocessor_error(regs);
	case X86_TRAP_AC: return exc_alignment_check(regs, error_code);
	case X86_TRAP_XF: return exc_simd_coprocessor_error(regs);
#ifdef CONFIG_X86_MCE
	case X86_TRAP_MC: return pvm_exc_machine_check(regs);
#endif
#ifdef CONFIG_X86_CET
	case X86_TRAP_CP: return exc_control_protection(regs, error_code);
#endif
	default: return pvm_bad_event(regs, vector, error_code);
	}
}

static noinstr void pvm_handle_INT80_compat(struct pt_regs *regs)
{
#ifdef CONFIG_IA32_EMULATION
	if (ia32_enabled()) {
		int80_emulation(regs);
		return;
	}
#endif
	exc_general_protection(regs, 0);
}

#define SYSVEC(_vector, _function) [_vector - FIRST_SYSTEM_VECTOR] = sysvec_##_function

#define pvm_handle_spurious_interrupt ((idtentry_t)(void *)spurious_interrupt)

static idtentry_t pvm_sysvec_table[NR_SYSTEM_VECTORS] __ro_after_init = {
	[0 ... NR_SYSTEM_VECTORS-1] = pvm_handle_spurious_interrupt,

	SYSVEC(ERROR_APIC_VECTOR,		error_interrupt),
	SYSVEC(SPURIOUS_APIC_VECTOR,		spurious_apic_interrupt),
	SYSVEC(LOCAL_TIMER_VECTOR,		apic_timer_interrupt),
	SYSVEC(X86_PLATFORM_IPI_VECTOR,		x86_platform_ipi),

#ifdef CONFIG_SMP
	SYSVEC(RESCHEDULE_VECTOR,		reschedule_ipi),
	SYSVEC(CALL_FUNCTION_SINGLE_VECTOR,	call_function_single),
	SYSVEC(CALL_FUNCTION_VECTOR,		call_function),
	SYSVEC(REBOOT_VECTOR,			reboot),
#endif
#ifdef CONFIG_X86_MCE_THRESHOLD
	SYSVEC(THRESHOLD_APIC_VECTOR,		threshold),
#endif
#ifdef CONFIG_X86_MCE_AMD
	SYSVEC(DEFERRED_ERROR_VECTOR,		deferred_error),
#endif
#ifdef CONFIG_X86_THERMAL_VECTOR
	SYSVEC(THERMAL_APIC_VECTOR,		thermal),
#endif
#ifdef CONFIG_IRQ_WORK
	SYSVEC(IRQ_WORK_VECTOR,			irq_work),
#endif
#ifdef CONFIG_HAVE_KVM
	SYSVEC(POSTED_INTR_VECTOR,		kvm_posted_intr_ipi),
	SYSVEC(POSTED_INTR_WAKEUP_VECTOR,	kvm_posted_intr_wakeup_ipi),
	SYSVEC(POSTED_INTR_NESTED_VECTOR,	kvm_posted_intr_nested_ipi),
#endif
};

void __init pvm_install_sysvec(unsigned int sysvec, idtentry_t handler)
{
	if (WARN_ON_ONCE(sysvec < FIRST_SYSTEM_VECTOR))
		return;
	if (!WARN_ON_ONCE(pvm_sysvec_table[sysvec - FIRST_SYSTEM_VECTOR] !=
			  pvm_handle_spurious_interrupt))
		pvm_sysvec_table[sysvec - FIRST_SYSTEM_VECTOR] = handler;
}

/*
 * some pointers in pvm_sysvec_table are actual spurious_interrupt() who
 * expects the second argument to be the vector.
 */
typedef void (*idtentry_x_t)(struct pt_regs *regs, int vector);

static __always_inline void pvm_handle_sysvec(struct pt_regs *regs, unsigned long vector)
{
	unsigned int index = array_index_nospec(vector - FIRST_SYSTEM_VECTOR,
						NR_SYSTEM_VECTORS);
	idtentry_x_t func = (void *)pvm_sysvec_table[index];

	func(regs, vector);
}

__visible noinstr void pvm_event(struct pt_regs *regs)
{
	u32 error_code = regs->orig_ax;
	u64 vector = regs->orig_ax >> 32;

	/* Invalidate orig_ax so that syscall_get_nr() works correctly */
	regs->orig_ax = -1;

	if (vector < NUM_EXCEPTION_VECTORS)
		pvm_exception(regs, vector, error_code);
	else if (vector >= FIRST_SYSTEM_VECTOR)
		pvm_handle_sysvec(regs, vector);
	else if (unlikely(vector == IA32_SYSCALL_VECTOR))
		pvm_handle_INT80_compat(regs);
	else
		common_interrupt(regs, vector);
}

extern void pvm_early_kernel_event_entry(void);

/*
 * Reserve a fixed-size area in the current stack during an event from
 * supervisor mode. This is for the int3 handler to emulate a call instruction.
 */
#define PVM_SUPERVISOR_REDZONE_SIZE	(2*8UL)

void __init pvm_early_setup(void)
{
	if (!pvm_range_end)
		return;

	setup_force_cpu_cap(X86_FEATURE_KVM_PVM_GUEST);

	wrmsrl(MSR_PVM_VCPU_STRUCT, __pa(this_cpu_ptr(&pvm_vcpu_struct)));
	wrmsrl(MSR_PVM_EVENT_ENTRY, (unsigned long)(void *)pvm_early_kernel_event_entry - 256);
	wrmsrl(MSR_PVM_SUPERVISOR_REDZONE, PVM_SUPERVISOR_REDZONE_SIZE);
	wrmsrl(MSR_PVM_RETS_RIP, (unsigned long)(void *)pvm_rets_rip);
}

void pvm_setup_event_handling(void)
{
	if (boot_cpu_has(X86_FEATURE_KVM_PVM_GUEST)) {
		u64 xpa = slow_virt_to_phys(this_cpu_ptr(&pvm_vcpu_struct));

		wrmsrl(MSR_PVM_VCPU_STRUCT, xpa);
		wrmsrl(MSR_PVM_EVENT_ENTRY, (unsigned long)(void *)pvm_user_event_entry);
		wrmsrl(MSR_PVM_SUPERVISOR_REDZONE, PVM_SUPERVISOR_REDZONE_SIZE);
		wrmsrl(MSR_PVM_RETU_RIP, (unsigned long)(void *)pvm_retu_rip);
		wrmsrl(MSR_PVM_RETS_RIP, (unsigned long)(void *)pvm_rets_rip);

		/*
		 * PVM spec requires the hypervisor-maintained
		 * MSR_KERNEL_GS_BASE to be the same as the kernel GSBASE for
		 * event delivery for user mode. wrmsrl(MSR_KERNEL_GS_BASE)
		 * accesses only the user GSBASE in the PVCS via
		 * pvm_write_msr() without hypervisor involved, so use
		 * PVM_HC_WRMSR instead.
		 */
		pvm_hypercall2(PVM_HC_WRMSR, MSR_KERNEL_GS_BASE,
			       cpu_kernelmode_gs_base(smp_processor_id()));
	}
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
