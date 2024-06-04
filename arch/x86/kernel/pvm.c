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
static DEFINE_PER_CPU(unsigned long, pvm_guest_cr3);

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

static void pvm_load_gs_index(unsigned int sel)
{
	if (sel & 4) {
		pr_warn_once("pvm guest doesn't support LDT");
		this_cpu_write(pvm_vcpu_struct.user_gsbase, 0);
	} else {
		unsigned long base;

		preempt_disable();
		base = pvm_hypercall1(PVM_HC_LOAD_GS, sel);
		__this_cpu_write(pvm_vcpu_struct.user_gsbase, base);
		preempt_enable();
	}
}

static unsigned long long pvm_read_msr_safe(unsigned int msr, int *err)
{
	switch (msr) {
	case MSR_FS_BASE:
		*err = 0;
		return rdfsbase();
	case MSR_KERNEL_GS_BASE:
		*err = 0;
		return this_cpu_read(pvm_vcpu_struct.user_gsbase);
	default:
		return native_read_msr_safe(msr, err);
	}
}

static unsigned long long pvm_read_msr(unsigned int msr)
{
	switch (msr) {
	case MSR_FS_BASE:
		return rdfsbase();
	case MSR_KERNEL_GS_BASE:
		return this_cpu_read(pvm_vcpu_struct.user_gsbase);
	default:
		return pvm_hypercall1(PVM_HC_RDMSR, msr);
	}
}

static int notrace pvm_write_msr_safe(unsigned int msr, u32 low, u32 high)
{
	unsigned long base = ((u64)high << 32) | low;

	switch (msr) {
	case MSR_FS_BASE:
		wrfsbase(base);
		return 0;
	case MSR_KERNEL_GS_BASE:
		this_cpu_write(pvm_vcpu_struct.user_gsbase, base);
		return 0;
	default:
		return pvm_hypercall2(PVM_HC_WRMSR, msr, base);
	}
}

static void notrace pvm_write_msr(unsigned int msr, u32 low, u32 high)
{
	pvm_write_msr_safe(msr, low, high);
}

static void pvm_load_tls(struct thread_struct *t, unsigned int cpu)
{
	struct desc_struct *gdt = get_cpu_gdt_rw(cpu);
	unsigned long *tls_array = (unsigned long *)gdt;

	if (memcmp(&gdt[GDT_ENTRY_TLS_MIN], &t->tls_array[0], sizeof(t->tls_array))) {
		native_load_tls(t, cpu);
		pvm_hypercall3(PVM_HC_LOAD_TLS, tls_array[GDT_ENTRY_TLS_MIN],
			       tls_array[GDT_ENTRY_TLS_MIN + 1],
			       tls_array[GDT_ENTRY_TLS_MIN + 2]);
	}
}

static noinstr void pvm_safe_halt(void)
{
	pvm_hypercall0(PVM_HC_IRQ_HALT);
}

static noinstr unsigned long pvm_read_cr2(void)
{
	return this_cpu_read(pvm_vcpu_struct.cr2);
}

static noinstr void pvm_write_cr2(unsigned long cr2)
{
	native_write_cr2(cr2);
	this_cpu_write(pvm_vcpu_struct.cr2, cr2);
}

static unsigned long pvm_read_cr3(void)
{
	return this_cpu_read(pvm_guest_cr3);
}

static unsigned long pvm_user_pgd(unsigned long pgd)
{
	return pgd | BIT(PTI_PGTABLE_SWITCH_BIT) | BIT(X86_CR3_PTI_PCID_USER_BIT);
}

static void pvm_write_cr3(unsigned long val)
{
	/* Convert CR3_NO_FLUSH bit to hypercall flags. */
	unsigned long flags = ~val >> 63;
	unsigned long pgd = val & ~X86_CR3_PCID_NOFLUSH;

	if (pgtable_l5_enabled())
		flags |= PVM_LOAD_PGTBL_FLAGS_LA57;
	this_cpu_write(pvm_guest_cr3, pgd);
	pvm_hypercall3(PVM_HC_LOAD_PGTBL, flags, pgd, pvm_user_pgd(pgd));
}

static void pvm_flush_tlb_user(void)
{
	pvm_hypercall0(PVM_HC_TLB_FLUSH_CURRENT);
}

static void pvm_flush_tlb_kernel(void)
{
	pvm_hypercall0(PVM_HC_TLB_FLUSH);
}

static void pvm_flush_tlb_one_user(unsigned long addr)
{
	pvm_hypercall1(PVM_HC_TLB_INVLPG, addr);
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

asm (
	".pushsection .rodata				\n"
	".global pvm_cmpxchg16b_emu_template		\n"
	"pvm_cmpxchg16b_emu_template:			\n"
	"	cmpxchg16b %gs:(%rsi)			\n"
	"	ret					\n"
	".global pvm_cmpxchg16b_emu_tail		\n"
	"pvm_cmpxchg16b_emu_tail:			\n"
	".popsection					\n"
);

extern u8 this_cpu_cmpxchg16b_emu[];
extern u8 pvm_cmpxchg16b_emu_template[];
extern u8 pvm_cmpxchg16b_emu_tail[];

static void __init pvm_early_patch(void)
{
	/*
	 * The pushf/popf instructions in this_cpu_cmpxchg16b_emu() are
	 * non-privilege instructions, so they cannot be trapped and emulated,
	 * which could cause a boot failure. However, since the cmpxchg16b
	 * instruction is supported for PVM guest. we can patch
	 * this_cpu_cmpxchg16b_emu() and use cmpxchg16b directly.
	 */
	memcpy(this_cpu_cmpxchg16b_emu, pvm_cmpxchg16b_emu_template,
	       (unsigned int)(pvm_cmpxchg16b_emu_tail - pvm_cmpxchg16b_emu_template));
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
	setup_force_cpu_cap(X86_FEATURE_PV_GUEST);

	/* Don't use SYSENTER (Intel) and SYSCALL32 (AMD) in vdso. */
	setup_clear_cpu_cap(X86_FEATURE_SYSENTER32);
	setup_clear_cpu_cap(X86_FEATURE_SYSCALL32);

	/* PVM takes care of %gs when switching to usermode for us */
	pv_ops.cpu.load_gs_index = pvm_load_gs_index;
	pv_ops.cpu.cpuid = pvm_cpuid;

	pv_ops.cpu.read_msr = pvm_read_msr;
	pv_ops.cpu.write_msr = pvm_write_msr;
	pv_ops.cpu.read_msr_safe = pvm_read_msr_safe;
	pv_ops.cpu.write_msr_safe = pvm_write_msr_safe;
	pv_ops.cpu.load_tls = pvm_load_tls;

	pv_ops.irq.save_fl = __PV_IS_CALLEE_SAVE(pvm_save_fl);
	pv_ops.irq.irq_disable = __PV_IS_CALLEE_SAVE(pvm_irq_disable);
	pv_ops.irq.irq_enable = __PV_IS_CALLEE_SAVE(pvm_irq_enable);
	pv_ops.irq.safe_halt = pvm_safe_halt;

	this_cpu_write(pvm_guest_cr3, __native_read_cr3());
	pv_ops.mmu.read_cr2 = __PV_IS_CALLEE_SAVE(pvm_read_cr2);
	pv_ops.mmu.write_cr2 = pvm_write_cr2;
	pv_ops.mmu.read_cr3 = pvm_read_cr3;
	pv_ops.mmu.write_cr3 = pvm_write_cr3;
	pv_ops.mmu.flush_tlb_user = pvm_flush_tlb_user;
	pv_ops.mmu.flush_tlb_kernel = pvm_flush_tlb_kernel;
	pv_ops.mmu.flush_tlb_one_user = pvm_flush_tlb_one_user;

	wrmsrl(MSR_PVM_VCPU_STRUCT, __pa(this_cpu_ptr(&pvm_vcpu_struct)));
	wrmsrl(MSR_PVM_EVENT_ENTRY, (unsigned long)(void *)pvm_early_kernel_event_entry - 256);
	wrmsrl(MSR_PVM_SUPERVISOR_REDZONE, PVM_SUPERVISOR_REDZONE_SIZE);
	wrmsrl(MSR_PVM_RETS_RIP, (unsigned long)(void *)pvm_rets_rip);

	pvm_early_patch();
}

void __init pvm_switch_pvcs(int cpu)
{
	/*
	 * During the boot process, the boot CPU will switch GSBASE from the
	 * .init.data area to the runtime per-CPU area, so we need to switch
	 * the physical address of PVCS after that.
	 */
	if (boot_cpu_has(X86_FEATURE_KVM_PVM_GUEST) && !cpu) {
		u64 xpa = slow_virt_to_phys(this_cpu_ptr(&pvm_vcpu_struct));

		wrmsrl(MSR_PVM_VCPU_STRUCT, xpa);
	}
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
