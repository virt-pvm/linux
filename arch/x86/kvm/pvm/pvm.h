/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_PVM_H
#define __KVM_X86_PVM_H

#include <linux/kvm_host.h>
#include <asm/switcher.h>

/*
 * Extra switch flags:
 *
 * IRQ_WIN:
 *	There is an irq window request, and the vcpu should not directly
 *	switch to context with IRQ enabled, e.g. user mode.
 * SINGLE_STEP:
 *	KVM_GUESTDBG_SINGLESTEP is set.
 * PVCS_INVALID:
 *	The GPC of PVCS is invalid and khva is NULL.
 */
#define SWITCH_FLAGS_IRQ_WIN				_BITULL(8)
#define SWITCH_FLAGS_SINGLE_STEP			_BITULL(9)
#define SWITCH_FLAGS_PVCS_INVALID			_BITULL(10)

#define SWITCH_FLAGS_INIT	(SWITCH_FLAGS_SMOD | SWITCH_FLAGS_PVCS_INVALID)

#define PVM_SYSCALL_VECTOR		SWITCH_EXIT_REASONS_SYSCALL
#define PVM_FAILED_VMENTRY_VECTOR	SWITCH_EXIT_REASONS_FAILED_VMETNRY

#define PVM_EXIT_REASONS_SHIFT		16
#define PVM_EXIT_REASONS_SYSCALL	(1UL << PVM_EXIT_REASONS_SHIFT)
#define PVM_EXIT_REASONS_HYPERCALL	(2UL << PVM_EXIT_REASONS_SHIFT)
#define PVM_EXIT_REASONS_ERETU		(3UL << PVM_EXIT_REASONS_SHIFT)
#define PVM_EXIT_REASONS_INTERRUPT	(4UL << PVM_EXIT_REASONS_SHIFT)
#define PVM_EXIT_REASONS_INT80		(5UL << PVM_EXIT_REASONS_SHIFT)

#define PVM_EXIT_REASONS		\
	{ DE_VECTOR, "DE excp" },	\
	{ DB_VECTOR, "DB excp" },	\
	{ NMI_VECTOR, "NMI excp" },	\
	{ BP_VECTOR, "BP excp" },	\
	{ OF_VECTOR, "OF excp" },	\
	{ BR_VECTOR, "BR excp" },	\
	{ UD_VECTOR, "UD excp" },	\
	{ NM_VECTOR, "NM excp" },	\
	{ DF_VECTOR, "DF excp" },	\
	{ TS_VECTOR, "TS excp" },	\
	{ SS_VECTOR, "SS excp" },	\
	{ GP_VECTOR, "GP excp" },	\
	{ PF_VECTOR, "PF excp" },	\
	{ MF_VECTOR, "MF excp" },	\
	{ AC_VECTOR, "AC excp" },	\
	{ MC_VECTOR, "MC excp" },	\
	{ XM_VECTOR, "XM excp" },	\
	{ VE_VECTOR, "VE excp" },	\
	{ PVM_EXIT_REASONS_SYSCALL, "SYSCALL" },	\
	{ PVM_EXIT_REASONS_HYPERCALL, "HYPERCALL" },	\
	{ PVM_EXIT_REASONS_ERETU, "ERETU" },		\
	{ PVM_EXIT_REASONS_INTERRUPT, "INTERRUPT" },	\
	{ PVM_EXIT_REASONS_INT80, "INT80" },		\
	{ PVM_FAILED_VMENTRY_VECTOR, "FAILED_VMENTRY" }

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

#define PVM_ASID_SHIFT			3
#define NUM_PVM_GUEST_PCID_INDEX	(1U << PVM_ASID_SHIFT)
#define PVM_GUEST_PTI_PCID_BIT		11
#define PVM_GUEST_PTI_PCID_MASK		(1U << PVM_GUEST_PTI_PCID_BIT)
#define PVM_GUEST_PCID_INDEX_MASK	(NUM_PVM_GUEST_PCID_INDEX - 1)
#define PVM_GUEST_PCID_MASK		(PVM_GUEST_PCID_INDEX_MASK | PVM_GUEST_PTI_PCID_MASK)

#define PVM_ASID_MIN			1
#define PVM_ASID_MAX			(((1U << PVM_GUEST_PTI_PCID_BIT) - 1) / NUM_PVM_GUEST_PCID_INDEX)
#define PVM_ASID_GEN_RESERVED		0
#define PVM_ASID_GEN_INIT		1

struct vcpu_pvm {
	struct kvm_vcpu vcpu;

	// guest rflags, turned into hw rflags when in switcher
	unsigned long rflags;

	unsigned long switch_flags;

	u16 host_ds_sel, host_es_sel;
	u64 host_debugctlmsr;

	union {
		unsigned long exit_extra;
		unsigned long exit_cr2;
		unsigned long exit_dr6;
		struct ve_info exit_ve;
	};
	u32 exit_vector;
	u32 exit_error_code;
	u32 hw_cs, hw_ss;

	int loaded_cpu_state;
	int int_shadow;
	bool non_pvm_mode;
	bool nmi_mask;

	unsigned long guest_dr7;

	struct gfn_to_pfn_cache pvcs_gpc;

	bool flush_hwtlb_current;
	u32 asid;
	u64 asid_generation;

	// emulated x86 msrs
	u64 msr_lstar;
	u64 msr_syscall_mask;
	u64 msr_star;
	u64 unused_MSR_CSTAR;
	u64 unused_MSR_IA32_SYSENTER_CS;
	u64 unused_MSR_IA32_SYSENTER_EIP;
	u64 unused_MSR_IA32_SYSENTER_ESP;
	u64 unused_MSR_IA32_BNDCFGS;
	u64 msr_kernel_gs_base;
	u64 msr_tsc_aux;
	/*
	 * Only bits masked by msr_ia32_feature_control_valid_bits can be set in
	 * msr_ia32_feature_control. FEAT_CTL_LOCKED is always included
	 * in msr_ia32_feature_control_valid_bits.
	 */
	u64 msr_ia32_feature_control;
	u64 msr_ia32_feature_control_valid_bits;

	// PVM paravirt MSRs
	unsigned long msr_vcpu_struct;
	unsigned long msr_event_entry;
	unsigned long msr_retu_rip_plus2;
	unsigned long msr_linear_address_range;

	u64 l4_range_start;
	u64 l4_range_end;
	u64 l5_range_start;
	u64 l5_range_end;

	struct kvm_segment segments[NR_VCPU_SREG];
	struct desc_ptr idt_ptr;
	struct desc_ptr gdt_ptr;
	struct desc_struct tls_array[GDT_ENTRY_TLS_ENTRIES];
};

struct kvm_pvm {
	struct kvm kvm;
};

static __always_inline struct kvm_pvm *to_kvm_pvm(struct kvm *kvm)
{
	return container_of(kvm, struct kvm_pvm, kvm);
}

static __always_inline struct vcpu_pvm *to_pvm(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct vcpu_pvm, vcpu);
}

#endif /* __KVM_X86_PVM_H */
