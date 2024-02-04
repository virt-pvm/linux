/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_PVM_H
#define __KVM_X86_PVM_H

#include <linux/kvm_host.h>
#include <asm/switcher.h>

#define SWITCH_FLAGS_INIT	(SWITCH_FLAGS_SMOD)

#define PVM_FAILED_VMENTRY_VECTOR	SWITCH_EXIT_REASONS_FAILED_VMETNRY

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

struct vcpu_pvm {
	struct kvm_vcpu vcpu;

	// guest rflags, turned into hw rflags when in switcher
	unsigned long rflags;

	unsigned long switch_flags;

	u16 host_ds_sel, host_es_sel;

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
	bool nmi_mask;

	struct gfn_to_pfn_cache pvcs_gpc;

	// emulated x86 msrs
	u64 msr_lstar;
	u64 msr_syscall_mask;
	u64 msr_star;
	u64 unused_MSR_CSTAR;
	u64 unused_MSR_IA32_SYSENTER_CS;
	u64 unused_MSR_IA32_SYSENTER_EIP;
	u64 unused_MSR_IA32_SYSENTER_ESP;
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
	unsigned long msr_supervisor_rsp;
	unsigned long msr_supervisor_redzone;
	unsigned long msr_event_entry;
	unsigned long msr_retu_rip_plus2;
	unsigned long msr_rets_rip_plus2;
	unsigned long msr_switch_cr3;
	unsigned long msr_linear_address_range;

	struct kvm_segment segments[NR_VCPU_SREG];
	struct desc_ptr idt_ptr;
	struct desc_ptr gdt_ptr;
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
