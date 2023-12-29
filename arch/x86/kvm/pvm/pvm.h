/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_PVM_H
#define __KVM_X86_PVM_H

#include <linux/kvm_host.h>

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
