// SPDX-License-Identifier: GPL-2.0-only
/*
 * Pagetable-based Virtual Machine driver for Linux
 *
 * Copyright (C) 2020 Ant Group
 * Copyright (C) 2020 Alibaba Group
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>

#include <asm/pvm_para.h>

#include "cpuid.h"
#include "x86.h"
#include "pvm.h"

MODULE_AUTHOR("AntGroup");
MODULE_LICENSE("GPL");

static bool __read_mostly is_intel;

static unsigned long host_idt_base;

static void pvm_setup_mce(struct kvm_vcpu *vcpu)
{
}

static bool pvm_has_emulated_msr(struct kvm *kvm, u32 index)
{
	switch (index) {
	case MSR_IA32_MCG_EXT_CTL:
	case KVM_FIRST_EMULATED_VMX_MSR ... KVM_LAST_EMULATED_VMX_MSR:
		return false;
	case MSR_AMD64_VIRT_SPEC_CTRL:
	case MSR_AMD64_TSC_RATIO:
		/* This is AMD SVM only. */
		return false;
	case MSR_IA32_SMBASE:
		/* Currenlty we only run guest in long mode. */
		return false;
	default:
		break;
	}

	return true;
}

static bool cpu_has_pvm_wbinvd_exit(void)
{
	return true;
}

static void reset_segment(struct kvm_segment *var, int seg)
{
	memset(var, 0, sizeof(*var));
	var->limit = 0xffff;
	var->present = 1;

	switch (seg) {
	case VCPU_SREG_CS:
		var->s = 1;
		var->type = 0xb; /* Code Segment */
		var->selector = 0xf000;
		var->base = 0xffff0000;
		break;
	case VCPU_SREG_LDTR:
		var->s = 0;
		var->type = DESC_LDT;
		break;
	case VCPU_SREG_TR:
		var->s = 0;
		var->type = DESC_TSS | 0x2; // TSS32 busy
		break;
	default:
		var->s = 1;
		var->type = 3; /* Read/Write Data Segment */
		break;
	}
}

static void __pvm_vcpu_reset(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	if (is_intel)
		vcpu->arch.microcode_version = 0x100000000ULL;
	else
		vcpu->arch.microcode_version = 0x01000065;

	pvm->msr_ia32_feature_control_valid_bits = FEAT_CTL_LOCKED;
}

static void pvm_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	int i;

	kvm_gpc_deactivate(&pvm->pvcs_gpc);

	if (!init_event)
		__pvm_vcpu_reset(vcpu);

	/*
	 * For PVM, cpuid faulting relies on hardware capability, but it is set
	 * as supported by default in kvm_arch_vcpu_create(). Therefore, it
	 * should be cleared if the host doesn't support it.
	 */
	if (!boot_cpu_has(X86_FEATURE_CPUID_FAULT))
		vcpu->arch.msr_platform_info &= ~MSR_PLATFORM_INFO_CPUID_FAULT;

	// X86 resets
	for (i = 0; i < ARRAY_SIZE(pvm->segments); i++)
		reset_segment(&pvm->segments[i], i);
	kvm_set_cr8(vcpu, 0);
	pvm->idt_ptr.address = 0;
	pvm->idt_ptr.size = 0xffff;
	pvm->gdt_ptr.address = 0;
	pvm->gdt_ptr.size = 0xffff;

	// PVM resets
	pvm->switch_flags = SWITCH_FLAGS_INIT;
	pvm->hw_cs = __USER_CS;
	pvm->hw_ss = __USER_DS;
	pvm->int_shadow = 0;
	pvm->nmi_mask = false;

	pvm->msr_vcpu_struct = 0;
	pvm->msr_supervisor_rsp = 0;
	pvm->msr_event_entry = 0;
	pvm->msr_retu_rip_plus2 = 0;
	pvm->msr_rets_rip_plus2 = 0;
	pvm->msr_switch_cr3 = 0;
}

static int pvm_vcpu_create(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	BUILD_BUG_ON(offsetof(struct vcpu_pvm, vcpu) != 0);

	pvm->switch_flags = SWITCH_FLAGS_INIT;
	kvm_gpc_init(&pvm->pvcs_gpc, vcpu->kvm, vcpu, KVM_GUEST_AND_HOST_USE_PFN);

	return 0;
}

static void pvm_vcpu_free(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	kvm_gpc_deactivate(&pvm->pvcs_gpc);
}

static void pvm_vcpu_after_set_cpuid(struct kvm_vcpu *vcpu)
{
}

static int pvm_vm_init(struct kvm *kvm)
{
	kvm->arch.host_mmu_root_pgd = host_mmu_root_pgd;
	return 0;
}

static int hardware_enable(void)
{
	/* Nothing to do */
	return 0;
}

static void hardware_disable(void)
{
	/* Nothing to do */
}

static int pvm_check_processor_compat(void)
{
	/* Nothing to do */
	return 0;
}

static __init void pvm_set_cpu_caps(void)
{
	if (boot_cpu_has(X86_FEATURE_NX))
		kvm_enable_efer_bits(EFER_NX);
	if (boot_cpu_has(X86_FEATURE_FXSR_OPT))
		kvm_enable_efer_bits(EFER_FFXSR);

	kvm_set_cpu_caps();

	/* Unloading kvm-intel.ko doesn't clean up kvm_caps.supported_mce_cap. */
	kvm_caps.supported_mce_cap = MCG_CTL_P | MCG_SER_P;

	kvm_caps.supported_xss = 0;

	/* PVM supervisor mode runs on hardware ring3, so no xsaves. */
	kvm_cpu_cap_clear(X86_FEATURE_XSAVES);

	/*
	 * PVM supervisor mode runs on hardware ring3, so SMEP and SMAP can not
	 * be supported directly through hardware.  But they can be emulated
	 * through other hardware feature when needed.
	 */

	/*
	 * PVM doesn't support SMAP, but the similar protection might be
	 * emulated via PKU in the future.
	 */
	kvm_cpu_cap_clear(X86_FEATURE_SMAP);

	/*
	 * PVM doesn't support SMEP.  When NX is supported and the guest can
	 * use NX on the user pagetable to emulate the same protection as SMEP.
	 */
	kvm_cpu_cap_clear(X86_FEATURE_SMEP);

	/*
	 * Unlike VMX/SVM which can switches paging mode atomically, PVM
	 * implements guest LA57 through host LA57 shadow paging.
	 */
	if (!pgtable_l5_enabled())
		kvm_cpu_cap_clear(X86_FEATURE_LA57);

	/*
	 * Even host pcid is not enabled, guest pcid can be enabled to reduce
	 * the heavy guest tlb flushing.  Guest CR4.PCIDE is not directly
	 * mapped to the hardware and is virtualized by PVM so that it can be
	 * enabled unconditionally.
	 */
	kvm_cpu_cap_set(X86_FEATURE_PCID);

	/* Don't expose MSR_IA32_SPEC_CTRL to guest */
	kvm_cpu_cap_clear(X86_FEATURE_SPEC_CTRL);
	kvm_cpu_cap_clear(X86_FEATURE_AMD_STIBP);
	kvm_cpu_cap_clear(X86_FEATURE_AMD_IBRS);
	kvm_cpu_cap_clear(X86_FEATURE_AMD_SSBD);

	/* PVM hypervisor hasn't implemented LAM so far */
	kvm_cpu_cap_clear(X86_FEATURE_LAM);

	/* Don't expose MSR_IA32_DEBUGCTLMSR related features. */
	kvm_cpu_cap_clear(X86_FEATURE_BUS_LOCK_DETECT);
}

static __init int hardware_setup(void)
{
	struct desc_ptr dt;

	store_idt(&dt);
	host_idt_base = dt.address;

	pvm_set_cpu_caps();

	kvm_configure_mmu(false, 0, 0, 0);

	enable_apicv = 0;

	return 0;
}

static void hardware_unsetup(void)
{
}

struct kvm_x86_nested_ops pvm_nested_ops = {};

static struct kvm_x86_ops pvm_x86_ops __initdata = {
	.name = KBUILD_MODNAME,

	.check_processor_compatibility = pvm_check_processor_compat,

	.hardware_unsetup = hardware_unsetup,
	.hardware_enable = hardware_enable,
	.hardware_disable = hardware_disable,
	.has_emulated_msr = pvm_has_emulated_msr,

	.has_wbinvd_exit = cpu_has_pvm_wbinvd_exit,

	.vm_size = sizeof(struct kvm_pvm),
	.vm_init = pvm_vm_init,

	.vcpu_create = pvm_vcpu_create,
	.vcpu_free = pvm_vcpu_free,
	.vcpu_reset = pvm_vcpu_reset,

	.vcpu_after_set_cpuid = pvm_vcpu_after_set_cpuid,

	.nested_ops = &pvm_nested_ops,

	.setup_mce = pvm_setup_mce,
};

static struct kvm_x86_init_ops pvm_init_ops __initdata = {
	.hardware_setup = hardware_setup,

	.runtime_ops = &pvm_x86_ops,
};

static void pvm_exit(void)
{
	kvm_exit();
	kvm_x86_vendor_exit();
	host_mmu_destroy();
	allow_smaller_maxphyaddr = false;
	kvm_cpuid_vendor_signature = 0;
}
module_exit(pvm_exit);

static int __init hardware_cap_check(void)
{
	/*
	 * switcher can't be used when KPTI. See the comments above
	 * SWITCHER_SAVE_AND_SWITCH_TO_HOST_CR3
	 */
	if (boot_cpu_has(X86_FEATURE_PTI)) {
		pr_warn("Support for host KPTI is not included yet.\n");
		return -EOPNOTSUPP;
	}
	if (!boot_cpu_has(X86_FEATURE_FSGSBASE)) {
		pr_warn("FSGSBASE is required per PVM specification.\n");
		return -EOPNOTSUPP;
	}
	if (!boot_cpu_has(X86_FEATURE_RDTSCP)) {
		pr_warn("RDTSCP is required to support for getcpu in guest vdso.\n");
		return -EOPNOTSUPP;
	}
	if (!boot_cpu_has(X86_FEATURE_CX16)) {
		pr_warn("CMPXCHG16B is required for guest.\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

static int __init pvm_init(void)
{
	int r;

	r = hardware_cap_check();
	if (r)
		return r;

	r = host_mmu_init();
	if (r)
		return r;

	is_intel = boot_cpu_data.x86_vendor == X86_VENDOR_INTEL;

	r = kvm_x86_vendor_init(&pvm_init_ops);
	if (r)
		goto exit_host_mmu;

	r = kvm_init(sizeof(struct vcpu_pvm), __alignof__(struct vcpu_pvm), THIS_MODULE);
	if (r)
		goto exit_vendor;

	allow_smaller_maxphyaddr = true;
	kvm_cpuid_vendor_signature = PVM_CPUID_SIGNATURE;

	return 0;

exit_vendor:
	kvm_x86_vendor_exit();
exit_host_mmu:
	host_mmu_destroy();
	return r;
}
module_init(pvm_init);
