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

#include <asm/gsseg.h>
#include <asm/io_bitmap.h>
#include <asm/pvm_para.h>
#include <asm/mmu_context.h>

#include "cpuid.h"
#include "lapic.h"
#include "mmu.h"
#include "trace.h"
#include "x86.h"
#include "pvm.h"

MODULE_AUTHOR("AntGroup");
MODULE_LICENSE("GPL");

static bool __read_mostly is_intel;

static unsigned long host_idt_base;

static inline bool is_smod(struct vcpu_pvm *pvm)
{
	unsigned long switch_flags = pvm->switch_flags;

	if ((switch_flags & SWITCH_FLAGS_MOD_TOGGLE) == SWITCH_FLAGS_SMOD)
		return true;

	WARN_ON_ONCE((switch_flags & SWITCH_FLAGS_MOD_TOGGLE) != SWITCH_FLAGS_UMOD);
	return false;
}

static inline void pvm_switch_flags_toggle_mod(struct vcpu_pvm *pvm)
{
	pvm->switch_flags ^= SWITCH_FLAGS_MOD_TOGGLE;
}

static inline u16 kernel_cs_by_msr(u64 msr_star)
{
	// [47..32]
	// and force rpl=0
	return ((msr_star >> 32) & ~0x3);
}

static inline u16 kernel_ds_by_msr(u64 msr_star)
{
	// [47..32] + 8
	// and force rpl=0
	return ((msr_star >> 32) & ~0x3) + 8;
}

static inline u16 user_cs32_by_msr(u64 msr_star)
{
	// [63..48] is user_cs32 and force rpl=3
	return ((msr_star >> 48) | 0x3);
}

static inline u16 user_cs_by_msr(u64 msr_star)
{
	// [63..48] is user_cs32, and [63..48] + 16 is user_cs
	// and force rpl=3
	return ((msr_star >> 48) | 0x3) + 16;
}

static inline void __save_gs_base(struct vcpu_pvm *pvm)
{
	// switcher will do a real hw swapgs, so use hw MSR_KERNEL_GS_BASE
	rdmsrl(MSR_KERNEL_GS_BASE, pvm->segments[VCPU_SREG_GS].base);
}

static inline void __load_gs_base(struct vcpu_pvm *pvm)
{
	// switcher will do a real hw swapgs, so use hw MSR_KERNEL_GS_BASE
	wrmsrl(MSR_KERNEL_GS_BASE, pvm->segments[VCPU_SREG_GS].base);
}

static inline void __save_fs_base(struct vcpu_pvm *pvm)
{
	rdmsrl(MSR_FS_BASE, pvm->segments[VCPU_SREG_FS].base);
}

static inline void __load_fs_base(struct vcpu_pvm *pvm)
{
	wrmsrl(MSR_FS_BASE, pvm->segments[VCPU_SREG_FS].base);
}

static u64 pvm_read_guest_gs_base(struct vcpu_pvm *pvm)
{
	preempt_disable();
	if (pvm->loaded_cpu_state)
		__save_gs_base(pvm);
	preempt_enable();

	return pvm->segments[VCPU_SREG_GS].base;
}

static u64 pvm_read_guest_fs_base(struct vcpu_pvm *pvm)
{
	preempt_disable();
	if (pvm->loaded_cpu_state)
		__save_fs_base(pvm);
	preempt_enable();

	return pvm->segments[VCPU_SREG_FS].base;
}

static u64 pvm_read_guest_kernel_gs_base(struct vcpu_pvm *pvm)
{
	return pvm->msr_kernel_gs_base;
}

static void pvm_write_guest_gs_base(struct vcpu_pvm *pvm, u64 data)
{
	preempt_disable();
	pvm->segments[VCPU_SREG_GS].base = data;
	if (pvm->loaded_cpu_state)
		__load_gs_base(pvm);
	preempt_enable();
}

static void pvm_write_guest_fs_base(struct vcpu_pvm *pvm, u64 data)
{
	preempt_disable();
	pvm->segments[VCPU_SREG_FS].base = data;
	if (pvm->loaded_cpu_state)
		__load_fs_base(pvm);
	preempt_enable();
}

static void pvm_write_guest_kernel_gs_base(struct vcpu_pvm *pvm, u64 data)
{
	pvm->msr_kernel_gs_base = data;
}

static __always_inline bool pvm_guest_allowed_va(struct kvm_vcpu *vcpu, u64 va)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	if ((s64)va > 0)
		return true;
	if (pvm->l4_range_start <= va && va < pvm->l4_range_end)
		return true;
	if (pvm->l5_range_start <= va && va < pvm->l5_range_end)
		return true;

	return false;
}

static bool pvm_disallowed_va(struct kvm_vcpu *vcpu, u64 va)
{
	if (is_noncanonical_address(va, vcpu))
		return true;

	return !pvm_guest_allowed_va(vcpu, va);
}

// switch_to_smod() and switch_to_umod() switch the mode (smod/umod) and
// the CR3.  No vTLB flushing when switching the CR3 per PVM Spec.
static inline void switch_to_smod(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	pvm_switch_flags_toggle_mod(pvm);
	kvm_mmu_new_pgd(vcpu, pvm->msr_switch_cr3);
	swap(pvm->msr_switch_cr3, vcpu->arch.cr3);

	pvm_write_guest_gs_base(pvm, pvm->msr_kernel_gs_base);
	kvm_rsp_write(vcpu, pvm->msr_supervisor_rsp);

	pvm->hw_cs = __USER_CS;
	pvm->hw_ss = __USER_DS;
}

static inline void switch_to_umod(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	pvm->msr_supervisor_rsp = kvm_rsp_read(vcpu);

	pvm_switch_flags_toggle_mod(pvm);
	kvm_mmu_new_pgd(vcpu, pvm->msr_switch_cr3);
	swap(pvm->msr_switch_cr3, vcpu->arch.cr3);
}

/*
 * Test whether DS, ES, FS and GS need to be reloaded.
 *
 * Reading them only returns the selectors, but writing them (if
 * nonzero) loads the full descriptor from the GDT or LDT.
 *
 * We therefore need to write new values to the segment registers
 * on every host-guest state switch unless both the new and old
 * values are zero.
 */
static inline bool need_reload_sel(u16 sel1, u16 sel2)
{
	return unlikely(sel1 | sel2);
}

/*
 * Save host DS/ES/FS/GS selector, FS base, and inactive GS base.
 * And load guest DS/ES/FS/GS selector, FS base, and GS base.
 *
 * Note, when the guest state is loaded and it is in hypervisor, the guest
 * GS base is loaded in the hardware MSR_KERNEL_GS_BASE which is loaded
 * with host inactive GS base when the guest state is NOT loaded.
 */
static void segments_save_host_and_switch_to_guest(struct vcpu_pvm *pvm)
{
	u16 pvm_ds_sel, pvm_es_sel, pvm_fs_sel, pvm_gs_sel;

	/* Save host segments */
	savesegment(ds, pvm->host_ds_sel);
	savesegment(es, pvm->host_es_sel);
	current_save_fsgs();

	/* Load guest segments */
	pvm_ds_sel = pvm->segments[VCPU_SREG_DS].selector;
	pvm_es_sel = pvm->segments[VCPU_SREG_ES].selector;
	pvm_fs_sel = pvm->segments[VCPU_SREG_FS].selector;
	pvm_gs_sel = pvm->segments[VCPU_SREG_GS].selector;

	if (need_reload_sel(pvm_ds_sel, pvm->host_ds_sel))
		loadsegment(ds, pvm_ds_sel);
	if (need_reload_sel(pvm_es_sel, pvm->host_es_sel))
		loadsegment(es, pvm_es_sel);
	if (need_reload_sel(pvm_fs_sel, current->thread.fsindex))
		loadsegment(fs, pvm_fs_sel);
	if (need_reload_sel(pvm_gs_sel, current->thread.gsindex))
		load_gs_index(pvm_gs_sel);

	__load_gs_base(pvm);
	__load_fs_base(pvm);
}

/*
 * Save guest DS/ES/FS/GS selector, FS base, and GS base.
 * And load host DS/ES/FS/GS selector, FS base, and inactive GS base.
 */
static void segments_save_guest_and_switch_to_host(struct vcpu_pvm *pvm)
{
	u16 pvm_ds_sel, pvm_es_sel, pvm_fs_sel, pvm_gs_sel;

	/* Save guest segments */
	savesegment(ds, pvm_ds_sel);
	savesegment(es, pvm_es_sel);
	savesegment(fs, pvm_fs_sel);
	savesegment(gs, pvm_gs_sel);
	pvm->segments[VCPU_SREG_DS].selector = pvm_ds_sel;
	pvm->segments[VCPU_SREG_ES].selector = pvm_es_sel;
	pvm->segments[VCPU_SREG_FS].selector = pvm_fs_sel;
	pvm->segments[VCPU_SREG_GS].selector = pvm_gs_sel;

	__save_fs_base(pvm);
	__save_gs_base(pvm);

	/* Load host segments */
	if (need_reload_sel(pvm_ds_sel, pvm->host_ds_sel))
		loadsegment(ds, pvm->host_ds_sel);
	if (need_reload_sel(pvm_es_sel, pvm->host_es_sel))
		loadsegment(es, pvm->host_es_sel);
	if (need_reload_sel(pvm_fs_sel, current->thread.fsindex))
		loadsegment(fs, current->thread.fsindex);
	if (need_reload_sel(pvm_gs_sel, current->thread.gsindex))
		load_gs_index(current->thread.gsindex);

	wrmsrl(MSR_KERNEL_GS_BASE, current->thread.gsbase);
	wrmsrl(MSR_FS_BASE, current->thread.fsbase);
}

static void pvm_prepare_switch_to_guest(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	if (pvm->loaded_cpu_state)
		return;

	pvm->loaded_cpu_state = 1;

#ifdef CONFIG_X86_IOPL_IOPERM
	/*
	 * PVM doesn't load guest I/O bitmap into hardware.  Invalidate I/O
	 * bitmap if the current task is using it.  This prevents any possible
	 * leakage of an active I/O bitmap to the guest and forces I/O
	 * instructions in guest to be trapped and emulated.
	 *
	 * The I/O bitmap will be restored when the current task exits to
	 * user mode in arch_exit_to_user_mode_prepare().
	 */
	if (test_thread_flag(TIF_IO_BITMAP))
		native_tss_invalidate_io_bitmap();
#endif

#ifdef CONFIG_MODIFY_LDT_SYSCALL
	/* PVM doesn't support LDT. */
	if (unlikely(current->mm->context.ldt))
		clear_LDT();
#endif

	segments_save_host_and_switch_to_guest(pvm);

	kvm_set_user_return_msr(0, (u64)entry_SYSCALL_64_switcher, -1ull);
	kvm_set_user_return_msr(1, pvm->msr_tsc_aux, -1ull);
	if (ia32_enabled()) {
		if (is_intel)
			kvm_set_user_return_msr(2, GDT_ENTRY_INVALID_SEG, -1ull);
		else
			kvm_set_user_return_msr(2, (u64)entry_SYSCALL32_ignore, -1ull);
	}
}

static void pvm_prepare_switch_to_host(struct vcpu_pvm *pvm)
{
	if (!pvm->loaded_cpu_state)
		return;

	++pvm->vcpu.stat.host_state_reload;

#ifdef CONFIG_MODIFY_LDT_SYSCALL
	if (unlikely(current->mm->context.ldt))
		kvm_load_ldt(GDT_ENTRY_LDT*8);
#endif

	segments_save_guest_and_switch_to_host(pvm);
	pvm->loaded_cpu_state = 0;
}

/*
 * Set all hardware states back to host.
 * Except user return MSRs.
 */
static void pvm_switch_to_host(struct vcpu_pvm *pvm)
{
	preempt_disable();
	pvm_prepare_switch_to_host(pvm);
	preempt_enable();
}

static void pvm_set_host_cr3_for_hypervisor(struct vcpu_pvm *pvm)
{
	unsigned long cr3;

	if (static_cpu_has(X86_FEATURE_PCID))
		cr3 = __get_current_cr3_fast() | X86_CR3_PCID_NOFLUSH;
	else
		cr3 = __get_current_cr3_fast();
	this_cpu_write(cpu_tss_rw.tss_ex.host_cr3, cr3);
}

// Set tss_ex.host_cr3 for VMExit.
// Set tss_ex.enter_cr3 for VMEnter.
static void pvm_set_host_cr3(struct vcpu_pvm *pvm)
{
	pvm_set_host_cr3_for_hypervisor(pvm);
	this_cpu_write(cpu_tss_rw.tss_ex.enter_cr3, pvm->vcpu.arch.mmu->root.hpa);
}

static void pvm_load_mmu_pgd(struct kvm_vcpu *vcpu, hpa_t root_hpa,
			     int root_level)
{
	/* Nothing to do. Guest cr3 will be prepared in pvm_set_host_cr3(). */
}

DEFINE_PER_CPU(struct vcpu_pvm *, active_pvm_vcpu);

/*
 * Switches to specified vcpu, until a matching vcpu_put(), but assumes
 * vcpu mutex is already taken.
 */
static void pvm_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	pvm->host_debugctlmsr = get_debugctlmsr();

	if (__this_cpu_read(active_pvm_vcpu) == pvm && vcpu->cpu == cpu)
		return;

	__this_cpu_write(active_pvm_vcpu, pvm);

	indirect_branch_prediction_barrier();
}

static void pvm_vcpu_put(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	pvm_prepare_switch_to_host(pvm);
}

static void pvm_sched_in(struct kvm_vcpu *vcpu, int cpu)
{
}

static void pvm_patch_hypercall(struct kvm_vcpu *vcpu, unsigned char *hypercall)
{
	/* KVM_X86_QUIRK_FIX_HYPERCALL_INSN should not be enabled for pvm guest */

	/* ud2; int3; */
	hypercall[0] = 0x0F;
	hypercall[1] = 0x0B;
	hypercall[2] = 0xCC;
}

static int pvm_check_emulate_instruction(struct kvm_vcpu *vcpu, int emul_type,
					 void *insn, int insn_len)
{
	return X86EMUL_CONTINUE;
}

static int skip_emulated_instruction(struct kvm_vcpu *vcpu)
{
	return kvm_emulate_instruction(vcpu, EMULTYPE_SKIP);
}

static int pvm_check_intercept(struct kvm_vcpu *vcpu,
			       struct x86_instruction_info *info,
			       enum x86_intercept_stage stage,
			       struct x86_exception *exception)
{
	/*
	 * HF_GUEST_MASK is not used even nested pvm is supported. L0 pvm
	 * might even be unaware the L1 pvm.
	 */
	WARN_ON_ONCE(1);
	return X86EMUL_CONTINUE;
}

static void pvm_set_msr_linear_address_range(struct vcpu_pvm *pvm,
					     u64 pml4_i_s, u64 pml4_i_e,
					     u64 pml5_i_s, u64 pml5_i_e)
{
	pvm->msr_linear_address_range = ((0xfe00 | pml4_i_s) << 0) |
					((0xfe00 | pml4_i_e) << 16) |
					((0xfe00 | pml5_i_s) << 32) |
					((0xfe00 | pml5_i_e) << 48);

	pvm->l4_range_start = (0x1fffe00 | pml4_i_s) * PT_L4_SIZE;
	pvm->l4_range_end = (0x1fffe00 | pml4_i_e) * PT_L4_SIZE;
	pvm->l5_range_start = (0xfe00 | pml5_i_s) * PT_L5_SIZE;
	pvm->l5_range_end = (0xfe00 | pml5_i_e) * PT_L5_SIZE;
}

static void pvm_set_default_msr_linear_address_range(struct vcpu_pvm *pvm)
{
	pvm_set_msr_linear_address_range(pvm, pml4_index_start, pml4_index_end,
					 pml5_index_start, pml5_index_end);
}

static bool pvm_check_and_set_msr_linear_address_range(struct vcpu_pvm *pvm, u64 msr)
{
	u64 pml4_i_s = (msr >> 0) & 0x1ff;
	u64 pml4_i_e = (msr >> 16) & 0x1ff;
	u64 pml5_i_s = (msr >> 32) & 0x1ff;
	u64 pml5_i_e = (msr >> 48) & 0x1ff;

	/* PVM specification requires those bits to be all set. */
	if ((msr & 0xff00ff00ff00ff00) != 0xff00ff00ff00ff00)
		return false;

	/* Guest ranges should be inside what the hypervisor can provide. */
	if (pml4_i_s < pml4_index_start || pml4_i_e > pml4_index_end ||
	    pml5_i_s < pml5_index_start || pml5_i_e > pml5_index_end)
		return false;

	pvm_set_msr_linear_address_range(pvm, pml4_i_s, pml4_i_e, pml5_i_s, pml5_i_e);

	return true;
}

static int pvm_get_msr_feature(struct kvm_msr_entry *msr)
{
	return 1;
}

static void pvm_msr_filter_changed(struct kvm_vcpu *vcpu)
{
	/* Accesses to MSRs are emulated in hypervisor, nothing to do here. */
}

/*
 * Reads an msr value (of 'msr_index') into 'msr_info'.
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
static int pvm_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	int ret = 0;

	switch (msr_info->index) {
	case MSR_FS_BASE:
		msr_info->data = pvm_read_guest_fs_base(pvm);
		break;
	case MSR_GS_BASE:
		msr_info->data = pvm_read_guest_gs_base(pvm);
		break;
	case MSR_KERNEL_GS_BASE:
		msr_info->data = pvm_read_guest_kernel_gs_base(pvm);
		break;
	case MSR_STAR:
		msr_info->data = pvm->msr_star;
		break;
	case MSR_LSTAR:
		msr_info->data = pvm->msr_lstar;
		break;
	case MSR_SYSCALL_MASK:
		msr_info->data = pvm->msr_syscall_mask;
		break;
	case MSR_CSTAR:
		msr_info->data = pvm->unused_MSR_CSTAR;
		break;
	/*
	 * Since SYSENTER is not supported for the guest, we return a bad
	 * segment to the emulator when emulating the instruction for #GP.
	 */
	case MSR_IA32_SYSENTER_CS:
		msr_info->data = GDT_ENTRY_INVALID_SEG;
		break;
	case MSR_IA32_SYSENTER_EIP:
		msr_info->data = pvm->unused_MSR_IA32_SYSENTER_EIP;
		break;
	case MSR_IA32_SYSENTER_ESP:
		msr_info->data = pvm->unused_MSR_IA32_SYSENTER_ESP;
		break;
	case MSR_IA32_DEBUGCTLMSR:
		msr_info->data = 0;
		break;
	case MSR_PVM_VCPU_STRUCT:
		msr_info->data = pvm->msr_vcpu_struct;
		break;
	case MSR_PVM_SUPERVISOR_RSP:
		msr_info->data = pvm->msr_supervisor_rsp;
		break;
	case MSR_PVM_SUPERVISOR_REDZONE:
		msr_info->data = pvm->msr_supervisor_redzone;
		break;
	case MSR_PVM_EVENT_ENTRY:
		msr_info->data = pvm->msr_event_entry;
		break;
	case MSR_PVM_RETU_RIP:
		msr_info->data = pvm->msr_retu_rip_plus2 - 2;
		break;
	case MSR_PVM_RETS_RIP:
		msr_info->data = pvm->msr_rets_rip_plus2 - 2;
		break;
	case MSR_PVM_SWITCH_CR3:
		msr_info->data = pvm->msr_switch_cr3;
		break;
	case MSR_PVM_LINEAR_ADDRESS_RANGE:
		msr_info->data = pvm->msr_linear_address_range;
		break;
	default:
		ret = kvm_get_msr_common(vcpu, msr_info);
	}

	return ret;
}

/*
 * Writes msr value into the appropriate "register".
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
static int pvm_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	int ret = 0;
	u32 msr_index = msr_info->index;
	u64 data = msr_info->data;

	switch (msr_index) {
	case MSR_FS_BASE:
		pvm_write_guest_fs_base(pvm, data);
		break;
	case MSR_GS_BASE:
		pvm_write_guest_gs_base(pvm, data);
		break;
	case MSR_KERNEL_GS_BASE:
		pvm_write_guest_kernel_gs_base(pvm, data);
		break;
	case MSR_STAR:
		/*
		 * Guest KERNEL_CS/DS shouldn't be NULL and guest USER_CS/DS
		 * must be the same as the host USER_CS/DS.
		 */
		if (!msr_info->host_initiated) {
			if (!kernel_cs_by_msr(data))
				return 1;
			if (user_cs_by_msr(data) != __USER_CS)
				return 1;
		}
		pvm->msr_star = data;
		break;
	case MSR_LSTAR:
		if (is_noncanonical_address(msr_info->data, vcpu))
			return 1;
		pvm->msr_lstar = data;
		break;
	case MSR_SYSCALL_MASK:
		pvm->msr_syscall_mask = data;
		break;
	case MSR_CSTAR:
		pvm->unused_MSR_CSTAR = data;
		break;
	case MSR_IA32_SYSENTER_CS:
		pvm->unused_MSR_IA32_SYSENTER_CS = data;
		break;
	case MSR_IA32_SYSENTER_EIP:
		pvm->unused_MSR_IA32_SYSENTER_EIP = data;
		break;
	case MSR_IA32_SYSENTER_ESP:
		pvm->unused_MSR_IA32_SYSENTER_ESP = data;
		break;
	case MSR_IA32_DEBUGCTLMSR:
		/* It is ignored now. */
		break;
	case MSR_PVM_VCPU_STRUCT:
		if (!PAGE_ALIGNED(data))
			return 1;
		if (!data)
			kvm_gpc_deactivate(&pvm->pvcs_gpc);
		else if (kvm_gpc_activate(&pvm->pvcs_gpc, data, PAGE_SIZE))
			return 1;

		pvm->msr_vcpu_struct = data;
		break;
	case MSR_PVM_SUPERVISOR_RSP:
		pvm->msr_supervisor_rsp = msr_info->data;
		break;
	case MSR_PVM_SUPERVISOR_REDZONE:
		pvm->msr_supervisor_redzone = msr_info->data;
		break;
	case MSR_PVM_EVENT_ENTRY:
		if (is_noncanonical_address(data, vcpu) ||
		    is_noncanonical_address(data + 256, vcpu) ||
		    is_noncanonical_address(data + 512, vcpu)) {
			kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
			return 1;
		}
		pvm->msr_event_entry = msr_info->data;
		break;
	case MSR_PVM_RETU_RIP:
		pvm->msr_retu_rip_plus2 = msr_info->data + 2;
		break;
	case MSR_PVM_RETS_RIP:
		pvm->msr_rets_rip_plus2 = msr_info->data + 2;
		break;
	case MSR_PVM_SWITCH_CR3:
		pvm->msr_switch_cr3 = msr_info->data;
		break;
	case MSR_PVM_LINEAR_ADDRESS_RANGE:
		if (!pvm_check_and_set_msr_linear_address_range(pvm, msr_info->data))
			return 1;
		break;
	default:
		ret = kvm_set_msr_common(vcpu, msr_info);
	}

	return ret;
}

static void pvm_get_segment(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	// Update CS or SS to reflect the current mode.
	if (seg == VCPU_SREG_CS) {
		if (is_smod(pvm)) {
			pvm->segments[seg].selector = kernel_cs_by_msr(pvm->msr_star);
			pvm->segments[seg].dpl = 0;
			pvm->segments[seg].l = 1;
			pvm->segments[seg].db = 0;
		} else {
			pvm->segments[seg].selector = pvm->hw_cs >> 3;
			pvm->segments[seg].dpl = 3;
			if (pvm->hw_cs == __USER_CS) {
				pvm->segments[seg].l = 1;
				pvm->segments[seg].db = 0;
			} else { // __USER32_CS
				pvm->segments[seg].l = 0;
				pvm->segments[seg].db = 1;
			}
		}
	} else if (seg == VCPU_SREG_SS) {
		if (is_smod(pvm)) {
			pvm->segments[seg].dpl = 0;
			pvm->segments[seg].selector = kernel_ds_by_msr(pvm->msr_star);
		} else {
			pvm->segments[seg].dpl = 3;
			pvm->segments[seg].selector = pvm->hw_ss >> 3;
		}
	}

	// Update DS/ES/FS/GS states from the hardware when the states are loaded.
	pvm_switch_to_host(pvm);
	*var = pvm->segments[seg];
}

static u64 pvm_get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_segment var;

	pvm_get_segment(vcpu, &var, seg);
	return var.base;
}

static int pvm_get_cpl(struct kvm_vcpu *vcpu)
{
	if (is_smod(to_pvm(vcpu)))
		return 0;
	return 3;
}

static void pvm_set_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var, int seg)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	int cpl = pvm_get_cpl(vcpu);

	// Unload DS/ES/FS/GS states from hardware before changing them.
	// It also has to unload the VCPU when leaving PVM mode.
	pvm_switch_to_host(pvm);
	pvm->segments[seg] = *var;

	switch (seg) {
	case VCPU_SREG_CS:
		if (var->dpl == 1 || var->dpl == 2)
			goto invalid_change;
		if (!kvm_vcpu_has_run(vcpu)) {
			// CPL changing is only valid for the first changed
			// after the vcpu is created (vm-migration).
			if (cpl != var->dpl)
				pvm_switch_flags_toggle_mod(pvm);
		} else {
			if (cpl != var->dpl)
				goto invalid_change;
			if (cpl == 0 && !var->l)
				goto invalid_change;
		}
		break;
	case VCPU_SREG_LDTR:
		// pvm doesn't support LDT
		if (var->selector)
			goto invalid_change;
		break;
	default:
		break;
	}

	return;

invalid_change:
	kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
}

static void pvm_get_cs_db_l_bits(struct kvm_vcpu *vcpu, int *db, int *l)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	if (pvm->hw_cs == __USER_CS) {
		*db = 0;
		*l = 1;
	} else {
		*db = 1;
		*l = 0;
	}
}

static void pvm_get_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	*dt = to_pvm(vcpu)->idt_ptr;
}

static void pvm_set_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	to_pvm(vcpu)->idt_ptr = *dt;
}

static void pvm_get_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	*dt = to_pvm(vcpu)->gdt_ptr;
}

static void pvm_set_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	to_pvm(vcpu)->gdt_ptr = *dt;
}

static void pvm_deliver_interrupt(struct kvm_lapic *apic, int delivery_mode,
				  int trig_mode, int vector)
{
	struct kvm_vcpu *vcpu = apic->vcpu;

	kvm_lapic_set_irr(vector, apic);
	kvm_make_request(KVM_REQ_EVENT, vcpu);
	kvm_vcpu_kick(vcpu);
}

static void pvm_refresh_apicv_exec_ctrl(struct kvm_vcpu *vcpu)
{
}

static bool pvm_apic_init_signal_blocked(struct kvm_vcpu *vcpu)
{
	return false;
}

static void update_exception_bitmap(struct kvm_vcpu *vcpu)
{
}

static struct pvm_vcpu_struct *pvm_get_vcpu_struct(struct vcpu_pvm *pvm)
{
	struct gfn_to_pfn_cache *gpc = &pvm->pvcs_gpc;

	read_lock_irq(&gpc->lock);
	while (!kvm_gpc_check(gpc, PAGE_SIZE)) {
		read_unlock_irq(&gpc->lock);

		if (kvm_gpc_refresh(gpc, PAGE_SIZE))
			return NULL;

		read_lock_irq(&gpc->lock);
	}

	return (struct pvm_vcpu_struct *)(gpc->khva);
}

static void pvm_put_vcpu_struct(struct vcpu_pvm *pvm, bool dirty)
{
	struct gfn_to_pfn_cache *gpc = &pvm->pvcs_gpc;

	read_unlock_irq(&gpc->lock);
	if (dirty)
		mark_page_dirty_in_slot(pvm->vcpu.kvm, gpc->memslot,
					gpc->gpa >> PAGE_SHIFT);
}

static void pvm_vcpu_gpc_refresh(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	struct gfn_to_pfn_cache *gpc = &pvm->pvcs_gpc;

	if (!gpc->active)
		return;

	if (pvm_get_vcpu_struct(pvm))
		pvm_put_vcpu_struct(pvm, false);
	else
		kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
}

static void pvm_event_flags_update(struct kvm_vcpu *vcpu, unsigned long set,
				   unsigned long clear)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	static struct pvm_vcpu_struct *pvcs;
	unsigned long old_flags, new_flags;

	if (!pvm->msr_vcpu_struct)
		return;

	pvcs = pvm_get_vcpu_struct(pvm);
	if (!pvcs)
		return;

	old_flags = pvcs->event_flags;
	new_flags = (old_flags | set) & ~clear;
	if (new_flags != old_flags)
		pvcs->event_flags = new_flags;

	pvm_put_vcpu_struct(pvm, new_flags != old_flags);
}

static void pvm_standard_event_entry(struct kvm_vcpu *vcpu, unsigned long entry)
{
	// Change rip, rflags, rcx and r11 per PVM event delivery specification,
	// this allows to use sysret in VM enter.
	kvm_rip_write(vcpu, entry);
	kvm_set_rflags(vcpu, X86_EFLAGS_FIXED);
	kvm_rcx_write(vcpu, entry);
	kvm_r11_write(vcpu, X86_EFLAGS_IF | X86_EFLAGS_FIXED);
}

/* handle pvm user event per PVM Spec. */
static int do_pvm_user_event(struct kvm_vcpu *vcpu, int vector,
			     bool has_err_code, u64 err_code)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	unsigned long entry = vector == PVM_SYSCALL_VECTOR ?
			      pvm->msr_lstar : pvm->msr_event_entry;
	struct pvm_vcpu_struct *pvcs;

	pvcs = pvm_get_vcpu_struct(pvm);
	if (!pvcs) {
		kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
		return 1;
	}

	pvcs->user_cs = pvm->hw_cs;
	pvcs->user_ss = pvm->hw_ss;
	pvcs->eflags = kvm_get_rflags(vcpu);
	pvcs->pkru = 0;
	pvcs->user_gsbase = pvm_read_guest_gs_base(pvm);
	pvcs->rip = kvm_rip_read(vcpu);
	pvcs->rsp = kvm_rsp_read(vcpu);
	pvcs->rcx = kvm_rcx_read(vcpu);
	pvcs->r11 = kvm_r11_read(vcpu);

	if (has_err_code)
		pvcs->event_errcode = err_code;
	if (vector != PVM_SYSCALL_VECTOR)
		pvcs->event_vector = vector;

	if (vector == PF_VECTOR)
		pvcs->cr2 = vcpu->arch.cr2;

	pvm_put_vcpu_struct(pvm, true);

	switch_to_smod(vcpu);

	pvm_standard_event_entry(vcpu, entry);

	return 1;
}

static int do_pvm_supervisor_exception(struct kvm_vcpu *vcpu, int vector,
				       bool has_error_code, u64 error_code)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	unsigned long stack;
	struct pvm_supervisor_event frame;
	struct x86_exception e;
	int ret;

	memset(&frame, 0, sizeof(frame));
	frame.cs = kernel_cs_by_msr(pvm->msr_star);
	frame.ss = kernel_ds_by_msr(pvm->msr_star);
	frame.rip = kvm_rip_read(vcpu);
	frame.rflags = kvm_get_rflags(vcpu);
	frame.rsp = kvm_rsp_read(vcpu);
	frame.errcode = ((unsigned long)vector << 32) | error_code;
	frame.r11 = kvm_r11_read(vcpu);
	frame.rcx = kvm_rcx_read(vcpu);

	stack = ((frame.rsp - pvm->msr_supervisor_redzone) & ~15UL) - sizeof(frame);

	ret = kvm_write_guest_virt_system(vcpu, stack, &frame, sizeof(frame), &e);
	if (ret) {
		kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
		return 1;
	}

	if (vector == PF_VECTOR) {
		struct pvm_vcpu_struct *pvcs;

		pvcs = pvm_get_vcpu_struct(pvm);
		if (!pvcs) {
			kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
			return 1;
		}

		pvcs->cr2 = vcpu->arch.cr2;
		pvm_put_vcpu_struct(pvm, true);
	}

	kvm_rsp_write(vcpu, stack);

	pvm_standard_event_entry(vcpu, pvm->msr_event_entry + 256);

	return 1;
}

static int do_pvm_supervisor_interrupt(struct kvm_vcpu *vcpu, int vector,
				       bool has_error_code, u64 error_code)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	unsigned long stack = kvm_rsp_read(vcpu);
	struct pvm_vcpu_struct *pvcs;

	pvcs = pvm_get_vcpu_struct(pvm);
	if (!pvcs) {
		kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
		return 1;
	}
	pvcs->eflags = kvm_get_rflags(vcpu);
	pvcs->rip = kvm_rip_read(vcpu);
	pvcs->rsp = stack;
	pvcs->rcx = kvm_rcx_read(vcpu);
	pvcs->r11 = kvm_r11_read(vcpu);

	pvcs->event_vector = vector;
	if (has_error_code)
		pvcs->event_errcode = error_code;

	pvm_put_vcpu_struct(pvm, true);

	stack = (stack - pvm->msr_supervisor_redzone) & ~15UL;
	kvm_rsp_write(vcpu, stack);

	pvm_standard_event_entry(vcpu, pvm->msr_event_entry + 512);

	return 1;
}

static int do_pvm_event(struct kvm_vcpu *vcpu, int vector,
			bool has_error_code, u64 error_code)
{
	if (!is_smod(to_pvm(vcpu)))
		return do_pvm_user_event(vcpu, vector, has_error_code, error_code);

	if (vector < 32)
		return do_pvm_supervisor_exception(vcpu, vector,
						   has_error_code, error_code);

	return do_pvm_supervisor_interrupt(vcpu, vector, has_error_code, error_code);
}

static unsigned long pvm_get_rflags(struct kvm_vcpu *vcpu)
{
	return to_pvm(vcpu)->rflags;
}

static void pvm_set_rflags(struct kvm_vcpu *vcpu, unsigned long rflags)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	int need_update = !!((pvm->rflags ^ rflags) & X86_EFLAGS_IF);

	pvm->rflags = rflags;

	/*
	 * The IF bit of 'pvcs->event_flags' should not be changed in user
	 * mode. It is recommended for this bit to be cleared when switching to
	 * user mode, so that when the guest switches back to supervisor mode,
	 * the X86_EFLAGS_IF is already cleared.
	 */
	if (!need_update || !is_smod(pvm))
		return;

	if (rflags & X86_EFLAGS_IF)
		pvm_event_flags_update(vcpu, X86_EFLAGS_IF, PVM_EVENT_FLAGS_IP);
	else
		pvm_event_flags_update(vcpu, 0, X86_EFLAGS_IF);
}

static bool pvm_get_if_flag(struct kvm_vcpu *vcpu)
{
	return pvm_get_rflags(vcpu) & X86_EFLAGS_IF;
}

static u32 pvm_get_interrupt_shadow(struct kvm_vcpu *vcpu)
{
	return to_pvm(vcpu)->int_shadow;
}

static void pvm_set_interrupt_shadow(struct kvm_vcpu *vcpu, int mask)
{
	/* PVM spec: ignore interrupt shadow when in PVM mode. */
}

static void enable_irq_window(struct kvm_vcpu *vcpu)
{
	pvm_event_flags_update(vcpu, PVM_EVENT_FLAGS_IP, 0);
}

static int pvm_interrupt_allowed(struct kvm_vcpu *vcpu, bool for_injection)
{
	return (pvm_get_rflags(vcpu) & X86_EFLAGS_IF) &&
		!to_pvm(vcpu)->int_shadow;
}

static bool pvm_get_nmi_mask(struct kvm_vcpu *vcpu)
{
	return to_pvm(vcpu)->nmi_mask;
}

static void pvm_set_nmi_mask(struct kvm_vcpu *vcpu, bool masked)
{
	to_pvm(vcpu)->nmi_mask = masked;
}

static void enable_nmi_window(struct kvm_vcpu *vcpu)
{
}

static int pvm_nmi_allowed(struct kvm_vcpu *vcpu, bool for_injection)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	return !pvm->nmi_mask && !pvm->int_shadow;
}

/* Always inject the exception directly and consume the event. */
static void pvm_inject_exception(struct kvm_vcpu *vcpu)
{
	unsigned int vector = vcpu->arch.exception.vector;
	bool has_error_code = vcpu->arch.exception.has_error_code;
	u32 error_code = vcpu->arch.exception.error_code;

	kvm_deliver_exception_payload(vcpu, &vcpu->arch.exception);

	if (do_pvm_event(vcpu, vector, has_error_code, error_code))
		kvm_clear_exception_queue(vcpu);
}

/* Always inject the interrupt directly and consume the event. */
static void pvm_inject_irq(struct kvm_vcpu *vcpu, bool reinjected)
{
	int irq = vcpu->arch.interrupt.nr;

	trace_kvm_inj_virq(irq, vcpu->arch.interrupt.soft, false);

	if (do_pvm_event(vcpu, irq, false, 0))
		kvm_clear_interrupt_queue(vcpu);

	++vcpu->stat.irq_injections;
}

/* Always inject the NMI directly and consume the event. */
static void pvm_inject_nmi(struct kvm_vcpu *vcpu)
{
	if (do_pvm_event(vcpu, NMI_VECTOR, false, 0)) {
		vcpu->arch.nmi_injected = false;
		pvm_set_nmi_mask(vcpu, true);
	}

	++vcpu->stat.nmi_injections;
}

static void pvm_cancel_injection(struct kvm_vcpu *vcpu)
{
	/*
	 * Nothing to do. Since exceptions/interrupts are delivered immediately
	 * during event injection, so they cannot be cancelled and reinjected.
	 */
}

static void pvm_setup_mce(struct kvm_vcpu *vcpu)
{
}

static int handle_exit_syscall(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	if (!is_smod(pvm))
		return do_pvm_user_event(vcpu, PVM_SYSCALL_VECTOR, false, 0);
	return 1;
}

static int handle_exit_debug(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	struct kvm_run *kvm_run = pvm->vcpu.run;

	if (pvm->vcpu.guest_debug &
	    (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP)) {
		kvm_run->exit_reason = KVM_EXIT_DEBUG;
		kvm_run->debug.arch.dr6 = pvm->exit_dr6 | DR6_FIXED_1 | DR6_RTM;
		kvm_run->debug.arch.dr7 = vcpu->arch.guest_debug_dr7;
		kvm_run->debug.arch.pc = kvm_rip_read(vcpu);
		kvm_run->debug.arch.exception = DB_VECTOR;
		return 0;
	}

	kvm_queue_exception_p(vcpu, DB_VECTOR, pvm->exit_dr6);
	return 1;
}

/* check if the previous instruction is "int3" on receiving #BP */
static bool is_bp_trap(struct kvm_vcpu *vcpu)
{
	u8 byte = 0;
	unsigned long rip;
	struct x86_exception exception;
	int r;

	rip = kvm_rip_read(vcpu) - 1;
	r = kvm_read_guest_virt(vcpu, rip, &byte, 1, &exception);

	/* Just assume it to be int3 when failed to fetch the instruction. */
	if (r)
		return true;

	return byte == 0xcc;
}

static int handle_exit_breakpoint(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	struct kvm_run *kvm_run = pvm->vcpu.run;

	/*
	 * Breakpoint exception can be caused by int3 or int 3.  While "int3"
	 * participates in guest debug, but "int 3" should not.
	 */
	if ((vcpu->guest_debug & KVM_GUESTDBG_USE_SW_BP) && is_bp_trap(vcpu)) {
		kvm_rip_write(vcpu, kvm_rip_read(vcpu) - 1);
		kvm_run->exit_reason = KVM_EXIT_DEBUG;
		kvm_run->debug.arch.pc = kvm_rip_read(vcpu);
		kvm_run->debug.arch.exception = BP_VECTOR;
		return 0;
	}

	kvm_queue_exception(vcpu, BP_VECTOR);
	return 1;
}

static int handle_exit_exception(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	struct kvm_run *kvm_run = vcpu->run;
	u32 vector, error_code;
	int err;

	vector = pvm->exit_vector;
	error_code = pvm->exit_error_code;

	switch (vector) {
	// #PF, #GP, #UD, #DB and #BP are guest exceptions or hypervisor
	// interested exceptions for emulation or debugging.
	case PF_VECTOR:
		// Remove hardware generated PFERR_USER_MASK when in supervisor
		// mode to reflect the real mode in PVM.
		if (is_smod(pvm))
			error_code &= ~PFERR_USER_MASK;

		// If it is a PK fault, set pkru=0 and re-enter the guest silently.
		// See the comment before pvm_load_guest_xsave_state().
		if (cpu_feature_enabled(X86_FEATURE_PKU) && (error_code & PFERR_PK_MASK))
			return 1;

		return kvm_handle_page_fault(vcpu, error_code, pvm->exit_cr2,
					     NULL, 0);
	case GP_VECTOR:
		err = kvm_emulate_instruction(vcpu, EMULTYPE_PVM_GP);
		if (!err)
			return 0;

		if (vcpu->arch.halt_request) {
			vcpu->arch.halt_request = 0;
			return kvm_emulate_halt_noskip(vcpu);
		}
		return 1;
	case UD_VECTOR:
		if (!is_smod(pvm)) {
			kvm_queue_exception(vcpu, UD_VECTOR);
			return 1;
		}
		return handle_ud(vcpu);
	case DB_VECTOR:
		return handle_exit_debug(vcpu);
	case BP_VECTOR:
		return handle_exit_breakpoint(vcpu);

	// #DE, #OF, #BR, #NM, #MF, #XM, #TS, #NP, #SS and #AC are pure guest
	// exceptions.
	case DE_VECTOR:
	case OF_VECTOR:
	case BR_VECTOR:
	case NM_VECTOR:
	case MF_VECTOR:
	case XM_VECTOR:
		kvm_queue_exception(vcpu, vector);
		return 1;
	case AC_VECTOR:
	case TS_VECTOR:
	case NP_VECTOR:
	case SS_VECTOR:
		kvm_queue_exception_e(vcpu, vector, error_code);
		return 1;

	// #NMI, #VE, #VC, #MC and #DF are exceptions that belong to host.
	// They should have been handled in atomic way when vmexit.
	case NMI_VECTOR:
		// NMI is handled by pvm_vcpu_run_noinstr().
		return 1;
	case VE_VECTOR:
		// TODO: tdx_handle_virt_exception(regs, &pvm->exit_ve); break;
		goto unknown_exit_reason;
	case X86_TRAP_VC:
		// TODO: handle the second part for #VC.
		goto unknown_exit_reason;
	case MC_VECTOR:
		// MC is handled by pvm_handle_exit_irqoff().
		// TODO: split kvm_machine_check() to avoid irq-enabled or
		// schedule code (thread dead) in pvm_handle_exit_irqoff().
		return 1;
	case DF_VECTOR:
		// DF is handled when exiting and can't reach here.
		pr_warn_once("host bug, can't reach here");
		break;
	default:
unknown_exit_reason:
		pr_warn_once("unknown exit_reason vector:%d, error_code:%x, rip:0x%lx\n",
			      vector, pvm->exit_error_code, kvm_rip_read(vcpu));
		kvm_run->exit_reason = KVM_EXIT_EXCEPTION;
		kvm_run->ex.exception = vector;
		kvm_run->ex.error_code = error_code;
		break;
	}
	return 0;
}

static int handle_exit_external_interrupt(struct kvm_vcpu *vcpu)
{
	++vcpu->stat.irq_exits;
	return 1;
}

static int handle_exit_failed_vmentry(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	u32 error_code = pvm->exit_error_code;

	kvm_queue_exception_e(vcpu, GP_VECTOR, error_code);
	return 1;
}

/*
 * The guest has exited.  See if we can fix it or if we need userspace
 * assistance.
 */
static int pvm_handle_exit(struct kvm_vcpu *vcpu, fastpath_t exit_fastpath)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	u32 exit_reason = pvm->exit_vector;

	if (exit_reason == PVM_SYSCALL_VECTOR)
		return handle_exit_syscall(vcpu);
	else if (exit_reason >= 0 && exit_reason < FIRST_EXTERNAL_VECTOR)
		return handle_exit_exception(vcpu);
	else if (exit_reason == IA32_SYSCALL_VECTOR)
		return do_pvm_event(vcpu, IA32_SYSCALL_VECTOR, false, 0);
	else if (exit_reason >= FIRST_EXTERNAL_VECTOR && exit_reason < NR_VECTORS)
		return handle_exit_external_interrupt(vcpu);
	else if (exit_reason == PVM_FAILED_VMENTRY_VECTOR)
		return handle_exit_failed_vmentry(vcpu);

	vcpu_unimpl(vcpu, "pvm: unexpected exit reason 0x%x\n", exit_reason);
	vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
	vcpu->run->internal.suberror =
		KVM_INTERNAL_ERROR_UNEXPECTED_EXIT_REASON;
	vcpu->run->internal.ndata = 2;
	vcpu->run->internal.data[0] = exit_reason;
	vcpu->run->internal.data[1] = vcpu->arch.last_vmentry_cpu;
	return 0;
}

static void pvm_handle_exit_irqoff(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	u32 vector = pvm->exit_vector;
	gate_desc *desc = (gate_desc *)host_idt_base + vector;

	if (vector >= FIRST_EXTERNAL_VECTOR && vector < NR_VECTORS &&
	    vector != IA32_SYSCALL_VECTOR)
		kvm_do_interrupt_irqoff(vcpu, gate_offset(desc));
	else if (vector == MC_VECTOR)
		kvm_machine_check();
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

static int pvm_vcpu_pre_run(struct kvm_vcpu *vcpu)
{
	return 1;
}

static void pvm_sync_dirty_debug_regs(struct kvm_vcpu *vcpu)
{
	WARN_ONCE(1, "pvm never sets KVM_DEBUGREG_WONT_EXIT\n");
}

static void pvm_set_dr7(struct kvm_vcpu *vcpu, unsigned long val)
{
	to_pvm(vcpu)->guest_dr7 = val;
}

static __always_inline unsigned long __dr7_enable_mask(int drnum)
{
	unsigned long bp_mask = 0;

	bp_mask |= (DR_LOCAL_ENABLE << (drnum * DR_ENABLE_SIZE));
	bp_mask |= (DR_GLOBAL_ENABLE << (drnum * DR_ENABLE_SIZE));

	return bp_mask;
}

static __always_inline unsigned long __dr7_mask(int drnum)
{
	unsigned long bp_mask = 0xf;

	bp_mask <<= (DR_CONTROL_SHIFT + drnum * DR_CONTROL_SIZE);
	bp_mask |= __dr7_enable_mask(drnum);

	return bp_mask;
}

/*
 * Calculate the correct dr7 for the hardware to avoid the host
 * being watched.
 *
 * It only needs to be calculated each time when vcpu->arch.eff_db or
 * pvm->guest_dr7 is changed.  But now it is calculated each time on
 * VM-enter since there is no proper callback for vcpu->arch.eff_db and
 * it is slow path.
 */
static __always_inline unsigned long pvm_eff_dr7(struct kvm_vcpu *vcpu)
{
	unsigned long eff_dr7 = to_pvm(vcpu)->guest_dr7;
	int i;

	/*
	 * DR7_GD should not be set to hardware. And it doesn't need to be
	 * set to hardware since PVM guest is running on hardware ring3.
	 * All access to debug registers will be trapped and the emulation
	 * code can handle DR7_GD correctly for PVM.
	 */
	eff_dr7 &= ~DR7_GD;

	/*
	 * Disallow addresses that are not for the guest, especially addresses
	 * on the host entry code.
	 */
	for (i = 0; i < KVM_NR_DB_REGS; i++) {
		if (!pvm_guest_allowed_va(vcpu, vcpu->arch.eff_db[i]))
			eff_dr7 &= ~__dr7_mask(i);
		if (!pvm_guest_allowed_va(vcpu, vcpu->arch.eff_db[i] + 7))
			eff_dr7 &= ~__dr7_mask(i);
	}

	return eff_dr7;
}

// Save guest registers from host sp0 or IST stack.
static __always_inline void save_regs(struct kvm_vcpu *vcpu, struct pt_regs *guest)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	vcpu->arch.regs[VCPU_REGS_RAX] = guest->ax;
	vcpu->arch.regs[VCPU_REGS_RCX] = guest->cx;
	vcpu->arch.regs[VCPU_REGS_RDX] = guest->dx;
	vcpu->arch.regs[VCPU_REGS_RBX] = guest->bx;
	vcpu->arch.regs[VCPU_REGS_RSP] = guest->sp;
	vcpu->arch.regs[VCPU_REGS_RBP] = guest->bp;
	vcpu->arch.regs[VCPU_REGS_RSI] = guest->si;
	vcpu->arch.regs[VCPU_REGS_RDI] = guest->di;
	vcpu->arch.regs[VCPU_REGS_R8] = guest->r8;
	vcpu->arch.regs[VCPU_REGS_R9] = guest->r9;
	vcpu->arch.regs[VCPU_REGS_R10] = guest->r10;
	vcpu->arch.regs[VCPU_REGS_R11] = guest->r11;
	vcpu->arch.regs[VCPU_REGS_R12] = guest->r12;
	vcpu->arch.regs[VCPU_REGS_R13] = guest->r13;
	vcpu->arch.regs[VCPU_REGS_R14] = guest->r14;
	vcpu->arch.regs[VCPU_REGS_R15] = guest->r15;
	vcpu->arch.regs[VCPU_REGS_RIP] = guest->ip;
	pvm->rflags = guest->flags;
	pvm->hw_cs = guest->cs;
	pvm->hw_ss = guest->ss;
}

// load guest registers to host sp0 stack.
static __always_inline void load_regs(struct kvm_vcpu *vcpu, struct pt_regs *guest)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	guest->ss = pvm->hw_ss;
	guest->sp = vcpu->arch.regs[VCPU_REGS_RSP];
	guest->flags = (pvm->rflags & SWITCH_ENTER_EFLAGS_ALLOWED) | SWITCH_ENTER_EFLAGS_FIXED;
	guest->cs = pvm->hw_cs;
	guest->ip = vcpu->arch.regs[VCPU_REGS_RIP];
	guest->orig_ax = -1;
	guest->di = vcpu->arch.regs[VCPU_REGS_RDI];
	guest->si = vcpu->arch.regs[VCPU_REGS_RSI];
	guest->dx = vcpu->arch.regs[VCPU_REGS_RDX];
	guest->cx = vcpu->arch.regs[VCPU_REGS_RCX];
	guest->ax = vcpu->arch.regs[VCPU_REGS_RAX];
	guest->r8 = vcpu->arch.regs[VCPU_REGS_R8];
	guest->r9 = vcpu->arch.regs[VCPU_REGS_R9];
	guest->r10 = vcpu->arch.regs[VCPU_REGS_R10];
	guest->r11 = vcpu->arch.regs[VCPU_REGS_R11];
	guest->bx = vcpu->arch.regs[VCPU_REGS_RBX];
	guest->bp = vcpu->arch.regs[VCPU_REGS_RBP];
	guest->r12 = vcpu->arch.regs[VCPU_REGS_R12];
	guest->r13 = vcpu->arch.regs[VCPU_REGS_R13];
	guest->r14 = vcpu->arch.regs[VCPU_REGS_R14];
	guest->r15 = vcpu->arch.regs[VCPU_REGS_R15];
}

static noinstr void pvm_vcpu_run_noinstr(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	struct pt_regs *sp0_regs = (struct pt_regs *)this_cpu_read(cpu_tss_rw.x86_tss.sp0) - 1;
	struct pt_regs *ret_regs;

	guest_state_enter_irqoff();

	// Load guest registers into the host sp0 stack for switcher.
	load_regs(vcpu, sp0_regs);

	if (unlikely(pvm->guest_dr7 & DR7_BP_EN_MASK))
		set_debugreg(pvm_eff_dr7(vcpu), 7);

	// Call into switcher and enter guest.
	ret_regs = switcher_enter_guest();

	// Get the guest registers from the host sp0 stack.
	save_regs(vcpu, ret_regs);
	pvm->exit_vector = (ret_regs->orig_ax >> 32);
	pvm->exit_error_code = (u32)ret_regs->orig_ax;

	// dr7 requires to be zero when the controling of debug registers
	// passes back to the host.
	if (unlikely(pvm->guest_dr7 & DR7_BP_EN_MASK))
		set_debugreg(0, 7);

	// handle noinstr vmexits reasons.
	switch (pvm->exit_vector) {
	case PF_VECTOR:
		// if the exit due to #PF, check for async #PF.
		pvm->exit_cr2 = read_cr2();
		vcpu->arch.apf.host_apf_flags = kvm_read_and_reset_apf_flags();
		break;
	case NMI_VECTOR:
		kvm_do_nmi_irqoff(vcpu);
		break;
	case VE_VECTOR:
		// TODO: pvm host is TDX guest.
		// tdx_get_ve_info(&pvm->host_ve);
		break;
	case X86_TRAP_VC:
		/*
		 * TODO: pvm host is SEV guest.
		 * if (!vc_is_db(error_code)) {
		 *      collect info and handle the first part for #VC
		 *      break;
		 * } else {
		 *      get_debugreg(pvm->exit_dr6, 6);
		 *      set_debugreg(DR6_RESERVED, 6);
		 * }
		 */
		break;
	case DB_VECTOR:
		get_debugreg(pvm->exit_dr6, 6);
		set_debugreg(DR6_RESERVED, 6);
		break;
	default:
		break;
	}

	guest_state_exit_irqoff();
}

/*
 * PVM wrappers for kvm_load_{guest|host}_xsave_state().
 *
 * Currently PKU is disabled for shadowpaging and to avoid overhead,
 * host CR4.PKE is unchanged for entering/exiting guest even when
 * host CR4.PKE is enabled.
 *
 * These wrappers fix pkru when host CR4.PKE is enabled.
 */
static inline void pvm_load_guest_xsave_state(struct kvm_vcpu *vcpu)
{
	kvm_load_guest_xsave_state(vcpu);

	if (cpu_feature_enabled(X86_FEATURE_PKU)) {
		if (vcpu->arch.host_pkru)
			write_pkru(0);
	}
}

static inline void pvm_load_host_xsave_state(struct kvm_vcpu *vcpu)
{
	kvm_load_host_xsave_state(vcpu);

	if (cpu_feature_enabled(X86_FEATURE_PKU)) {
		if (rdpkru() != vcpu->arch.host_pkru)
			write_pkru(vcpu->arch.host_pkru);
	}
}

static fastpath_t pvm_vcpu_run(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	trace_kvm_entry(vcpu);

	pvm_load_guest_xsave_state(vcpu);

	kvm_wait_lapic_expire(vcpu);

	pvm_set_host_cr3(pvm);

	if (pvm->host_debugctlmsr)
		update_debugctlmsr(0);

	pvm_vcpu_run_noinstr(vcpu);

	/* MSR_IA32_DEBUGCTLMSR is zeroed before vmenter. Restore it if needed */
	if (pvm->host_debugctlmsr)
		update_debugctlmsr(pvm->host_debugctlmsr);

	if (is_smod(pvm)) {
		struct pvm_vcpu_struct *pvcs = pvm->pvcs_gpc.khva;

		/*
		 * Load the X86_EFLAGS_IF bit from PVCS. In user mode, the
		 * Interrupt Flag is considered to be set and cannot be
		 * changed. Since it is already set in 'pvm->rflags', so
		 * nothing to do. In supervisor mode, the Interrupt Flag is
		 * reflected in 'pvcs->event_flags' and can be changed
		 * directly without triggering a VM exit.
		 */
		pvm->rflags &= ~X86_EFLAGS_IF;
		if (likely(pvm->msr_vcpu_struct))
			pvm->rflags |= X86_EFLAGS_IF & pvcs->event_flags;

		if (pvm->hw_cs != __USER_CS || pvm->hw_ss != __USER_DS)
			kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
	}

	pvm_load_host_xsave_state(vcpu);

	mark_page_dirty_in_slot(vcpu->kvm, pvm->pvcs_gpc.memslot,
				pvm->pvcs_gpc.gpa >> PAGE_SHIFT);

	return EXIT_FASTPATH_NONE;
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

	pvm_switch_to_host(pvm);

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
	pvm_set_default_msr_linear_address_range(pvm);
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

#ifdef CONFIG_KVM_SMM
static int pvm_smi_allowed(struct kvm_vcpu *vcpu, bool for_injection)
{
	return 0;
}

static int pvm_enter_smm(struct kvm_vcpu *vcpu, union kvm_smram *smram)
{
	return 0;
}

static int pvm_leave_smm(struct kvm_vcpu *vcpu, const union kvm_smram *smram)
{
	return 0;
}

static void enable_smi_window(struct kvm_vcpu *vcpu)
{
}
#endif

/*
 * When in PVM mode, the hardware MSR_LSTAR is set to the entry point
 * provided by the host entry code (switcher), and the
 * hypervisor can also change the hardware MSR_TSC_AUX to emulate
 * the guest MSR_TSC_AUX.
 */
static __init void pvm_setup_user_return_msrs(void)
{
	kvm_add_user_return_msr(MSR_LSTAR);
	kvm_add_user_return_msr(MSR_TSC_AUX);
	if (ia32_enabled()) {
		if (is_intel)
			kvm_add_user_return_msr(MSR_IA32_SYSENTER_CS);
		else
			kvm_add_user_return_msr(MSR_CSTAR);
	}
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

	pvm_setup_user_return_msrs();

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

	.prepare_switch_to_guest = pvm_prepare_switch_to_guest,
	.vcpu_load = pvm_vcpu_load,
	.vcpu_put = pvm_vcpu_put,

	.update_exception_bitmap = update_exception_bitmap,
	.get_msr_feature = pvm_get_msr_feature,
	.get_msr = pvm_get_msr,
	.set_msr = pvm_set_msr,
	.get_segment_base = pvm_get_segment_base,
	.get_segment = pvm_get_segment,
	.set_segment = pvm_set_segment,
	.get_cpl = pvm_get_cpl,
	.get_cs_db_l_bits = pvm_get_cs_db_l_bits,
	.load_mmu_pgd = pvm_load_mmu_pgd,
	.get_gdt = pvm_get_gdt,
	.set_gdt = pvm_set_gdt,
	.get_idt = pvm_get_idt,
	.set_idt = pvm_set_idt,
	.set_dr7 = pvm_set_dr7,
	.sync_dirty_debug_regs = pvm_sync_dirty_debug_regs,
	.get_rflags = pvm_get_rflags,
	.set_rflags = pvm_set_rflags,
	.get_if_flag = pvm_get_if_flag,

	.vcpu_pre_run = pvm_vcpu_pre_run,
	.vcpu_run = pvm_vcpu_run,
	.handle_exit = pvm_handle_exit,
	.skip_emulated_instruction = skip_emulated_instruction,
	.set_interrupt_shadow = pvm_set_interrupt_shadow,
	.get_interrupt_shadow = pvm_get_interrupt_shadow,
	.patch_hypercall = pvm_patch_hypercall,
	.inject_irq = pvm_inject_irq,
	.inject_nmi = pvm_inject_nmi,
	.inject_exception = pvm_inject_exception,
	.cancel_injection = pvm_cancel_injection,
	.interrupt_allowed = pvm_interrupt_allowed,
	.nmi_allowed = pvm_nmi_allowed,
	.get_nmi_mask = pvm_get_nmi_mask,
	.set_nmi_mask = pvm_set_nmi_mask,
	.enable_nmi_window = enable_nmi_window,
	.enable_irq_window = enable_irq_window,
	.refresh_apicv_exec_ctrl = pvm_refresh_apicv_exec_ctrl,
	.deliver_interrupt = pvm_deliver_interrupt,

	.vcpu_after_set_cpuid = pvm_vcpu_after_set_cpuid,

	.check_intercept = pvm_check_intercept,
	.handle_exit_irqoff = pvm_handle_exit_irqoff,

	.request_immediate_exit = __kvm_request_immediate_exit,

	.sched_in = pvm_sched_in,

	.nested_ops = &pvm_nested_ops,

	.setup_mce = pvm_setup_mce,

#ifdef CONFIG_KVM_SMM
	.smi_allowed = pvm_smi_allowed,
	.enter_smm = pvm_enter_smm,
	.leave_smm = pvm_leave_smm,
	.enable_smi_window = enable_smi_window,
#endif

	.apic_init_signal_blocked = pvm_apic_init_signal_blocked,
	.msr_filter_changed = pvm_msr_filter_changed,
	.complete_emulated_msr = kvm_complete_insn_gp,
	.vcpu_deliver_sipi_vector = kvm_vcpu_deliver_sipi_vector,

	.check_emulate_instruction = pvm_check_emulate_instruction,
	.disallowed_va = pvm_disallowed_va,
	.vcpu_gpc_refresh = pvm_vcpu_gpc_refresh,
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
