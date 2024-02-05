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
	default:
		ret = kvm_set_msr_common(vcpu, msr_info);
	}

	return ret;
}

static int pvm_get_cpl(struct kvm_vcpu *vcpu)
{
	if (is_smod(to_pvm(vcpu)))
		return 0;
	return 3;
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

static void pvm_setup_mce(struct kvm_vcpu *vcpu)
{
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

	if (exit_reason >= FIRST_EXTERNAL_VECTOR && exit_reason < NR_VECTORS)
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

	// Call into switcher and enter guest.
	ret_regs = switcher_enter_guest();

	// Get the guest registers from the host sp0 stack.
	save_regs(vcpu, ret_regs);
	pvm->exit_vector = (ret_regs->orig_ax >> 32);
	pvm->exit_error_code = (u32)ret_regs->orig_ax;

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

	pvm_vcpu_run_noinstr(vcpu);

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

	.get_msr_feature = pvm_get_msr_feature,
	.get_msr = pvm_get_msr,
	.set_msr = pvm_set_msr,
	.get_cpl = pvm_get_cpl,
	.load_mmu_pgd = pvm_load_mmu_pgd,
	.get_rflags = pvm_get_rflags,
	.set_rflags = pvm_set_rflags,
	.get_if_flag = pvm_get_if_flag,

	.vcpu_pre_run = pvm_vcpu_pre_run,
	.vcpu_run = pvm_vcpu_run,
	.handle_exit = pvm_handle_exit,
	.set_interrupt_shadow = pvm_set_interrupt_shadow,
	.get_interrupt_shadow = pvm_get_interrupt_shadow,
	.interrupt_allowed = pvm_interrupt_allowed,
	.nmi_allowed = pvm_nmi_allowed,
	.get_nmi_mask = pvm_get_nmi_mask,
	.set_nmi_mask = pvm_set_nmi_mask,
	.enable_nmi_window = enable_nmi_window,
	.enable_irq_window = enable_irq_window,
	.refresh_apicv_exec_ctrl = pvm_refresh_apicv_exec_ctrl,
	.deliver_interrupt = pvm_deliver_interrupt,

	.vcpu_after_set_cpuid = pvm_vcpu_after_set_cpuid,

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
