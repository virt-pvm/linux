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
#include <linux/entry-kvm.h>

#include <asm/gsseg.h>
#include <asm/io_bitmap.h>
#include <asm/pvm_para.h>
#include <asm/mmu_context.h>

#include "cpuid.h"
#include "lapic.h"
#include "mmu.h"
#include "pmu.h"
#include "trace.h"
#include "x86.h"
#include "pvm.h"

MODULE_AUTHOR("AntGroup");
MODULE_LICENSE("GPL");

static bool __read_mostly enable_cpuid_intercept = 0;
module_param_named(cpuid_intercept, enable_cpuid_intercept, bool, 0444);

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

	if ((s64)va >= 0)
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

static void __set_cpuid_faulting(bool on)
{
	u64 msrval;

	rdmsrl_safe(MSR_MISC_FEATURES_ENABLES, &msrval);
	msrval &= ~MSR_MISC_FEATURES_ENABLES_CPUID_FAULT;
	msrval |= (on << MSR_MISC_FEATURES_ENABLES_CPUID_FAULT_BIT);
	wrmsrl(MSR_MISC_FEATURES_ENABLES, msrval);
}

static void reset_cpuid_intercept(struct kvm_vcpu *vcpu)
{
	if (test_thread_flag(TIF_NOCPUID))
		return;

	if (enable_cpuid_intercept || cpuid_fault_enabled(vcpu))
		__set_cpuid_faulting(false);
}

static void set_cpuid_intercept(struct kvm_vcpu *vcpu)
{
	if (test_thread_flag(TIF_NOCPUID))
		return;

	if (enable_cpuid_intercept || cpuid_fault_enabled(vcpu))
		__set_cpuid_faulting(true);
}

static void pvm_update_guest_cpuid_faulting(struct kvm_vcpu *vcpu, u64 data)
{
	bool guest_enabled = cpuid_fault_enabled(vcpu);
	bool set_enabled = data & MSR_MISC_FEATURES_ENABLES_CPUID_FAULT;
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	if (!(guest_enabled ^ set_enabled))
		return;
	if (enable_cpuid_intercept)
		return;
	if (test_thread_flag(TIF_NOCPUID))
		return;

	preempt_disable();
	if (pvm->loaded_cpu_state)
		__set_cpuid_faulting(set_enabled);
	preempt_enable();
}

/*
 * Non-PVM mode is not a part of PVM.  Basic support for it via emulation.
 * Non-PVM mode is required for booting the guest and bringing up vCPUs so far.
 *
 * In future, when VMM can directly boot the guest and bring vCPUs up from
 * 64-bit mode without any help from non-64-bit mode, then the support non-PVM
 * mode will be removed.
 */
#define CONVERT_TO_PVM_CR0_OFF	(X86_CR0_NW | X86_CR0_CD)
#define CONVERT_TO_PVM_CR0_ON	(X86_CR0_NE | X86_CR0_AM | X86_CR0_WP | \
				 X86_CR0_PG | X86_CR0_PE)

static inline void pvm_standard_msr_star(struct vcpu_pvm *pvm)
{
	pvm->msr_star = ((u64)pvm->segments[VCPU_SREG_CS].selector << 32) |
			((u64)__USER32_CS << 48);
}

static bool try_to_convert_to_pvm_mode(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	unsigned long cr0 = vcpu->arch.cr0;

	if (!is_long_mode(vcpu))
		return false;
	if (!pvm->segments[VCPU_SREG_CS].l) {
		if (is_smod(pvm))
			return false;
		if (!pvm->segments[VCPU_SREG_CS].db)
			return false;
	}

	/* Atomically set EFER_SCE converting to PVM mode. */
	if ((vcpu->arch.efer | EFER_SCE) != vcpu->arch.efer)
		vcpu->arch.efer |= EFER_SCE;

	/* Change CR0 on converting to PVM mode. */
	cr0 &= ~CONVERT_TO_PVM_CR0_OFF;
	cr0 |= CONVERT_TO_PVM_CR0_ON;
	if (cr0 != vcpu->arch.cr0)
		kvm_set_cr0(vcpu, cr0);

	/*
	 * Atomically set MSR_STAR when switching to PVM mode if the guest is
	 * in supervisor mode. In the case of user mode, the MSR_STAR should be
	 * set using MSR setting during the VM migration.
	 */
	if (is_smod(pvm))
		pvm_standard_msr_star(pvm);

	pvm->non_pvm_mode = false;

	return true;
}

static int handle_non_pvm_mode(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	int ret = 1;
	unsigned int count = 130;

	if (try_to_convert_to_pvm_mode(vcpu))
		return 1;

	while (pvm->non_pvm_mode && count-- != 0) {
		if (kvm_test_request(KVM_REQ_EVENT, vcpu))
			return 1;

		if (try_to_convert_to_pvm_mode(vcpu))
			return 1;

		ret = kvm_emulate_instruction(vcpu, 0);

		if (!ret)
			goto out;

		/* don't do mode switch in emulation */
		if (!is_smod(pvm))
			goto emulation_error;

		if (vcpu->arch.exception.pending)
			goto emulation_error;

		if (vcpu->arch.halt_request) {
			vcpu->arch.halt_request = 0;
			ret = kvm_emulate_halt_noskip(vcpu);
			goto out;
		}
		/*
		 * Note, return 1 and not 0, vcpu_run() will invoke
		 * xfer_to_guest_mode() which will create a proper return
		 * code.
		 */
		if (__xfer_to_guest_mode_work_pending())
			return 1;
	}

out:
	return ret;

emulation_error:
	vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
	vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_EMULATION;
	vcpu->run->internal.ndata = 0;
	return 0;
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

/*
 * Load guest TLS entries into the GDT.
 */
static inline void host_gdt_set_tls(struct vcpu_pvm *pvm)
{
	struct desc_struct *gdt = get_current_gdt_rw();
	unsigned int i;

	for (i = 0; i < GDT_ENTRY_TLS_ENTRIES; i++)
		gdt[GDT_ENTRY_TLS_MIN + i] = pvm->tls_array[i];
}

/*
 * Load current task's TLS into the GDT.
 */
static inline void host_gdt_restore_tls(void)
{
	native_load_tls(&current->thread, smp_processor_id());
}

static void pvm_prepare_switch_to_guest(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	if (pvm->loaded_cpu_state)
		return;

	// we can't load guest state to hardware when guest is not on long mode
	if (unlikely(pvm->non_pvm_mode))
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

	host_gdt_set_tls(pvm);

#ifdef CONFIG_MODIFY_LDT_SYSCALL
	/* PVM doesn't support LDT. */
	if (unlikely(current->mm->context.ldt))
		clear_LDT();
#endif

	segments_save_host_and_switch_to_guest(pvm);

	set_cpuid_intercept(vcpu);

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

	reset_cpuid_intercept(&pvm->vcpu);

#ifdef CONFIG_MODIFY_LDT_SYSCALL
	if (unlikely(current->mm->context.ldt))
		kvm_load_ldt(GDT_ENTRY_LDT*8);
#endif

	host_gdt_restore_tls();

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

struct host_pcid_one {
	/*
	 * It is struct vcpu_pvm *pvm, but it is not allowed to be
	 * dereferenced since it might be freed.
	 */
	void *pvm;
	u64 root_hpa;
};

struct host_pcid_state {
	struct host_pcid_one pairs[NUM_HOST_PCID_FOR_GUEST];
	int evict_next_round_robin;
};

static DEFINE_PER_CPU(struct host_pcid_state, pvm_tlb_state);

static void host_pcid_flush_all(struct vcpu_pvm *pvm)
{
	struct host_pcid_state *tlb_state = this_cpu_ptr(&pvm_tlb_state);
	int i;

	for (i = 0; i < NUM_HOST_PCID_FOR_GUEST; i++) {
		if (tlb_state->pairs[i].pvm == pvm)
			tlb_state->pairs[i].pvm = NULL;
	}
}

static inline unsigned int host_pcid_to_index(unsigned int host_pcid)
{
	return host_pcid & ~HOST_PCID_TAG_FOR_GUEST;
}

static inline int index_to_host_pcid(int index)
{
	return index | HOST_PCID_TAG_FOR_GUEST;
}

/*
 * Free the uncached guest pcid (not in mmu->root nor mmu->prev_root), so
 * that the next allocation would not evict a clean one.
 *
 * It would be better if kvm.ko notifies us when a root_pgd is freed
 * from the cache.
 *
 * Returns a freed index or -1 if nothing is freed.
 */
static int host_pcid_free_uncached(struct vcpu_pvm *pvm)
{
	/* It is allowed to do nothing. */
	return -1;
}

/*
 * Get a host pcid of the current pCPU for the specific guest pgd.
 * PVM vTLB is guest pgd tagged.
 */
static int host_pcid_get(struct vcpu_pvm *pvm, u64 root_hpa, bool *flush)
{
	struct host_pcid_state *tlb_state = this_cpu_ptr(&pvm_tlb_state);
	int i, j = -1;

	/* find if it is allocated. */
	for (i = 0; i < NUM_HOST_PCID_FOR_GUEST; i++) {
		struct host_pcid_one *tlb = &tlb_state->pairs[i];

		if (tlb->root_hpa == root_hpa && tlb->pvm == pvm)
			return index_to_host_pcid(i);

		/* if it has no owner, allocate it if not found. */
		if (!tlb->pvm)
			j = i;
	}

	/*
	 * Fallback to:
	 *    use the fallback recorded in the above loop.
	 *    use a freed uncached.
	 *    evict one (which might be still usable) by round-robin policy.
	 */
	if (j < 0)
		j = host_pcid_free_uncached(pvm);
	if (j < 0) {
		j = tlb_state->evict_next_round_robin;
		if (++tlb_state->evict_next_round_robin == NUM_HOST_PCID_FOR_GUEST)
			tlb_state->evict_next_round_robin = 0;
	}

	/* associate the host pcid to the guest */
	tlb_state->pairs[j].pvm = pvm;
	tlb_state->pairs[j].root_hpa = root_hpa;

	*flush = true;
	return index_to_host_pcid(j);
}

static void host_pcid_free(struct vcpu_pvm *pvm, u64 root_hpa)
{
	struct host_pcid_state *tlb_state = this_cpu_ptr(&pvm_tlb_state);
	int i;

	for (i = 0; i < NUM_HOST_PCID_FOR_GUEST; i++) {
		struct host_pcid_one *tlb = &tlb_state->pairs[i];

		if (tlb->root_hpa == root_hpa && tlb->pvm == pvm) {
			tlb->pvm = NULL;
			return;
		}
	}
}

static inline void *host_pcid_owner(int host_pcid)
{
	return this_cpu_read(pvm_tlb_state.pairs[host_pcid_to_index(host_pcid)].pvm);
}

static inline u64 host_pcid_root(int host_pcid)
{
	return this_cpu_read(pvm_tlb_state.pairs[host_pcid_to_index(host_pcid)].root_hpa);
}

static void __pvm_hwtlb_flush_all(struct vcpu_pvm *pvm)
{
	if (static_cpu_has(X86_FEATURE_PCID))
		host_pcid_flush_all(pvm);
}

static void pvm_flush_hwtlb(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	get_cpu();
	__pvm_hwtlb_flush_all(pvm);
	put_cpu();
}

static void pvm_flush_hwtlb_guest(struct kvm_vcpu *vcpu)
{
	/*
	 * flushing hwtlb for guest only when:
	 *	change to the shadow page table.
	 *	reused an used (guest) pcid.
	 * change to the shadow page table always results flushing hwtlb
	 * and PVM uses pgd tagged tlb.
	 *
	 * So no hwtlb needs to be flushed here.
	 */
}

static void pvm_flush_hwtlb_current(struct kvm_vcpu *vcpu)
{
	/* No flush required if the current context is invalid. */
	if (!VALID_PAGE(vcpu->arch.mmu->root.hpa))
		return;

	if (static_cpu_has(X86_FEATURE_PCID)) {
		get_cpu();
		host_pcid_free(to_pvm(vcpu), vcpu->arch.mmu->root.hpa);
		put_cpu();
	}
}

static void pvm_flush_hwtlb_gva(struct kvm_vcpu *vcpu, gva_t addr)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	int max = MIN_HOST_PCID_FOR_GUEST + NUM_HOST_PCID_FOR_GUEST;
	int i;

	if (!static_cpu_has(X86_FEATURE_PCID))
		return;

	get_cpu();
	if (!this_cpu_has(X86_FEATURE_INVPCID)) {
		host_pcid_flush_all(pvm);
		put_cpu();
		return;
	}

	host_pcid_free_uncached(pvm);
	for (i = MIN_HOST_PCID_FOR_GUEST; i < max; i++) {
		if (host_pcid_owner(i) == pvm)
			invpcid_flush_one(i, addr);
	}

	put_cpu();
}

static bool check_switch_cr3(struct vcpu_pvm *pvm, u64 switch_host_cr3)
{
	u64 root = pvm->vcpu.arch.mmu->prev_roots[0].hpa;

	if (pvm->vcpu.arch.mmu->prev_roots[0].pgd != pvm->msr_switch_cr3)
		return false;
	if (!VALID_PAGE(root))
		return false;
	if (host_pcid_owner(switch_host_cr3 & X86_CR3_PCID_MASK) != pvm)
		return false;
	if (host_pcid_root(switch_host_cr3 & X86_CR3_PCID_MASK) != root)
		return false;
	if (root != (switch_host_cr3 & CR3_ADDR_MASK))
		return false;

	return true;
}

static void pvm_set_host_cr3_for_guest_with_host_pcid(struct vcpu_pvm *pvm)
{
	u64 root_hpa = pvm->vcpu.arch.mmu->root.hpa;
	bool flush = false;
	u32 host_pcid = host_pcid_get(pvm, root_hpa, &flush);
	u64 hw_cr3 = root_hpa | host_pcid;
	u64 switch_host_cr3;

	if (!flush)
		hw_cr3 |= CR3_NOFLUSH;
	this_cpu_write(cpu_tss_rw.tss_ex.enter_cr3, hw_cr3);

	if (is_smod(pvm)) {
		this_cpu_write(cpu_tss_rw.tss_ex.smod_cr3, hw_cr3 | CR3_NOFLUSH);
		switch_host_cr3 = this_cpu_read(cpu_tss_rw.tss_ex.umod_cr3);
	} else {
		this_cpu_write(cpu_tss_rw.tss_ex.umod_cr3, hw_cr3 | CR3_NOFLUSH);
		switch_host_cr3 = this_cpu_read(cpu_tss_rw.tss_ex.smod_cr3);
	}

	if (check_switch_cr3(pvm, switch_host_cr3))
		pvm->switch_flags &= ~SWITCH_FLAGS_NO_DS_CR3;
	else
		pvm->switch_flags |= SWITCH_FLAGS_NO_DS_CR3;
}

static void pvm_set_host_cr3_for_guest_without_host_pcid(struct vcpu_pvm *pvm)
{
	u64 root_hpa = pvm->vcpu.arch.mmu->root.hpa;
	u64 switch_root = 0;
	u64 prev_root_hpa = pvm->vcpu.arch.mmu->prev_roots[0].hpa;

	if (VALID_PAGE(prev_root_hpa) &&
	    pvm->vcpu.arch.mmu->prev_roots[0].pgd == pvm->msr_switch_cr3) {
		switch_root = prev_root_hpa;
		pvm->switch_flags &= ~SWITCH_FLAGS_NO_DS_CR3;
	} else {
		pvm->switch_flags |= SWITCH_FLAGS_NO_DS_CR3;
	}

	this_cpu_write(cpu_tss_rw.tss_ex.enter_cr3, root_hpa);
	if (is_smod(pvm)) {
		this_cpu_write(cpu_tss_rw.tss_ex.smod_cr3, root_hpa);
		this_cpu_write(cpu_tss_rw.tss_ex.umod_cr3, switch_root);
	} else {
		this_cpu_write(cpu_tss_rw.tss_ex.umod_cr3, root_hpa);
		this_cpu_write(cpu_tss_rw.tss_ex.smod_cr3, switch_root);
	}
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
// Set tss_ex.smod_cr3 and tss_ex.umod_cr3 and set or clear
// SWITCH_FLAGS_NO_DS_CR3 for direct switching.
static void pvm_set_host_cr3(struct vcpu_pvm *pvm)
{
	pvm_set_host_cr3_for_hypervisor(pvm);

	if (static_cpu_has(X86_FEATURE_PCID))
		pvm_set_host_cr3_for_guest_with_host_pcid(pvm);
	else
		pvm_set_host_cr3_for_guest_without_host_pcid(pvm);
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

	if (vcpu->cpu != cpu)
		__pvm_hwtlb_flush_all(pvm);

	indirect_branch_prediction_barrier();
}

static void pvm_vcpu_put(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	host_pcid_free_uncached(pvm);
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

static u64 pvm_get_l2_tsc_offset(struct kvm_vcpu *vcpu)
{
	return 0;
}

static u64 pvm_get_l2_tsc_multiplier(struct kvm_vcpu *vcpu)
{
	return 0;
}

static void pvm_write_tsc_offset(struct kvm_vcpu *vcpu)
{
	// TODO: add proper ABI and make guest use host TSC
	vcpu->arch.tsc_offset = 0;
	vcpu->arch.l1_tsc_offset = 0;
}

static void pvm_write_tsc_multiplier(struct kvm_vcpu *vcpu)
{
	// TODO: add proper ABI and make guest use host TSC
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

	if (!msr) {
		pvm_set_default_msr_linear_address_range(pvm);
		return true;
	}

	/* PVM specification requires those bits to be all set. */
	if ((msr & 0xff00ff00ff00ff00) != 0xff00ff00ff00ff00)
		return false;

	if (pml4_i_s > pml4_i_e || pml5_i_s > pml5_i_e)
		return false;

	/*
	 * PVM specification requires the index to be set as '0x1ff' if the
	 * size of range is 0.
	 */
	if ((pml4_i_s == pml4_i_e && pml4_i_s != 0x1ff) ||
	    (pml5_i_s == pml5_i_e && pml5_i_s != 0x1ff))
		return false;

	/* Guest ranges should be inside what the hypervisor can provide. */
	if (pml4_i_s < pml4_index_start || pml4_i_e > pml4_index_end)
		return false;

	/*
	 * Allow for migration of guest in 4-level paging mode between hosts in
	 * both 4-level paging mode and 5-level paging mode.
	 */
	if (pml5_i_s != 0x1ff && (pml5_i_s < pml5_index_start || pml5_i_e > pml5_index_end))
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

static inline bool is_pvm_feature_control_msr_valid(struct vcpu_pvm *pvm,
						    struct msr_data *msr_info)
{
	/*
	 * currently only FEAT_CTL_LOCKED bit is valid, maybe
	 * vmx, sgx and mce associated bits can be valid when those features
	 * are supported for guest.
	 */
	u64 valid_bits = pvm->msr_ia32_feature_control_valid_bits;

	if (!msr_info->host_initiated &&
	    (pvm->msr_ia32_feature_control & FEAT_CTL_LOCKED))
		return false;

	return !(msr_info->data & ~valid_bits);
}

static void pvm_update_uret_msr(struct vcpu_pvm *pvm, unsigned int slot,
				u64 data, u64 mask)
{
	preempt_disable();
	if (pvm->loaded_cpu_state)
		kvm_set_user_return_msr(slot, data, mask);
	preempt_enable();
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
	case MSR_TSC_AUX:
		msr_info->data = pvm->msr_tsc_aux;
		break;
	case MSR_IA32_DEBUGCTLMSR:
		msr_info->data = 0;
		break;
	case MSR_IA32_FEAT_CTL:
		msr_info->data = pvm->msr_ia32_feature_control;
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
	case MSR_TSC_AUX:
		pvm->msr_tsc_aux = data;
		pvm_update_uret_msr(pvm, 1, data, -1ull);
		break;
	case MSR_IA32_DEBUGCTLMSR:
		/* It is ignored now. */
		break;
	case MSR_IA32_FEAT_CTL:
		if (!is_intel || !is_pvm_feature_control_msr_valid(pvm, msr_info))
			return 1;
		pvm->msr_ia32_feature_control = data;
		break;
	case MSR_MISC_FEATURES_ENABLES:
		ret = kvm_set_msr_common(vcpu, msr_info);
		if (!ret)
			pvm_update_guest_cpuid_faulting(vcpu, data);
		break;
	case MSR_PLATFORM_INFO:
		if ((data & MSR_PLATFORM_INFO_CPUID_FAULT) &&
		     !boot_cpu_has(X86_FEATURE_CPUID_FAULT))
			return 1;
		ret = kvm_set_msr_common(vcpu, msr_info);
		break;
	case MSR_PVM_VCPU_STRUCT:
		if (!PAGE_ALIGNED(data))
			return 1;
		/*
		 * During the VM restore process, if the VMM restores MSRs
		 * before adding the user memory region, it can result in a
		 * failure in kvm_gpc_activate() because no memslot has been
		 * added yet. As a consequence, the VM will panic after the VM
		 * restore since the GPC is not active. However, if we store
		 * the value even if kvm_gpc_activate() fails later when the
		 * GPC is active, it can be refreshed by the addition of the
		 * user memory region before the VM entry.
		 */
		pvm->msr_vcpu_struct = data;
		if (!data)
			kvm_gpc_deactivate(&pvm->pvcs_gpc);
		else if (kvm_gpc_activate(&pvm->pvcs_gpc, data, PAGE_SIZE))
			return 1;
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

static void pvm_cache_reg(struct kvm_vcpu *vcpu, enum kvm_reg reg)
{
	/* Nothing to do */
}

static int pvm_set_efer(struct kvm_vcpu *vcpu, u64 efer)
{
	vcpu->arch.efer = efer;

	return 0;
}

static bool pvm_is_valid_cr0(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	return true;
}

static void pvm_set_cr0(struct kvm_vcpu *vcpu, unsigned long cr0)
{
	if (vcpu->arch.efer & EFER_LME) {
		if (!is_paging(vcpu) && (cr0 & X86_CR0_PG))
			vcpu->arch.efer |= EFER_LMA;

		if (is_paging(vcpu) && !(cr0 & X86_CR0_PG))
			vcpu->arch.efer &= ~EFER_LMA;
	}

	vcpu->arch.cr0 = cr0;
}

static bool pvm_is_valid_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	return true;
}

static void pvm_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	unsigned long old_cr4 = vcpu->arch.cr4;

	vcpu->arch.cr4 = cr4;

	if ((cr4 ^ old_cr4) & (X86_CR4_OSXSAVE | X86_CR4_PKE))
		kvm_update_cpuid_runtime(vcpu);
}

static void pvm_get_segment(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	if (pvm->non_pvm_mode) {
		*var = pvm->segments[seg];
		return;
	}

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
				pvm->non_pvm_mode = true;
			if (cpl == 0 && !pvm->non_pvm_mode)
				pvm_standard_msr_star(pvm);
		}
		if (pvm->non_pvm_mode)
			try_to_convert_to_pvm_mode(vcpu);
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

	if (pvm->non_pvm_mode) {
		*db = pvm->segments[VCPU_SREG_CS].db;
		*l = pvm->segments[VCPU_SREG_CS].l;
	} else {
		if (pvm->hw_cs == __USER_CS) {
			*db = 0;
			*l = 1;
		} else {
			*db = 1;
			*l = 0;
		}
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
	/* disable direct switch when single step debugging */
	if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)
		to_pvm(vcpu)->switch_flags |= SWITCH_FLAGS_SINGLE_STEP;
	else
		to_pvm(vcpu)->switch_flags &= ~SWITCH_FLAGS_SINGLE_STEP;
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
	/*
	 * Unlike in VMX, the injected event is delivered by the guest before
	 * VM entry, so it is not allowed to inject event in non-PVM mode.
	 * Although, we have attempted to switch to PVM mode before event
	 * injection, the VMM may still inject event in non-PVM mode, so issue
	 * a warning for VMM in such cases. Also, try to swith to PVM mode if
	 * something is broken in the hypervisor.
	 */
	if (unlikely(to_pvm(vcpu)->non_pvm_mode)) {
		pr_warn_ratelimited("Inject event in non-PVM mode");
		try_to_convert_to_pvm_mode(vcpu);
	}

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
	if (unlikely(pvm->non_pvm_mode) || !need_update || !is_smod(pvm))
		return;

	if (rflags & X86_EFLAGS_IF) {
		pvm->switch_flags &= ~SWITCH_FLAGS_IRQ_WIN;
		pvm_event_flags_update(vcpu, X86_EFLAGS_IF, PVM_EVENT_FLAGS_IP);
	} else {
		pvm_event_flags_update(vcpu, 0, X86_EFLAGS_IF);
	}
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
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	/* PVM spec: ignore interrupt shadow when in PVM mode. */
	if (pvm->non_pvm_mode)
		pvm->int_shadow = mask;
}

static void enable_irq_window(struct kvm_vcpu *vcpu)
{
	to_pvm(vcpu)->switch_flags |= SWITCH_FLAGS_IRQ_WIN;
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
	to_pvm(vcpu)->switch_flags |= SWITCH_FLAGS_NMI_WIN;
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

	to_pvm(vcpu)->switch_flags &= ~SWITCH_FLAGS_IRQ_WIN;

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

static int handle_synthetic_instruction_return_user(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	struct pvm_vcpu_struct *pvcs;

	// instruction to return user means nmi allowed.
	pvm->nmi_mask = false;
	pvm->switch_flags &= ~(SWITCH_FLAGS_IRQ_WIN | SWITCH_FLAGS_NMI_WIN);

	/*
	 * switch to user mode before kvm_set_rflags() to avoid PVM_EVENT_FLAGS_IF
	 * to be set.
	 */
	switch_to_umod(vcpu);

	pvcs = pvm_get_vcpu_struct(pvm);
	if (!pvcs) {
		kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
		return 1;
	}

	/*
	 * pvm_set_rflags() doesn't clear PVM_EVENT_FLAGS_IP
	 * for user mode, so clear it here.
	 */
	if (pvcs->event_flags & PVM_EVENT_FLAGS_IP) {
		pvcs->event_flags &= ~PVM_EVENT_FLAGS_IP;
		kvm_make_request(KVM_REQ_EVENT, vcpu);
	}

	pvm->hw_cs = pvcs->user_cs | USER_RPL;
	pvm->hw_ss = pvcs->user_ss | USER_RPL;

	pvm_write_guest_gs_base(pvm, pvcs->user_gsbase);
	kvm_set_rflags(vcpu, pvcs->eflags | X86_EFLAGS_IF);
	kvm_rip_write(vcpu, pvcs->rip);
	kvm_rsp_write(vcpu, pvcs->rsp);
	kvm_rcx_write(vcpu, pvcs->rcx);
	kvm_r11_write(vcpu, pvcs->r11);

	pvm_put_vcpu_struct(pvm, false);

	return 1;
}

static int handle_synthetic_instruction_return_supervisor(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	unsigned long rsp = kvm_rsp_read(vcpu);
	struct pvm_supervisor_event frame;
	struct x86_exception e;

	if (kvm_read_guest_virt(vcpu, rsp, &frame, sizeof(frame), &e)) {
		kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
		return 1;
	}

	// instruction to return supervisor means nmi allowed.
	pvm->nmi_mask = false;
	pvm->switch_flags &= ~SWITCH_FLAGS_NMI_WIN;

	kvm_set_rflags(vcpu, frame.rflags);
	kvm_rip_write(vcpu, frame.rip);
	kvm_rsp_write(vcpu, frame.rsp);
	kvm_rcx_write(vcpu, frame.rcx);
	kvm_r11_write(vcpu, frame.r11);

	return 1;
}

static int handle_hc_interrupt_window(struct kvm_vcpu *vcpu)
{
	kvm_make_request(KVM_REQ_EVENT, vcpu);
	to_pvm(vcpu)->switch_flags &= ~SWITCH_FLAGS_IRQ_WIN;
	pvm_event_flags_update(vcpu, 0, PVM_EVENT_FLAGS_IP);

	++vcpu->stat.irq_window_exits;
	return 1;
}

static int handle_hc_irq_halt(struct kvm_vcpu *vcpu)
{
	kvm_set_rflags(vcpu, kvm_get_rflags(vcpu) | X86_EFLAGS_IF);

	return kvm_emulate_halt_noskip(vcpu);
}

static void pvm_flush_tlb_guest_current_kernel_user(struct kvm_vcpu *vcpu)
{
	/*
	 * sync the current pgd and user_pgd (pvm->msr_switch_cr3)
	 * which is a subset work of KVM_REQ_TLB_FLUSH_GUEST.
	 */
	kvm_make_request(KVM_REQ_TLB_FLUSH_GUEST, vcpu);
}

/*
 * Hypercall: PVM_HC_LOAD_PGTBL
 *	Load two PGDs into the current CR3 and MSR_PVM_SWITCH_CR3.
 *
 * Arguments:
 *	flags:	bit0: flush the TLBs tagged with @pgd and @user_pgd.
 *		bit1: 4 (bit1=0) or 5 (bit1=1 && cpuid_has(LA57)) level paging.
 *	pgd: to be loaded into CR3.
 *	user_pgd: to be loaded into MSR_PVM_SWITCH_CR3.
 */
static int handle_hc_load_pagetables(struct kvm_vcpu *vcpu, unsigned long flags,
				     unsigned long pgd, unsigned long user_pgd)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	unsigned long cr4 = vcpu->arch.cr4;

	if (!(flags & PVM_LOAD_PGTBL_FLAGS_LA57))
		cr4 &= ~X86_CR4_LA57;
	else if (guest_cpuid_has(vcpu, X86_FEATURE_LA57))
		cr4 |= X86_CR4_LA57;

	if (cr4 != vcpu->arch.cr4) {
		vcpu->arch.cr4 = cr4;
		kvm_mmu_reset_context(vcpu);
	}

	kvm_mmu_new_pgd(vcpu, pgd);
	vcpu->arch.cr3 = pgd;
	pvm->msr_switch_cr3 = user_pgd;

	if (flags & PVM_LOAD_PGTBL_FLAGS_TLB)
		pvm_flush_tlb_guest_current_kernel_user(vcpu);

	return 1;
}

/*
 * Hypercall: PVM_HC_TLB_FLUSH
 *	Flush all TLBs.
 */
static int handle_hc_flush_tlb_all(struct kvm_vcpu *vcpu)
{
	kvm_make_request(KVM_REQ_TLB_FLUSH_GUEST, vcpu);

	return 1;
}

/*
 * Hypercall: PVM_HC_TLB_FLUSH_CURRENT
 *	Flush all TLBs tagged with the current CR3 and MSR_PVM_SWITCH_CR3.
 */
static int handle_hc_flush_tlb_current_kernel_user(struct kvm_vcpu *vcpu)
{
	pvm_flush_tlb_guest_current_kernel_user(vcpu);

	return 1;
}

/*
 * Hypercall: PVM_HC_TLB_INVLPG
 *	Flush TLBs associated with a single address for all tags.
 */
static int handle_hc_invlpg(struct kvm_vcpu *vcpu, unsigned long addr)
{
	kvm_mmu_invlpg(vcpu, addr);

	return 1;
}

/*
 * Hypercall: PVM_HC_LOAD_GS
 *	Load %gs with the selector %rdi and load the resulted base address
 *	into RAX.
 *
 *	If %rdi is an invalid selector (including RPL != 3), NULL selector
 *	will be used instead.
 *
 *	Return the resulted GS BASE in vCPU's RAX.
 */
static int handle_hc_load_gs(struct kvm_vcpu *vcpu, unsigned short sel)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	unsigned long guest_kernel_gs_base;

	/* Use NULL selector if RPL != 3. */
	if (sel != 0 && (sel & 3) != 3)
		sel = 0;

	/* Protect the guest state on the hardware. */
	preempt_disable();

	/*
	 * Switch to the guest state because the CPU is going to set the %gs to
	 * the guest value.  Save the original guest MSR_GS_BASE if it is
	 * already the guest state.
	 */
	if (!pvm->loaded_cpu_state)
		pvm_prepare_switch_to_guest(vcpu);
	else
		__save_gs_base(pvm);

	/*
	 * Load sel into %gs, which also changes the hardware MSR_KERNEL_GS_BASE.
	 *
	 * Before load_gs_index(sel):
	 *	hardware %gs:			old gs index
	 *	hardware MSR_KERNEL_GS_BASE:	guest MSR_GS_BASE
	 *
	 * After load_gs_index(sel);
	 *	hardware %gs:			resulted %gs, @sel or NULL
	 *	hardware MSR_KERNEL_GS_BASE:	resulted GS BASE
	 *
	 * The resulted %gs is the new guest %gs and will be saved into
	 * pvm->segments[VCPU_SREG_GS].selector later when the CPU is
	 * switching to host or the guest %gs is read (pvm_get_segment()).
	 *
	 * The resulted hardware MSR_KERNEL_GS_BASE will be returned via RAX
	 * to the guest and the hardware MSR_KERNEL_GS_BASE, which represents
	 * the guest MSR_GS_BASE when in VM-Exit state, is restored back to
	 * the guest MSR_GS_BASE.
	 */
	load_gs_index(sel);

	/* Get the resulted guest MSR_KERNEL_GS_BASE. */
	rdmsrl(MSR_KERNEL_GS_BASE, guest_kernel_gs_base);

	/* Restore the guest MSR_GS_BASE into the hardware MSR_KERNEL_GS_BASE. */
	__load_gs_base(pvm);

	/* Finished access to the guest state on the hardware. */
	preempt_enable();

	/* Return RAX with the resulted GS BASE. */
	kvm_rax_write(vcpu, guest_kernel_gs_base);

	return 1;
}

/*
 * Hypercall: PVM_HC_RDMSR
 *	Write MSR.
 *	Return with RAX = the MSR value if succeeded.
 *	Return with RAX = 0 if it failed.
 */
static int handle_hc_rdmsr(struct kvm_vcpu *vcpu, u32 index)
{
	u64 value = 0;

	kvm_get_msr(vcpu, index, &value);
	kvm_rax_write(vcpu, value);

	return 1;
}

/*
 * Hypercall: PVM_HC_WRMSR
 *	Write MSR.
 *	Return with RAX = 0 if succeeded.
 *	Return with RAX = -EIO if it failed
 */
static int handle_hc_wrmsr(struct kvm_vcpu *vcpu, u32 index, u64 value)
{
	if (kvm_set_msr(vcpu, index, value))
		kvm_rax_write(vcpu, -EIO);
	else
		kvm_rax_write(vcpu, 0);

	return 1;
}

// Check if the tls desc is allowed on the host GDT.
// The same logic as tls_desc_okay() in arch/x86/kernel/tls.c.
static bool tls_desc_okay(struct desc_struct *desc)
{
	// Only allow present segments.
	if (!desc->p)
		return false;

	// Only allow data segments.
	if (desc->type & (1 << 3))
		return false;

	// Only allow 32-bit data segments.
	if (!desc->d)
		return false;

	return true;
}

/*
 * Hypercall: PVM_HC_LOAD_TLS
 *	Load guest TLS desc into host GDT.
 */
static int handle_hc_load_tls(struct kvm_vcpu *vcpu, unsigned long tls_desc_0,
			      unsigned long tls_desc_1, unsigned long tls_desc_2)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	unsigned long *tls_array = (unsigned long *)&pvm->tls_array[0];
	int i;

	tls_array[0] = tls_desc_0;
	tls_array[1] = tls_desc_1;
	tls_array[2] = tls_desc_2;

	for (i = 0; i < GDT_ENTRY_TLS_ENTRIES; i++) {
		if (!tls_desc_okay(&pvm->tls_array[i])) {
			pvm->tls_array[i] = (struct desc_struct){0};
			continue;
		}
		/* Standarding TLS descs, same as fill_ldt(). */
		pvm->tls_array[i].type |= 1;
		pvm->tls_array[i].s = 1;
		pvm->tls_array[i].dpl = 0x3;
		pvm->tls_array[i].l = 0;
	}

	preempt_disable();
	if (pvm->loaded_cpu_state)
		host_gdt_set_tls(pvm);
	preempt_enable();

	return 1;
}

static int handle_kvm_hypercall(struct kvm_vcpu *vcpu)
{
	int r;

	// In PVM, r10 is the replacement for rcx in hypercall
	kvm_rcx_write(vcpu, kvm_r10_read(vcpu));
	r = kvm_emulate_hypercall_noskip(vcpu);
	kvm_r10_write(vcpu, kvm_rcx_read(vcpu));

	return r;
}

static int handle_exit_syscall(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	unsigned long rip = kvm_rip_read(vcpu);
	unsigned long a0, a1, a2;

	if (!is_smod(pvm))
		return do_pvm_user_event(vcpu, PVM_SYSCALL_VECTOR, false, 0);

	if (rip == pvm->msr_retu_rip_plus2)
		return handle_synthetic_instruction_return_user(vcpu);
	if (rip == pvm->msr_rets_rip_plus2)
		return handle_synthetic_instruction_return_supervisor(vcpu);

	a0 = kvm_rbx_read(vcpu);
	a1 = kvm_r10_read(vcpu);
	a2 = kvm_rdx_read(vcpu);

	// handle hypercall, check it for pvm hypercall and then kvm hypercall
	switch (kvm_rax_read(vcpu)) {
	case PVM_HC_IRQ_WIN:
		return handle_hc_interrupt_window(vcpu);
	case PVM_HC_IRQ_HALT:
		return handle_hc_irq_halt(vcpu);
	case PVM_HC_LOAD_PGTBL:
		return handle_hc_load_pagetables(vcpu, a0, a1, a2);
	case PVM_HC_TLB_FLUSH:
		return handle_hc_flush_tlb_all(vcpu);
	case PVM_HC_TLB_FLUSH_CURRENT:
		return handle_hc_flush_tlb_current_kernel_user(vcpu);
	case PVM_HC_TLB_INVLPG:
		return handle_hc_invlpg(vcpu, a0);
	case PVM_HC_LOAD_GS:
		return handle_hc_load_gs(vcpu, a0);
	case PVM_HC_RDMSR:
		return handle_hc_rdmsr(vcpu, a0);
	case PVM_HC_WRMSR:
		return handle_hc_wrmsr(vcpu, a0, a1);
	case PVM_HC_LOAD_TLS:
		return handle_hc_load_tls(vcpu, a0, a1, a2);
	default:
		return handle_kvm_hypercall(vcpu);
	}
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

static bool handle_synthetic_instruction_pvm_cpuid(struct kvm_vcpu *vcpu)
{
	/* invlpg 0xffffffffff4d5650; cpuid; */
	static const char pvm_synthetic_cpuid_insns[] = { PVM_SYNTHETIC_CPUID };
	char insns[10];
	struct x86_exception e;

	if (kvm_read_guest_virt(vcpu, kvm_get_linear_rip(vcpu),
				insns, sizeof(insns), &e) == 0 &&
	    memcmp(insns, pvm_synthetic_cpuid_insns, sizeof(insns)) == 0) {
		u32 eax, ebx, ecx, edx;

		if (unlikely(pvm_guest_allowed_va(vcpu, PVM_SYNTHETIC_CPUID_ADDRESS)))
			kvm_mmu_invlpg(vcpu, PVM_SYNTHETIC_CPUID_ADDRESS);

		eax = kvm_rax_read(vcpu);
		ecx = kvm_rcx_read(vcpu);
		kvm_cpuid(vcpu, &eax, &ebx, &ecx, &edx, false);
		kvm_rax_write(vcpu, eax);
		kvm_rbx_write(vcpu, ebx);
		kvm_rcx_write(vcpu, ecx);
		kvm_rdx_write(vcpu, edx);

		kvm_rip_write(vcpu, kvm_rip_read(vcpu) + sizeof(insns));
		return true;
	}

	return false;
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
		if (is_smod(pvm) && handle_synthetic_instruction_pvm_cpuid(vcpu))
			return 1;

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

	if (unlikely(pvm->non_pvm_mode))
		return handle_non_pvm_mode(vcpu);

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

static u32 pvm_get_syscall_exit_reason(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	unsigned long rip = kvm_rip_read(vcpu);

	if (is_smod(pvm)) {
		if (rip == pvm->msr_retu_rip_plus2)
			return PVM_EXIT_REASONS_ERETU;
		else if (rip == pvm->msr_rets_rip_plus2)
			return PVM_EXIT_REASONS_ERETS;
		else
			return PVM_EXIT_REASONS_HYPERCALL;
	}

	return PVM_EXIT_REASONS_SYSCALL;
}

static void pvm_get_exit_info(struct kvm_vcpu *vcpu, u32 *reason, u64 *info1, u64 *info2,
			      u32 *intr_info, u32 *error_code)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	if (pvm->exit_vector == PVM_SYSCALL_VECTOR)
		*reason = pvm_get_syscall_exit_reason(vcpu);
	else if (pvm->exit_vector == IA32_SYSCALL_VECTOR)
		*reason = PVM_EXIT_REASONS_INT80;
	else if (pvm->exit_vector >= FIRST_EXTERNAL_VECTOR &&
		 pvm->exit_vector < NR_VECTORS)
		*reason = PVM_EXIT_REASONS_INTERRUPT;
	else
		*reason = pvm->exit_vector;
	*info1 = pvm->exit_vector;
	*info2 = pvm->exit_error_code;
	*intr_info = pvm->exit_vector;
	*error_code = pvm->exit_error_code;
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
	struct tss_extra *tss_ex = this_cpu_ptr(&cpu_tss_rw.tss_ex);
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	struct pt_regs *sp0_regs = (struct pt_regs *)this_cpu_read(cpu_tss_rw.x86_tss.sp0) - 1;
	struct pt_regs *ret_regs;

	guest_state_enter_irqoff();

	// Load guest registers into the host sp0 stack for switcher.
	load_regs(vcpu, sp0_regs);

	// Prepare context for direct switching.
	tss_ex->switch_flags = pvm->switch_flags;
	tss_ex->pvcs = pvm->pvcs_gpc.khva;
	tss_ex->retu_rip = pvm->msr_retu_rip_plus2;
	tss_ex->smod_entry = pvm->msr_lstar;
	tss_ex->smod_gsbase = pvm->msr_kernel_gs_base;
	tss_ex->smod_rsp = pvm->msr_supervisor_rsp;

	if (unlikely(pvm->guest_dr7 & DR7_BP_EN_MASK))
		set_debugreg(pvm_eff_dr7(vcpu), 7);

	// Call into switcher and enter guest.
	ret_regs = switcher_enter_guest();

	// Get the resulted mode and PVM MSRs which might be changed
	// when direct switching.
	pvm->switch_flags = tss_ex->switch_flags;
	pvm->msr_supervisor_rsp = tss_ex->smod_rsp;

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
	bool is_smod_befor_run = is_smod(pvm);

	/*
	 * Don't enter guest if guest state is invalid, let the exit handler
	 * start emulation until we arrive back to a valid state.
	 */
	if (pvm->non_pvm_mode)
		return EXIT_FASTPATH_NONE;

	trace_kvm_entry(vcpu);

	pvm_load_guest_xsave_state(vcpu);

	kvm_wait_lapic_expire(vcpu);

	pvm_set_host_cr3(pvm);

	if (pvm->host_debugctlmsr)
		update_debugctlmsr(0);

	pvm_vcpu_run_noinstr(vcpu);

	if (is_smod_befor_run != is_smod(pvm)) {
		swap(pvm->vcpu.arch.mmu->root, pvm->vcpu.arch.mmu->prev_roots[0]);
		swap(pvm->msr_switch_cr3, pvm->vcpu.arch.cr3);
	}

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

	trace_kvm_exit(vcpu, KVM_ISA_PVM);

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

	// Non-PVM mode resets
	pvm->non_pvm_mode = true;
	pvm->msr_star = 0;

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
	memset(&pvm->tls_array[0], 0, sizeof(pvm->tls_array));

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
	 *
	 * If the allocation of the reserved range fails, disable support for
	 * 5-level paging support.
	 */
	if (!pgtable_l5_enabled() || pml5_index_start == 0x1ff)
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

//====== start of dummy pmu ===========
//TODO: split kvm-pmu-intel.ko & kvm-pmu-amd.ko from kvm-intel.ko & kvm-amd.ko.
static bool dummy_pmu_hw_event_available(struct kvm_pmc *pmc)
{
	return true;
}

static struct kvm_pmc *dummy_pmc_idx_to_pmc(struct kvm_pmu *pmu, int pmc_idx)
{
	return NULL;
}

static struct kvm_pmc *dummy_pmu_rdpmc_ecx_to_pmc(struct kvm_vcpu *vcpu,
						  unsigned int idx, u64 *mask)
{
	return NULL;
}

static bool dummy_pmu_is_valid_rdpmc_ecx(struct kvm_vcpu *vcpu, unsigned int idx)
{
	return false;
}

static struct kvm_pmc *dummy_pmu_msr_idx_to_pmc(struct kvm_vcpu *vcpu, u32 msr)
{
	return NULL;
}

static bool dummy_pmu_is_valid_msr(struct kvm_vcpu *vcpu, u32 msr)
{
	return 0;
}

static int dummy_pmu_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	return 1;
}

static int dummy_pmu_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	return 1;
}

static void dummy_pmu_refresh(struct kvm_vcpu *vcpu)
{
}

static void dummy_pmu_init(struct kvm_vcpu *vcpu)
{
}

static void dummy_pmu_reset(struct kvm_vcpu *vcpu)
{
}

struct kvm_pmu_ops dummy_pmu_ops = {
	.hw_event_available = dummy_pmu_hw_event_available,
	.pmc_idx_to_pmc = dummy_pmc_idx_to_pmc,
	.rdpmc_ecx_to_pmc = dummy_pmu_rdpmc_ecx_to_pmc,
	.msr_idx_to_pmc = dummy_pmu_msr_idx_to_pmc,
	.is_valid_rdpmc_ecx = dummy_pmu_is_valid_rdpmc_ecx,
	.is_valid_msr = dummy_pmu_is_valid_msr,
	.get_msr = dummy_pmu_get_msr,
	.set_msr = dummy_pmu_set_msr,
	.refresh = dummy_pmu_refresh,
	.init = dummy_pmu_init,
	.reset = dummy_pmu_reset,
};
//========== end of dummy pmu =============

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
	.is_valid_cr0 = pvm_is_valid_cr0,
	.set_cr0 = pvm_set_cr0,
	.load_mmu_pgd = pvm_load_mmu_pgd,
	.is_valid_cr4 = pvm_is_valid_cr4,
	.set_cr4 = pvm_set_cr4,
	.set_efer = pvm_set_efer,
	.get_gdt = pvm_get_gdt,
	.set_gdt = pvm_set_gdt,
	.get_idt = pvm_get_idt,
	.set_idt = pvm_set_idt,
	.set_dr7 = pvm_set_dr7,
	.sync_dirty_debug_regs = pvm_sync_dirty_debug_regs,
	.cache_reg = pvm_cache_reg,
	.get_rflags = pvm_get_rflags,
	.set_rflags = pvm_set_rflags,
	.get_if_flag = pvm_get_if_flag,

	.flush_tlb_all = pvm_flush_hwtlb,
	.flush_tlb_current = pvm_flush_hwtlb_current,
	.flush_tlb_gva = pvm_flush_hwtlb_gva,
	.flush_tlb_guest = pvm_flush_hwtlb_guest,

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

	.get_exit_info = pvm_get_exit_info,

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

	.get_l2_tsc_offset = pvm_get_l2_tsc_offset,
	.get_l2_tsc_multiplier = pvm_get_l2_tsc_multiplier,
	.write_tsc_offset = pvm_write_tsc_offset,
	.write_tsc_multiplier = pvm_write_tsc_multiplier,
	.check_emulate_instruction = pvm_check_emulate_instruction,
	.disallowed_va = pvm_disallowed_va,
	.vcpu_gpc_refresh = pvm_vcpu_gpc_refresh,
};

static struct kvm_x86_init_ops pvm_init_ops __initdata = {
	.hardware_setup = hardware_setup,

	.runtime_ops = &pvm_x86_ops,
	.pmu_ops = &dummy_pmu_ops,
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

#define TLB_NR_DYN_ASIDS	6

static int __init hardware_cap_check(void)
{
	BUILD_BUG_ON(MIN_HOST_PCID_FOR_GUEST <= TLB_NR_DYN_ASIDS);
#ifdef CONFIG_PAGE_TABLE_ISOLATION
	BUILD_BUG_ON((MIN_HOST_PCID_FOR_GUEST + NUM_HOST_PCID_FOR_GUEST) >=
		     (1 << X86_CR3_PTI_PCID_USER_BIT));
#endif

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
	if (!boot_cpu_has(X86_FEATURE_CPUID_FAULT) && enable_cpuid_intercept) {
		pr_warn("Host doesn't support cpuid faulting.\n");
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
