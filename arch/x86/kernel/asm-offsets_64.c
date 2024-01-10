// SPDX-License-Identifier: GPL-2.0
#ifndef __LINUX_KBUILD_H
# error "Please do not build this file directly, build asm-offsets.c instead"
#endif

#include <asm/ia32.h>
#include <asm/pvm_para.h>

#if defined(CONFIG_KVM_GUEST)
#include <asm/kvm_para.h>
#endif

int main(void)
{
#ifdef CONFIG_PARAVIRT
#ifdef CONFIG_PARAVIRT_XXL
#ifdef CONFIG_DEBUG_ENTRY
	OFFSET(PV_IRQ_save_fl, paravirt_patch_template, irq.save_fl);
#endif
#endif
	BLANK();
#endif

#if defined(CONFIG_KVM_GUEST)
	OFFSET(KVM_STEAL_TIME_preempted, kvm_steal_time, preempted);
	BLANK();
#endif

#define ENTRY(entry) OFFSET(pt_regs_ ## entry, pt_regs, entry)
	ENTRY(bx);
	ENTRY(cx);
	ENTRY(dx);
	ENTRY(sp);
	ENTRY(bp);
	ENTRY(si);
	ENTRY(di);
	ENTRY(r8);
	ENTRY(r9);
	ENTRY(r10);
	ENTRY(r11);
	ENTRY(r12);
	ENTRY(r13);
	ENTRY(r14);
	ENTRY(r15);
	ENTRY(flags);
	BLANK();
#undef ENTRY

#define ENTRY(entry) OFFSET(saved_context_ ## entry, saved_context, entry)
	ENTRY(cr0);
	ENTRY(cr2);
	ENTRY(cr3);
	ENTRY(cr4);
	ENTRY(gdt_desc);
	BLANK();
#undef ENTRY

	BLANK();

#ifdef CONFIG_STACKPROTECTOR_FIXED
	OFFSET(FIXED_stack_canary, fixed_percpu_data, stack_canary);
	BLANK();
#endif

#define ENTRY(entry) OFFSET(TSS_EX_ ## entry, tss_struct, tss_ex.entry)
	ENTRY(host_cr3);
	ENTRY(host_rsp);
	ENTRY(enter_cr3);
	ENTRY(switch_flags);
	ENTRY(smod_cr3);
	ENTRY(umod_cr3);
	ENTRY(pvcs);
	ENTRY(retu_rip);
	ENTRY(smod_entry);
	ENTRY(smod_gsbase);
	ENTRY(smod_rsp);
	BLANK();
#undef ENTRY

#define ENTRY(entry) OFFSET(PVCS_ ## entry, pvm_vcpu_struct, entry)
	ENTRY(event_flags);
	ENTRY(event_errcode);
	ENTRY(user_cs);
	ENTRY(user_ss);
	ENTRY(user_gsbase);
	ENTRY(rsp);
	ENTRY(eflags);
	ENTRY(rip);
	ENTRY(rcx);
	ENTRY(r11);
	BLANK();
#undef ENTRY

	return 0;
}
