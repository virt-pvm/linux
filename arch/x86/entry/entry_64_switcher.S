/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <linux/export.h>
#include <asm/segment.h>
#include <asm/asm-offsets.h>
#include <asm/msr.h>
#include <asm/percpu.h>
#include <asm/asm.h>
#include <asm/nospec-branch.h>
#include <asm/switcher.h>

#include "calling.h"

.code64
.section .entry.text, "ax"

.macro MITIGATION_EXIT
	/* Same as user entry. */
	IBRS_EXIT
.endm

.macro MITIGATION_ENTER
	/*
	 * IMPORTANT: RSB filling and SPEC_CTRL handling must be done before
	 * the first unbalanced RET after vmexit!
	 *
	 * For retpoline or IBRS, RSB filling is needed to prevent poisoned RSB
	 * entries and (in some cases) RSB underflow.
	 *
	 * eIBRS has its own protection against poisoned RSB, so it doesn't
	 * need the RSB filling sequence.  But it does need to be enabled, and a
	 * single call to retire, before the first unbalanced RET.
	 */
	FILL_RETURN_BUFFER %rcx, RSB_CLEAR_LOOPS, X86_FEATURE_RSB_VMEXIT, \
			   X86_FEATURE_RSB_VMEXIT_LITE

	IBRS_ENTER
.endm

/*
 * switcher_enter_guest - Do a transition to guest mode
 *
 * Called with guest registers on the top of the sp0 stack and the switcher
 * states on cpu_tss_rw.tss_ex.
 *
 * Returns:
 *	pointer to pt_regs (on top of sp0 or IST stack) with guest registers.
 */
SYM_FUNC_START(switcher_enter_guest)
	pushq	%rbp
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx

	/* Save host RSP and mark the switcher active */
	movq	%rsp, TSS_extra(host_rsp)

	/* Switch to host sp0  */
	movq	PER_CPU_VAR(cpu_tss_rw + TSS_sp0), %rdi
	subq	$FRAME_SIZE, %rdi
	movq	%rdi, %rsp

	UNWIND_HINT_REGS

	MITIGATION_EXIT

	/* switch to guest cr3 on sp0 stack */
	movq	TSS_extra(enter_cr3), %rax
	movq	%rax, %cr3
	/* Load guest registers. */
	POP_REGS
	addq	$8, %rsp

	/* Switch to guest GSBASE and return to guest */
	swapgs
	jmp	.L_switcher_return_to_guest

SYM_INNER_LABEL(switcher_return_from_guest, SYM_L_GLOBAL)
	/* switch back to host cr3 when still on sp0/ist stack */
	movq	TSS_extra(host_cr3), %rax
	movq	%rax, %cr3

	MITIGATION_ENTER

	/* Restore to host RSP and mark the switcher inactive */
	movq	%rsp, %rax
	movq	TSS_extra(host_rsp), %rsp
	movq	$0, TSS_extra(host_rsp)

	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	RET
SYM_FUNC_END(switcher_enter_guest)
EXPORT_SYMBOL_GPL(switcher_enter_guest)

.macro canonical_rcx
	/*
	 * If width of "canonical tail" ever becomes variable, this will need
	 * to be updated to remain correct on both old and new CPUs.
	 *
	 * Change top bits to match most significant bit (47th or 56th bit
	 * depending on paging mode) in the address.
	 */
#ifdef CONFIG_X86_5LEVEL
	ALTERNATIVE "shl $(64 - 48), %rcx; sar $(64 - 48), %rcx", \
		    "shl $(64 - 57), %rcx; sar $(64 - 57), %rcx", X86_FEATURE_LA57
#else
	shl	$(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx
	sar	$(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx
#endif
.endm

SYM_CODE_START(entry_SYSCALL_64_switcher)
	UNWIND_HINT_ENTRY
	ENDBR

	swapgs
	/* tss.sp2 is scratch space. */
	movq	%rsp, PER_CPU_VAR(cpu_tss_rw + TSS_sp2)
	movq	PER_CPU_VAR(cpu_tss_rw + TSS_sp0), %rsp

SYM_INNER_LABEL(entry_SYSCALL_64_switcher_safe_stack, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR

	/* Construct struct pt_regs on stack */
	pushq	$__USER_DS				/* pt_regs->ss */
	pushq	PER_CPU_VAR(cpu_tss_rw + TSS_sp2)	/* pt_regs->sp */
	pushq	%r11					/* pt_regs->flags */
	pushq	$__USER_CS				/* pt_regs->cs */
	pushq	%rcx					/* pt_regs->ip */
	pushq	%rdi					/* put rdi on ORIG_RAX */

	/* check if it can do direct switch from umod to smod */
	testq	$SWITCH_FLAGS_NO_DS_TO_SMOD, TSS_extra(switch_flags)
	jnz	.L_switcher_check_return_umod_instruction

	/* Now it must be umod, start to do direct switch from umod to smod */
	movq	TSS_extra(pvcs), %rdi
	movl	$((__USER_DS << 16) | __USER_CS), PVCS_user_cs(%rdi)
	movl	%r11d, PVCS_eflags(%rdi)
	movq	%rcx, PVCS_rip(%rdi)
	movq	%rcx, PVCS_rcx(%rdi)
	movq	%r11, PVCS_r11(%rdi)
	movq	RSP-ORIG_RAX(%rsp), %rcx
	movq	%rcx, PVCS_rsp(%rdi)

	/* switch umod to smod (switch_flags & cr3) */
	xorb	$SWITCH_FLAGS_MOD_TOGGLE, TSS_extra(switch_flags)
	movq	TSS_extra(smod_cr3), %rcx
	movq	%rcx, %cr3

	/* load smod registers from TSS_extra to sp0 stack or %r11 */
	movq	TSS_extra(smod_rsp), %rcx
	movq	%rcx, RSP-ORIG_RAX(%rsp)
	movq	TSS_extra(smod_entry), %rcx
	movq	%rcx, RIP-ORIG_RAX(%rsp)
	movq	TSS_extra(smod_gsbase), %r11

	/* switch host gsbase to guest gsbase, TSS_extra can't be use afterward */
	swapgs

	/* save guest gsbase as user_gsbase and switch to smod_gsbase */
	rdgsbase %rcx
	movq	%rcx, PVCS_user_gsbase(%rdi)
	wrgsbase %r11

	/* restore umod rdi and smod rflags/r11, rip/rcx and rsp for sysretq */
	popq	%rdi
	movq	$SWITCH_ENTER_EFLAGS_FIXED, %r11
	movq	RIP-RIP(%rsp), %rcx

.L_switcher_sysretq:
	UNWIND_HINT_IRET_REGS
	/* now everything is ready for sysretq except for %rsp */
	movq	RSP-RIP(%rsp), %rsp
	/* No instruction can be added between seting the guest %rsp and doing sysretq */
SYM_INNER_LABEL(entry_SYSRETQ_switcher_unsafe_stack, SYM_L_GLOBAL)
	sysretq

.L_switcher_check_return_umod_instruction:
	UNWIND_HINT_IRET_REGS offset=8

	/* check if it can do direct switch from smod to umod */
	testq	$SWITCH_FLAGS_NO_DS_TO_UMOD, TSS_extra(switch_flags)
	jnz	.L_switcher_return_to_hypervisor

	/*
	 * Now it must be smod, check if it is the return-umod instruction.
	 * Switcher and the PVM specification defines a SYSCALL instrucion
	 * at TSS_extra(retu_rip) - 2 in smod as the return-umod instruction.
	 */
	cmpq	%rcx, TSS_extra(retu_rip)
	jne	.L_switcher_return_to_hypervisor

	/* only handle for the most common cs/ss */
	movq	TSS_extra(pvcs), %rdi
	cmpl	$((__USER_DS << 16) | __USER_CS), PVCS_user_cs(%rdi)
	jne	.L_switcher_return_to_hypervisor

	/* Switcher and the PVM specification requires the smod RSP to be saved */
	movq	RSP-ORIG_RAX(%rsp), %rcx
	movq	%rcx, TSS_extra(smod_rsp)

	/* switch smod to umod (switch_flags & cr3) */
	xorb	$SWITCH_FLAGS_MOD_TOGGLE, TSS_extra(switch_flags)
	movq	TSS_extra(umod_cr3), %rcx
	movq	%rcx, %cr3

	/* switch host gsbase to guest gsbase, TSS_extra can't be use afterward */
	swapgs

	/* write umod gsbase */
	movq	PVCS_user_gsbase(%rdi), %rcx
	canonical_rcx
	wrgsbase %rcx

	/* load sp, flags, ip to sp0 stack and cx, r11, rdi to registers */
	movq	PVCS_rsp(%rdi), %rcx
	movq	%rcx, RSP-ORIG_RAX(%rsp)
	movl	PVCS_eflags(%rdi), %r11d
	movq	%r11, EFLAGS-ORIG_RAX(%rsp)
	movq	PVCS_rip(%rdi), %rcx
	movq	%rcx, RIP-ORIG_RAX(%rsp)
	movq	PVCS_rcx(%rdi), %rcx
	movq	PVCS_r11(%rdi), %r11
	popq	%rdi		// saved rdi (on ORIG_RAX)

.L_switcher_return_to_guest:
	/*
	 * Now the RSP points to an IRET frame with guest state on the
	 * top of the sp0 stack.  Check if it can do sysretq.
	 */
	UNWIND_HINT_IRET_REGS

	andq	$SWITCH_ENTER_EFLAGS_ALLOWED, EFLAGS-RIP(%rsp)
	orq	$SWITCH_ENTER_EFLAGS_FIXED, EFLAGS-RIP(%rsp)
	testq	$(X86_EFLAGS_RF|X86_EFLAGS_TF), EFLAGS-RIP(%rsp)
	jnz	native_irq_return_iret
	cmpq	%r11, EFLAGS-RIP(%rsp)
	jne	native_irq_return_iret

	cmpq	%rcx, RIP-RIP(%rsp)
	jne	native_irq_return_iret
	/*
	 * On Intel CPUs, SYSRET with non-canonical RCX/RIP will #GP
	 * in kernel space.  This essentially lets the guest take over
	 * the host, since guest controls RSP.
	 */
	canonical_rcx
	cmpq	%rcx, RIP-RIP(%rsp)
	je	.L_switcher_sysretq

	/* RCX matches for RIP only before RCX is canonicalized, restore RCX and do IRET. */
	movq	RIP-RIP(%rsp), %rcx
	jmp	native_irq_return_iret

.L_switcher_return_to_hypervisor:
	popq	%rdi					/* saved rdi */
	pushq	$0					/* pt_regs->orig_ax */
	movl	$SWITCH_EXIT_REASONS_SYSCALL, 4(%rsp)

	PUSH_AND_CLEAR_REGS
	jmp	switcher_return_from_guest
SYM_CODE_END(entry_SYSCALL_64_switcher)
EXPORT_SYMBOL_GPL(entry_SYSCALL_64_switcher)
