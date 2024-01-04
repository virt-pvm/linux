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
	jmp	native_irq_return_iret

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

	pushq	$0					/* pt_regs->orig_ax */
	movl	$SWITCH_EXIT_REASONS_SYSCALL, 4(%rsp)

	PUSH_AND_CLEAR_REGS
	jmp	switcher_return_from_guest
SYM_CODE_END(entry_SYSCALL_64_switcher)
EXPORT_SYMBOL_GPL(entry_SYSCALL_64_switcher)
