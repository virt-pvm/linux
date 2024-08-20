/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/asm-offsets.h>
#include <asm/percpu.h>
#include <asm/pvm_para.h>

#include "calling.h"

/* Construct struct pt_regs on stack */
.macro PUSH_IRET_FRAME_FROM_PVCS user:req
	.if \user == 1
		movl	PER_CPU_VAR(pvm_vcpu_struct + PVCS_user_ss), %ecx
		andq	$0xff, %rcx
		pushq	%rcx				/* pt_regs->ss */
	.else
		pushq	$__KERNEL_DS
	.endif

	pushq	PER_CPU_VAR(pvm_vcpu_struct + PVCS_rsp) /* pt_regs->sp */
	movl	PER_CPU_VAR(pvm_vcpu_struct + PVCS_eflags), %ecx
	pushq	%rcx					/* pt_regs->flags */

	.if \user == 1
		movl	PER_CPU_VAR(pvm_vcpu_struct + PVCS_user_cs), %ecx
		andq	$0xff, %rcx
		pushq	%rcx				/* pt_regs->cs */
	.else
		pushq	$__KERNEL_CS
	.endif

	pushq	PER_CPU_VAR(pvm_vcpu_struct + PVCS_rip) /* pt_regs->ip */

	/* set %rcx, %r11 per PVM event handling specification */
	movq	PER_CPU_VAR(pvm_vcpu_struct + PVCS_rcx), %rcx
	movq	PER_CPU_VAR(pvm_vcpu_struct + PVCS_r11), %r11
.endm

.macro pvm_enable_events
	orq	$PVM_EVENT_FLAGS_EF, PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_flags)
	btq	$PVM_EVENT_FLAGS_EP_BIT, PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_flags)
	jnc	.L_no_event_pending_\@
	pushq	%rax
	movq	$PVM_HC_EVENT_WIN, %rax
	call	pvm_hypercall
	popq	%rax
.L_no_event_pending_\@:
.endm

.macro pvm_disable_events
	btrq	$PVM_EVENT_FLAGS_EF_BIT, PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_flags)
.endm

.code64
.section .entry.text, "ax"

SYM_CODE_START(entry_SYSCALL_64_pvm)
	UNWIND_HINT_ENTRY
	ENDBR

	PUSH_IRET_FRAME_FROM_PVCS user=1

	pvm_enable_events

	jmp	entry_SYSCALL_64_after_hwframe
SYM_CODE_END(entry_SYSCALL_64_pvm)

.pushsection .noinstr.text, "ax"
SYM_FUNC_START(pvm_hypercall)
	push	%r11
	push	%r10
	movq	%rcx, %r10
	UNWIND_HINT_SAVE
	syscall
	UNWIND_HINT_RESTORE
	movq	%r10, %rcx
	popq	%r10
	popq	%r11
	RET
SYM_FUNC_END(pvm_hypercall)

SYM_FUNC_START(pvm_save_fl)
	movq	PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_flags), %rax
	RET
SYM_FUNC_END(pvm_save_fl)

SYM_FUNC_START(pvm_irq_disable)
	btrq	$X86_EFLAGS_IF_BIT, PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_flags)
	RET
SYM_FUNC_END(pvm_irq_disable)

SYM_FUNC_START(pvm_irq_enable)
	/* set X86_EFLAGS_IF */
	orq	$X86_EFLAGS_IF, PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_flags)
	btq	$PVM_EVENT_FLAGS_IP_BIT, PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_flags)
	jc	.L_maybe_interrupt_pending
	RET
.L_maybe_interrupt_pending:
	/* handle pending IRQ */
	movq	$PVM_HC_EVENT_WIN, %rax
	jmp	pvm_hypercall
SYM_FUNC_END(pvm_irq_enable)
.popsection

/*
 * The new RIP value that PVM event delivery establishes is
 * MSR_PVM_EVENT_ENTRY for vector events that occur in user mode.
 */
	.align 64
SYM_CODE_START(pvm_user_event_entry)
	UNWIND_HINT_ENTRY
	ENDBR

	PUSH_IRET_FRAME_FROM_PVCS user=1
	/* pt_regs->orig_ax: errcode and vector */
	pushq	PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_errcode)

	pvm_enable_events

	PUSH_AND_CLEAR_REGS
	movq	%rsp, %rdi	/* %rdi -> pt_regs */
	call	pvm_event

SYM_INNER_LABEL(pvm_restore_regs_and_return_to_usermode, SYM_L_GLOBAL)
	POP_REGS

	pvm_disable_events

	/* Copy %rcx, %r11 to the PVM CPU structure. */
	movq	%rcx, PER_CPU_VAR(pvm_vcpu_struct + PVCS_rcx)
	movq	%r11, PER_CPU_VAR(pvm_vcpu_struct + PVCS_r11)

	/* Copy the IRET frame to the PVM CPU structure. */
	movq	1*8(%rsp), %rcx		/* RIP */
	movq	%rcx, PER_CPU_VAR(pvm_vcpu_struct + PVCS_rip)
	movq	2*8(%rsp), %rcx		/* CS */
	movw	%cx, PER_CPU_VAR(pvm_vcpu_struct + PVCS_user_cs)
	movq	3*8(%rsp), %rcx		/* RFLAGS */
	movl	%ecx, PER_CPU_VAR(pvm_vcpu_struct + PVCS_eflags)
	movq	4*8(%rsp), %rcx		/* RSP */
	movq	%rcx, PER_CPU_VAR(pvm_vcpu_struct + PVCS_rsp)
	movq	5*8(%rsp), %rcx		/* SS */
	movw	%cx, PER_CPU_VAR(pvm_vcpu_struct + PVCS_user_ss)

	/*
	 * We are on the trampoline stack.  All regs are live.
	 * We can do future final exit work right here.
	 */
	STACKLEAK_ERASE_NOCLOBBER

	addq	$6*8, %rsp
SYM_INNER_LABEL(pvm_retu_rip, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	syscall
SYM_CODE_END(pvm_user_event_entry)

/*
 * The new RIP value that PVM event delivery establishes is
 * MSR_PVM_EVENT_ENTRY + 512 for supervisor mode events.
 */
	.org pvm_user_event_entry+512, 0xcc
SYM_CODE_START(pvm_kernel_event_entry)
	UNWIND_HINT_ENTRY
	ENDBR

	/*
	 * Reserve a fixed-size area in the current stack during an event from
	 * supervisor mode. This is for the int3 handler to emulate a call instruction.
	 */
	subq	$16, %rsp

	/* TODO: check stack overflow */

	PUSH_IRET_FRAME_FROM_PVCS user=0
	/* pt_regs->orig_ax: errcode and vector */
	pushq	PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_errcode)

	pvm_enable_events

	PUSH_AND_CLEAR_REGS
	movq	%rsp, %rdi	/* %rdi -> pt_regs */
	call	pvm_event

SYM_INNER_LABEL(pvm_restore_regs_and_return_to_kernel, SYM_L_GLOBAL)
	POP_REGS

	pvm_disable_events

	/* Copy %rcx, %r11 to the PVM CPU structure. */
	movq	%rcx, PER_CPU_VAR(pvm_vcpu_struct + PVCS_rcx)
	movq	%r11, PER_CPU_VAR(pvm_vcpu_struct + PVCS_r11)

	/* Copy the IRET frame to the PVM CPU structure. */
	movq	1*8(%rsp), %rcx		/* RIP */
	movq	%rcx, PER_CPU_VAR(pvm_vcpu_struct + PVCS_rip)
	movq	3*8(%rsp), %rcx		/* RFLAGS */
	movl	%ecx, PER_CPU_VAR(pvm_vcpu_struct + PVCS_eflags)
	movq	4*8(%rsp), %rcx		/* RSP */
	movq	%rcx, PER_CPU_VAR(pvm_vcpu_struct + PVCS_rsp)

	addq	$6*8, %rsp
SYM_INNER_LABEL(pvm_rets_rip, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	syscall
SYM_CODE_END(pvm_kernel_event_entry)
