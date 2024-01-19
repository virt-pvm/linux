/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/asm-offsets.h>
#include <asm/percpu.h>
#include <asm/pvm_para.h>

#include "calling.h"

/* Construct struct pt_regs on stack */
.macro PUSH_IRET_FRAME_FROM_PVCS has_cs_ss:req is_kernel:req
	.if \has_cs_ss == 1
		movl	PER_CPU_VAR(pvm_vcpu_struct + PVCS_user_ss), %ecx
		andl	$0xff, %ecx
		pushq	%rcx				/* pt_regs->ss */
	.elseif \is_kernel == 1
		pushq	$__KERNEL_DS
	.else
		pushq	$__USER_DS
	.endif

	pushq	PER_CPU_VAR(pvm_vcpu_struct + PVCS_rsp) /* pt_regs->sp */
	movl	PER_CPU_VAR(pvm_vcpu_struct + PVCS_eflags), %ecx
	pushq	%rcx					/* pt_regs->flags */

	.if \has_cs_ss == 1
		movl	PER_CPU_VAR(pvm_vcpu_struct + PVCS_user_cs), %ecx
		andl	$0xff, %ecx
		pushq	%rcx				/* pt_regs->cs */
	.elseif \is_kernel == 1
		pushq	$__KERNEL_CS
	.else
		pushq	$__USER_CS
	.endif

	pushq	PER_CPU_VAR(pvm_vcpu_struct + PVCS_rip) /* pt_regs->ip */

	/* set %rcx, %r11 per PVM event handling specification */
	movq	PER_CPU_VAR(pvm_vcpu_struct + PVCS_rcx), %rcx
	movq	PER_CPU_VAR(pvm_vcpu_struct + PVCS_r11), %r11
.endm

.code64
.section .entry.text, "ax"

SYM_CODE_START(entry_SYSCALL_64_pvm)
	UNWIND_HINT_ENTRY
	ENDBR

	PUSH_IRET_FRAME_FROM_PVCS has_cs_ss=0 is_kernel=0

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
.popsection

/*
 * The new RIP value that PVM event delivery establishes is
 * MSR_PVM_EVENT_ENTRY for vector events that occur in user mode.
 */
	.align 64
SYM_CODE_START(pvm_user_event_entry)
	UNWIND_HINT_ENTRY
	ENDBR

	PUSH_IRET_FRAME_FROM_PVCS has_cs_ss=1 is_kernel=0
	/* pt_regs->orig_ax: errcode and vector */
	pushq	PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_errcode)

	PUSH_AND_CLEAR_REGS
	movq	%rsp, %rdi	/* %rdi -> pt_regs */
	call	pvm_event

SYM_INNER_LABEL(pvm_restore_regs_and_return_to_usermode, SYM_L_GLOBAL)
	POP_REGS

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
 * MSR_PVM_EVENT_ENTRY + 256 for events with vector < 32
 * that occur in supervisor mode.
 */
	.org pvm_user_event_entry+256, 0xcc
SYM_CODE_START(pvm_kernel_exception_entry)
	UNWIND_HINT_ENTRY
	ENDBR

	/* set %rcx, %r11 per PVM event handling specification */
	movq	6*8(%rsp), %rcx
	movq	7*8(%rsp), %r11

	PUSH_AND_CLEAR_REGS
	movq	%rsp, %rdi	/* %rdi -> pt_regs */
	call	pvm_event

	jmp pvm_restore_regs_and_return_to_kernel
SYM_CODE_END(pvm_kernel_exception_entry)

/*
 * The new RIP value that PVM event delivery establishes is
 * MSR_PVM_EVENT_ENTRY + 512 for events with vector >= 32
 * that occur in supervisor mode.
 */
	.org pvm_user_event_entry+512, 0xcc
SYM_CODE_START(pvm_kernel_interrupt_entry)
	UNWIND_HINT_ENTRY
	ENDBR

	/* Reserve space for rcx/r11 */
	subq	$16, %rsp

	PUSH_IRET_FRAME_FROM_PVCS has_cs_ss=0 is_kernel=1
	/* pt_regs->orig_ax: errcode and vector */
	pushq	PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_errcode)

	PUSH_AND_CLEAR_REGS
	movq	%rsp, %rdi	/* %rdi -> pt_regs */
	call	pvm_event

SYM_INNER_LABEL(pvm_restore_regs_and_return_to_kernel, SYM_L_GLOBAL)
	POP_REGS

	movq	%rcx, 6*8(%rsp)
	movq	%r11, 7*8(%rsp)
SYM_INNER_LABEL(pvm_rets_rip, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	syscall
SYM_CODE_END(pvm_kernel_interrupt_entry)
