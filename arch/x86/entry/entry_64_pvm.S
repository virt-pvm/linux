/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/asm-offsets.h>
#include <asm/percpu.h>
#include <asm/pvm_para.h>

#include "calling.h"

#define REDZONE_SIZE	16

/* Construct struct pt_regs on stack */
.macro PUSH_IRET_FRAME_FROM_PVCS user:req
	movq	%rsp,	%r11
	.if \user == 1
		movq	PER_CPU_VAR(pcpu_hot + X86_top_of_stack), %rsp

		movl	PER_CPU_VAR(pvm_vcpu_struct + PVCS_user_ss), %ecx
		andl	$0xFFFF, %ecx
		pushq	%rcx				/* pt_regs->ss */
	.else
		andq	$-16, %rsp

		/*
		 * Reserve a fixed-size area in the current stack during an
		 * event from supervisor mode. This is for the int3 handler
		 * to emulate a call instruction.
		 */
		subq	$REDZONE_SIZE, %rsp

		/* TODO: check stack overflow */

		pushq	$__KERNEL_DS
	.endif

	pushq	%r11					/* pt_regs->sp */
	movl	PER_CPU_VAR(pvm_vcpu_struct + PVCS_eflags), %ecx
	pushq	%rcx					/* pt_regs->flags */

	.if \user == 1
		movl	PER_CPU_VAR(pvm_vcpu_struct + PVCS_user_cs), %ecx
		andl	$0xFFFF, %ecx
		pushq	%rcx				/* pt_regs->cs */
	.else
		pushq	$__KERNEL_CS
	.endif

	pushq	PER_CPU_VAR(pvm_vcpu_struct + PVCS_rip) /* pt_regs->ip */

	/* set %rcx, %r11 per PVM event handling specification */
	movq	PER_CPU_VAR(pvm_vcpu_struct + PVCS_rcx), %rcx
	movq	PER_CPU_VAR(pvm_vcpu_struct + PVCS_r11), %r11
.endm

.macro PUSH_REGS_AND_HANDLE_EVENT handler:req
	/* Invalidate orig_ax so that syscall_get_nr() works correctly */
	pushq	$-1
	PUSH_AND_CLEAR_REGS

	movw	PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_errcode), %dx
	xorl	%esi,  %esi
	// get all async exceptions and put PVCS with non-contended xchg
	xchgw	%si, PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_vector)
	movq	%rsp, %rdi	/* %rdi -> pt_regs */
	call	\handler
.endm

.macro POP_REGS_AND_LOAD_IRET_FRAME_INTO_PVCS
	POP_REGS

	// get PVCS before access to it
	btsw	$PVM_PVCS_EVENT_VECTOR_STD_BIT, PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_vector)

	// Copy %rcx, %r11 to the PVM CPU structure
	movq	%rcx, PER_CPU_VAR(pvm_vcpu_struct + PVCS_rcx)
	movq	%r11, PER_CPU_VAR(pvm_vcpu_struct + PVCS_r11)

	// Copy the IRET frame to the PVM CPU structure
	// PVCS_user_cs/ss are ignored for ERETS, load them anyway
	movq	1*8(%rsp), %rcx		/* RIP */
	movq	%rcx, PER_CPU_VAR(pvm_vcpu_struct + PVCS_rip)
	movq	2*8(%rsp), %rcx		/* CS */
	movw	%cx, PER_CPU_VAR(pvm_vcpu_struct + PVCS_user_cs)
	movq	3*8(%rsp), %rcx		/* RFLAGS */
	movl	%ecx, PER_CPU_VAR(pvm_vcpu_struct + PVCS_eflags)
	movq	5*8(%rsp), %rcx		/* SS */
	movw	%cx, PER_CPU_VAR(pvm_vcpu_struct + PVCS_user_ss)

	movq	4*8(%rsp), %rsp		/* RSP */
.endm

.code64
.section .entry.text, "ax"

SYM_CODE_START(entry_SYSCALL_64_pvm)
	UNWIND_HINT_ENTRY
	ENDBR

	PUSH_IRET_FRAME_FROM_PVCS user=1

	btrw	$PVM_PVCS_EVENT_VECTOR_STD_BIT, PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_vector)
	cmpw	$0, PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_vector)
	jz	entry_SYSCALL_64_after_hwframe

.L_async_exception:
	PUSH_REGS_AND_HANDLE_EVENT handler=pvm_event
	POP_REGS
	addq	$8, %rsp
	jmp	entry_SYSCALL_64_after_hwframe
SYM_CODE_END(entry_SYSCALL_64_pvm)

/*
 * The new RIP value that PVM event delivery establishes is
 * MSR_PVM_EVENT_ENTRY for vector events that occur in user mode.
 */
	.align 64
SYM_CODE_START(pvm_user_event_entry)
	UNWIND_HINT_ENTRY
	ENDBR

	PUSH_IRET_FRAME_FROM_PVCS user=1
	PUSH_REGS_AND_HANDLE_EVENT handler=pvm_event

SYM_INNER_LABEL(pvm_restore_regs_and_return_to_usermode, SYM_L_GLOBAL)
	STACKLEAK_ERASE
	POP_REGS_AND_LOAD_IRET_FRAME_INTO_PVCS
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

	PUSH_IRET_FRAME_FROM_PVCS user=0

	// if RIP < .L_pvm_supervisor_iret_irq_enabled_start ==> skip fixup
	leaq	.L_pvm_supervisor_iret_irq_enabled_start(%rip), %rcx
	cmpq	RIP-RIP(%rsp), %rcx
	ja	.L_pvm_supervisor_iret_irq_fixed

	// if RIP >= .L_pvm_supervisor_iret_irq_enabled_end ==> skip fixup
	leaq	.L_pvm_supervisor_iret_irq_enabled_end(%rip), %rcx
	cmpq	RIP-RIP(%rsp), %rcx
	jbe	.L_pvm_supervisor_iret_irq_fixed

	// fixup to Previous IRET Frame
	//	Previous IRET Frame
	//	RAX
	//	RCX
	//	R11
	//	HW_ring3 IRET Frame	<-- origin rsp
	//	padding for alignment (8 bytes)
	//	RED_ZONE (16 bytes)
	//	Current IRET Frame
	movq	RSP-RIP(%rsp), %rcx
	movq	(16+40)(%rcx), %rax
	movq	( 8+40)(%rcx), %r11
	movq	%r11, PER_CPU_VAR(pvm_vcpu_struct + PVCS_rcx)
	movq	( 0+40)(%rcx), %r11
	leaq	(24+40)(%rcx), %rsp
.L_pvm_supervisor_iret_irq_fixed:
	movq	PER_CPU_VAR(pvm_vcpu_struct + PVCS_rcx), %rcx

	PUSH_REGS_AND_HANDLE_EVENT handler=pvm_event

.L_pvm_supervisor_restore_regs_and_return:
	POP_REGS
	movq	%rax, (%rsp)
	pushq	%rcx
	pushq	%r11
	mov	%ss, %rax
	pushq	%rax		/* current hw SS for supervisor_iret */
	pushq	8*7(%rsp)	/* RSP */
	pushq	8*7(%rsp)	/* RFLAGS */
	mov	%cs, %rax
	pushq	%rax		/* current hw CS for supervisor_iret */
	pushq	8*7(%rsp)	/* RIP */
	testl	$X86_EFLAGS_IF, EFLAGS-RIP(%rsp)
	jz	.L_pvm_supervisor_iret
	orq	$X86_EFLAGS_IF, PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_flags)
.L_pvm_supervisor_iret_irq_enabled_start:
	btq	$PVM_EVENT_FLAGS_IP_BIT, PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_flags)
	jc	.L_pvm_supervisor_iret_irq_pending
.L_pvm_supervisor_iret:
	movq	8*7(%rsp), %rax
	iretq
.L_pvm_supervisor_iret_irq_pending:
	/* handle pending IRQ */
	movq	$PVM_HC_IRQ_WIN, %rax
	syscall
	// normally don't reach here, but it can only happend when there is actually no IRQ pending
	movq	8*5(%rsp), %r11
	movq	8*6(%rsp), %rcx
	jmp	.L_pvm_supervisor_iret
.L_pvm_supervisor_iret_irq_enabled_end:
SYM_CODE_END(pvm_kernel_event_entry)
