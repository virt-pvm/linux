/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <asm/asm.h>
#include <asm/nospec-branch.h>
#include <asm/segment.h>

.macro KVM_DO_EVENT_IRQOFF call_insn call_target
	/*
	 * Unconditionally create a stack frame, getting the correct RSP on the
	 * stack (for x86-64) would take two instructions anyways, and RBP can
	 * be used to restore RSP to make objtool happy (see below).
	 */
	push %_ASM_BP
	mov %_ASM_SP, %_ASM_BP

#ifdef CONFIG_X86_64
	/*
	 * Align RSP to a 16-byte boundary (to emulate CPU behavior) before
	 * creating the synthetic interrupt stack frame for the IRQ/NMI.
	 */
	and  $-16, %rsp
	push $__KERNEL_DS
	push %rbp
#endif
	pushf
	push $__KERNEL_CS
	\call_insn \call_target

	/*
	 * "Restore" RSP from RBP, even though IRET has already unwound RSP to
	 * the correct value.  objtool doesn't know the callee will IRET and,
	 * without the explicit restore, thinks the stack is getting walloped.
	 * Using an unwind hint is problematic due to x86-64's dynamic alignment.
	 */
	mov %_ASM_BP, %_ASM_SP
	pop %_ASM_BP
	RET
.endm

.section .noinstr.text, "ax"

SYM_FUNC_START(kvm_do_host_nmi_irqoff)
	KVM_DO_EVENT_IRQOFF call asm_exc_nmi_kvm
SYM_FUNC_END(kvm_do_host_nmi_irqoff)

.section .text, "ax"

SYM_FUNC_START(kvm_do_host_interrupt_irqoff)
	KVM_DO_EVENT_IRQOFF CALL_NOSPEC _ASM_ARG1
SYM_FUNC_END(kvm_do_host_interrupt_irqoff)
