/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <linux/export.h>
#include <asm/segment.h>
#include <asm/asm-offsets.h>
#include <asm/msr.h>
#include <asm/percpu.h>
#include <asm/asm.h>
#include <asm/errno.h>
#include <asm/nospec-branch.h>
#include <asm/smap.h>
#include "pvm_switcher.h"
#include "asm-offsets.h"

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
 * states in PVM TSS extra storage.
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

	/* Load guest registers. */
	POP_REGS pop_rdi=0

	/*
	 * The IRET/SYSRET path expects pt_regs->orig_ax to carry the target
	 * guest CR3.  The initial enter path gets it from tss_extra; direct
	 * syscall switching stores its target CR3 before reusing the same code.
	 */
	movq	TSS_extra(enter_cr3), %rdi
	movq	%rdi, ORIG_RAX-RDI(%rsp)

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
	UNWIND_HINT_FUNC
	RET
SYM_FUNC_END(switcher_enter_guest)

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
	pushq	$0					/* ORIG_RAX */
	pushq	%rdi					/* rdi */

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

	/* switch umod to smod (switch_flags) and prepare smod cr3 in pt_regs->orig_ax */
	xorb	$SWITCH_FLAGS_MOD_TOGGLE, TSS_extra(switch_flags)
	movq	TSS_extra(smod_cr3), %rcx
	movq	%rcx, ORIG_RAX-RDI(%rsp)

	/* load smod registers from TSS_extra to sp0 stack or %r11 */
	movq	TSS_extra(smod_entry), %rcx
	movq	%rcx, RIP-RDI(%rsp)
	movq	TSS_extra(smod_gsbase), %r11

	/* switch host gsbase to guest gsbase, TSS_extra can't be use afterward */
	swapgs

	/* save guest gsbase as user_gsbase and switch to smod_gsbase */
	rdgsbase %rcx
	movq	%rcx, PVCS_user_gsbase(%rdi)
	wrgsbase %r11

	/* restore smod rflags/r11, rip/rcx and rsp for sysretq */
	movq	$SWITCH_ENTER_EFLAGS_FIXED, EFLAGS-RDI(%rsp)
	movq	$SWITCH_ENTER_EFLAGS_FIXED, %r11
	movq	RIP-RDI(%rsp), %rcx

.L_switcher_enter_guest_start:
.L_switcher_sysretq:
	UNWIND_HINT_IRET_REGS offset=16
	/* load target guest cr3 from pt_regs->orig_ax */
	movq	ORIG_RAX-RDI(%rsp), %rdi
	movq	%rdi, %cr3
	movq	RDI-RDI(%rsp), %rdi

	/* now everything is ready for sysretq except for %rsp */
	movq	RSP-RDI(%rsp), %rsp
	/* No instruction can be added between seting the guest %rsp and doing sysretq */
SYM_INNER_LABEL(entry_SYSRETQ_switcher_unsafe_stack, SYM_L_GLOBAL)
	sysretq

.L_switcher_iretq:
	UNWIND_HINT_IRET_REGS offset=16

	movq	ORIG_RAX-RDI(%rsp), %rdi
	movq	%rdi, %cr3
	movq	RDI-RDI(%rsp), %rdi
	addq	$(RIP-RDI), %rsp

SYM_INNER_LABEL(entry_IRETQ_switcher_rip, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	iretq
.L_switcher_enter_guest_end:

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

	/* switch smod to umod (switch_flags) and prepare umod cr3 in pt_regs->orig_ax */
	xorb	$SWITCH_FLAGS_MOD_TOGGLE, TSS_extra(switch_flags)
	movq	TSS_extra(umod_cr3), %rcx
	movq	%rcx, ORIG_RAX-RDI(%rsp)

	/* switch host gsbase to guest gsbase, TSS_extra can't be use afterward */
	swapgs

	/* write umod gsbase */
	movq	PVCS_user_gsbase(%rdi), %rcx
	canonical_rcx
	wrgsbase %rcx

	/* load flags, ip to sp0 stack and cx, r11 to registers */
	movl	PVCS_eflags(%rdi), %r11d
	movq	%r11, EFLAGS-RDI(%rsp)
	movq	PVCS_rip(%rdi), %rcx
	movq	%rcx, RIP-RDI(%rsp)
	movq	PVCS_rcx(%rdi), %rcx
	movq	PVCS_r11(%rdi), %r11

.L_switcher_return_to_guest:
	/*
	 * Now the RSP points to an IRET frame with guest state on the
	 * top of the sp0 stack.  Check if it can do sysretq.
	 */
	UNWIND_HINT_IRET_REGS offset=16

	andq	$SWITCH_ENTER_EFLAGS_ALLOWED, EFLAGS-RDI(%rsp)
	orq	$SWITCH_ENTER_EFLAGS_FIXED, EFLAGS-RDI(%rsp)
	testq	$(X86_EFLAGS_RF|X86_EFLAGS_TF), EFLAGS-RDI(%rsp)
	jnz	.L_switcher_iretq
	cmpq	%r11, EFLAGS-RDI(%rsp)
	jne	.L_switcher_iretq

	cmpq	%rcx, RIP-RDI(%rsp)
	jne	.L_switcher_iretq
	/*
	 * On Intel CPUs, SYSRET with non-canonical RCX/RIP will #GP
	 * in kernel space.  This essentially lets the guest take over
	 * the host, since guest controls RSP.
	 */
	canonical_rcx
	cmpq	%rcx, RIP-RDI(%rsp)
	je	.L_switcher_sysretq

	/* RCX matches for RIP only before RCX is canonicalized, restore RCX and do IRET. */
	movq	RIP-RDI(%rsp), %rcx
	jmp	.L_switcher_iretq

.L_switcher_return_to_hypervisor:
	popq	%rdi					/* saved rdi */
	movl	$SWITCH_EXIT_REASONS_SYSCALL, 4(%rsp)

	PUSH_AND_CLEAR_REGS
	jmp	switcher_return_from_guest
SYM_CODE_END(entry_SYSCALL_64_switcher)

	.align PVM_IDT_ALIGN
SYM_CODE_START(pvm_entries_start)
	/*
	 * OOT mode installs these entries in the remapped guest IDT.  Exceptions
	 * and interrupts taken while executing guest context land here with the
	 * hardware IRET frame on the current entry stack.  Store the vector in
	 * pt_regs->orig_ax and then funnel into pvm_idtentry(), which builds a
	 * full pt_regs and returns to the host through switcher_return_from_guest.
	 */
	vector = 0
	.rept 32
0:
	.if ((EXCEPTION_ERRCODE_MASK >> vector) & 1) == 0
		UNWIND_HINT_IRET_REGS
		ENDBR
		pushq	$-1
	.else
		UNWIND_HINT_IRET_REGS offset=8
		ENDBR
	.endif
	movl	$(vector), 4(%rsp)
	jmp	pvm_idtentry
	.fill 0b + PVM_IDT_ALIGN - ., 1, 0xcc
	vector = vector + 1
	.endr

	.rept 256 - 32
	UNWIND_HINT_IRET_REGS
0:
	ENDBR
	pushq	$-1
	movl	$(vector), 4(%rsp)
	jmp	pvm_idtentry
	.fill 0b + PVM_IDT_ALIGN - ., 1, 0xcc
	vector = vector + 1
	.endr
SYM_CODE_END(pvm_entries_start)

.macro switcher_ist_stack_to_sp0 CEA_from_STACKTOP:req
	/*
	 * Paranoid exceptions use their IST stack.  Convert the IST hardware
	 * frame into the same pt_regs layout used on the normal entry stack so
	 * the common PVM exit path can consume it.
	 */
	addq	$(6*8+\CEA_from_STACKTOP+CEA_ENTRY_STACK), %rsp
	pushq	(-CEA_ENTRY_STACK-\CEA_from_STACKTOP-1*8)(%rsp) /* pt_regs->ss */
	pushq	(-CEA_ENTRY_STACK-\CEA_from_STACKTOP-1*8)(%rsp) /* pt_regs->sp */
	pushq	(-CEA_ENTRY_STACK-\CEA_from_STACKTOP-1*8)(%rsp) /* pt_regs->flags */
	pushq	(-CEA_ENTRY_STACK-\CEA_from_STACKTOP-1*8)(%rsp) /* pt_regs->cs */
	pushq	(-CEA_ENTRY_STACK-\CEA_from_STACKTOP-1*8)(%rsp) /* pt_regs->ip */
	pushq	(-CEA_ENTRY_STACK-\CEA_from_STACKTOP-1*8)(%rsp) /* pt_regs->orig_ax, pvm_vector */
.endm

/* Used after the error code and vector have been pushed. */
.macro pvm_idtentry_body CEA_from_STACKTOP:req paranoid:req
	.if \CEA_from_STACKTOP != -CEA_ENTRY_STACK
	switcher_ist_stack_to_sp0 CEA_from_STACKTOP=\CEA_from_STACKTOP
	.endif

	PUSH_AND_CLEAR_REGS

	.if \paranoid == 0
	swapgs
	.else
	/*
	 * Paranoid entries can interrupt either side of SWAPGS.  Compare the
	 * current GSBASE against the host GSBASE saved in tss_extra; only swap
	 * when the interrupted context was still running with guest GSBASE.
	 */
	rdgsbase %rbp
	xorq	TSS_EX_host_gs_base+CEA_TSS_EXTRA-CEA_ENTRY_STACK+FRAME_SIZE(%rsp), %rbp
	jz	1f
	swapgs
1:
	.endif

	jmp	switcher_return_from_guest
.endm

SYM_CODE_START(pvm_idtentry)
	ASM_CLAC
	cld
	/* Guest IDT entries run with guest GSBASE; restore host GSBASE first. */
	swapgs

	/*
	 * CPL3 means the event came from guest context and can be handled as a
	 * normal PVM exit.  CPL0 here is expected only for exceptions raised by
	 * the switcher itself, most notably the IRET-to-guest fault path below.
	 */
	testb	$3, CS-ORIG_RAX(%rsp)
	jz	.L_from_switcher

.L_from_guest:
	PUSH_AND_CLEAR_REGS
	jmp	switcher_return_from_guest

.L_from_switcher:
	pushq	%rdi
	leaq	entry_IRETQ_switcher_rip(%rip), %rdi
	cmpq	%rdi, RIP-RDI(%rsp)
	jne	.L_unknown_switcher_exp

	/*
	 * The only expected CPL0 exception in this path is a bad IRET while
	 * entering the guest.  The guest frame is still on the entry stack, so
	 * make the exception look as if it happened immediately after IRET and
	 * let the common guest-exit path save the guest state.
	 */
	movq	%rsp, %rdi

	movq	RSP-RDI(%rsp), %rsp		/* rsp before IRET, it is guest iret frame */
	UNWIND_HINT_IRET_REGS
	pushq	ORIG_RAX-RDI(%rdi)
	movq	RDI-RDI(%rdi), %rdi
	jmp	.L_from_guest

.L_unknown_switcher_exp:
	/* Not expected.  Trap on a reliable stack instead of continuing. */
	int     $1
SYM_CODE_END(pvm_idtentry)

SYM_CODE_START(switcher_double_fault)
	UNWIND_HINT_IRET_ENTRY offset=8
	ENDBR
	ASM_CLAC
	cld

	movl	$8, 4(%rsp)
	pvm_idtentry_body CEA_from_STACKTOP=-CEA_DF_STACK, paranoid=1
SYM_CODE_END(switcher_double_fault)

.macro switcher_enter_guest_fixup CEA_from_STACKTOP:req
	/*
	 * NMI/MCE can hit while switcher_enter_guest() is already running on
	 * guest CR3.  The host handler must run on host CR3 and then returns with
	 * a plain IRET, so it cannot restore guest CR3 by itself.
	 *
	 * If RIP is in the fragile switcher window, rewrite the interrupted frame
	 * to the switcher IRETQ label and rebuild RSP from the saved guest frame.
	 * After the host handler returns, execution resumes from an enter-guest
	 * state that will switch to guest CR3 again before retrying the guest IRET.
	 */
	pushq	%rdi					/* on ORIG_RAX */

	leaq	.L_switcher_enter_guest_start(%rip), %rdi
	cmpq	%rdi, RIP-ORIG_RAX(%rsp)		/* RIP < start? */
	jb	.L_switcher_enter_guest_fixed_\@

	leaq	.L_switcher_enter_guest_end(%rip), %rdi
	cmpq	%rdi, RIP-ORIG_RAX(%rsp)		/* RIP >= end? */
	jae	.L_switcher_enter_guest_fixed_\@

	/* Now RIP is within [label_start, label_end); do fixup. */
	leaq	.L_switcher_iretq(%rip), %rdi
	movq	%rdi, RIP-ORIG_RAX(%rsp)
	leaq	CEA_ENTRY_STACK+\CEA_from_STACKTOP+RDI-ORIG_RAX(%rsp), %rdi
	movq	%rdi, RSP-ORIG_RAX(%rsp)

.L_switcher_enter_guest_fixed_\@:
	/* The host handler runs on host page tables. */
	movq	CEA_TSS_EXTRA+TSS_EX_host_cr3+\CEA_from_STACKTOP+FRAME_SIZE-ORIG_RAX(%rsp), %rdi
	movq	%rdi, %cr3
	popq	%rdi
.endm

.macro JMP_TO_HOST_VECTOR vector
	/*
	 * Tail-jump into the original host IDT handler.  Do not use INT or CALL:
	 * the host entry code expects the original hardware frame on the IST
	 * stack and has its own NMI nesting/paranoid-entry handling.
	 */
	ANNOTATE_RETPOLINE_SAFE
	jmp	*pvm_host_idt_entries+\vector*8(%rip)
	int3
.endm

SYM_CODE_START(switcher_nmi)
	UNWIND_HINT_ENTRY
	ENDBR
	ASM_CLAC
	cld

	/*
	 * Guest NMIs are PVM exits.  NMIs that interrupt the switcher itself stay
	 * on the NMI IST stack and are delivered directly to the host NMI entry,
	 * because the guest register image may not be complete yet.
	 */
	testb	$3, CS-RIP(%rsp)
	jz	.L_switcher_nmi_from_switcher
	pushq	$-1
	movl	$2, 4(%rsp)
	pvm_idtentry_body CEA_from_STACKTOP=-CEA_NMI_STACK, paranoid=0

.L_switcher_nmi_from_switcher:
	switcher_enter_guest_fixup CEA_from_STACKTOP=-CEA_NMI_STACK
	JMP_TO_HOST_VECTOR 2
SYM_CODE_END(switcher_nmi)

SYM_CODE_START(switcher_debug)
	UNWIND_HINT_IRET_REGS
	ENDBR
	ASM_CLAC
	cld

	testb	$3, CS-RIP(%rsp)
	jz	.L_switcher_debug_from_switcher
	pushq	$-1
	movl	$1, 4(%rsp)
	pvm_idtentry_body CEA_from_STACKTOP=-CEA_DEBUG_STACK, paranoid=0

.L_switcher_debug_from_switcher:
	/* Ignore #DB raised in the switcher window as the code is noist. */
	iretq
SYM_CODE_END(switcher_debug)

SYM_CODE_START(switcher_mce)
	UNWIND_HINT_IRET_REGS
	ENDBR
	ASM_CLAC
	cld

	/*
	 * Like NMI, a machine check from guest context exits to PVM, while one
	 * taken in the switcher window is forwarded to the host MCE entry after
	 * repairing any fragile switcher frame.
	 */
	testb	$3, CS-RIP(%rsp)
	jz	.L_switcher_mce_from_switcher
	pushq	$-1
	movl	$18, 4(%rsp)
	pvm_idtentry_body CEA_from_STACKTOP=-CEA_MCE_STACK, paranoid=0

.L_switcher_mce_from_switcher:
	switcher_enter_guest_fixup CEA_from_STACKTOP=-CEA_MCE_STACK
	JMP_TO_HOST_VECTOR 18
SYM_CODE_END(switcher_mce)

SYM_CODE_START(entry_pvm_SYSCALL32_ignore)
	UNWIND_HINT_END_OF_STACK
	ENDBR
	mov	$-ENOSYS, %eax
	sysretl
SYM_CODE_END(entry_pvm_SYSCALL32_ignore)
