/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_X86_PVM_PARA_H
#define _UAPI_ASM_X86_PVM_PARA_H

#include <linux/const.h>

/*
 * The CPUID instruction in PVM guest might not be trapped and emulated,
 * so PVM guest should use the following two instructions instead:
 * "invlpg 0xffffffffff4d5650; cpuid;"
 *
 * PVM_SYNTHETIC_CPUID is supposed to not trigger any trap in the real or any
 * paravirtual x86 kernel mode and is also guaranteed to trigger a trap in the
 * underlying hardware user mode for the hypervisor emulating it. The
 * hypervisor emulates both of the basic instructions, while the INVLPG is
 * often emulated as an NOP since 0xffffffffff4d5650 is normally out of the
 * allowed linear address ranges.
 */
#define PVM_SYNTHETIC_CPUID		0x0f,0x01,0x3c,0x25,0x50, \
					0x56,0x4d,0xff,0x0f,0xa2
#define PVM_SYNTHETIC_CPUID_ADDRESS	0xffffffffff4d5650

/*
 * PVM virtual MSRS falls in the range 0x4b564df0-0x4b564dff, and it should not
 * conflict with KVM, see arch/x86/include/uapi/asm/kvm_para.h
 */
#define PVM_VIRTUAL_MSR_MAX_NR		15
#define PVM_VIRTUAL_MSR_BASE		0x4b564df0
#define PVM_VIRTUAL_MSR_MAX		(PVM_VIRTUAL_MSR_BASE+PVM_VIRTUAL_MSR_MAX_NR)

#define MSR_PVM_LINEAR_ADDRESS_RANGE	0x4b564df0
#define MSR_PVM_VCPU_STRUCT		0x4b564df1
// #define MSR_PVM_SWITCH_CR3		0x4b564df2 // deprecated, FIXME: reordering when sending v2
// #define MSR_PVM_SUPERVISOR_RSP	0x4b564df3 // deprecated, FIXME: reordering when sending v2
#define MSR_PVM_EVENT_ENTRY		0x4b564df4
#define MSR_PVM_RETU_RIP		0x4b564df5
// #define MSR_PVM_RETS_RIP		0x4b564df6

#define PVM_HC_SPECIAL_MAX_NR		(256)
#define PVM_HC_SPECIAL_BASE		(0x17088200)
#define PVM_HC_SPECIAL_MAX		(PVM_HC_SPECIAL_BASE+PVM_HC_SPECIAL_MAX_NR)

#define PVM_HC_LOAD_PGTBL		(PVM_HC_SPECIAL_BASE+0)
#define PVM_HC_IRQ_WIN			(PVM_HC_SPECIAL_BASE+1)
#define PVM_HC_IRQ_HALT			(PVM_HC_SPECIAL_BASE+2)
#define PVM_HC_TLB_FLUSH		(PVM_HC_SPECIAL_BASE+3)
#define PVM_HC_TLB_FLUSH_CURRENT	(PVM_HC_SPECIAL_BASE+4)
#define PVM_HC_TLB_INVLPG		(PVM_HC_SPECIAL_BASE+5)
#define PVM_HC_LOAD_GS			(PVM_HC_SPECIAL_BASE+6)
#define PVM_HC_RDMSR			(PVM_HC_SPECIAL_BASE+7)
#define PVM_HC_WRMSR			(PVM_HC_SPECIAL_BASE+8)
#define PVM_HC_LOAD_TLS			(PVM_HC_SPECIAL_BASE+9)

/*
 * PVM_EVENT_FLAGS_IF
 *	- Interrupt enable flag. The flag is set to respond to maskable
 *	  external interrupts; and cleared to inhibit maskable external
 *	  interrupts.
 *
 * PVM_EVENT_FLAGS_IP
 *	- interrupt pending flag. The hypervisor sets it if it fails to inject
 *	  a maskable event to the VCPU due to the interrupt-enable flag being
 *	  cleared in supervisor mode.
 */
#define PVM_EVENT_FLAGS_IP_BIT		8
#define PVM_EVENT_FLAGS_IP		_BITUL(PVM_EVENT_FLAGS_IP_BIT)
#define PVM_EVENT_FLAGS_IF_BIT		9
#define PVM_EVENT_FLAGS_IF		_BITUL(PVM_EVENT_FLAGS_IF_BIT)

/*
 * Bits for event_vector.
 *
 * The lowest 8-bit is the vector number for non async-exception vector events.
 *
 * The highest 8-bit is defined as following.  When the highest 8-bit is
 * non-zero in supervisor mode, only async-exception can be delivered without
 * jumping to the entry point.  The guest supervisor should check any pending
 * NMI/MCE when handling any events.  The hypervisor will also check it
 * for pending NMI/MCE in handling ERETU/ERETS.  Trying to deliver a non
 * async-exception when the highest 8-bit is non-zero in supervisor mode
 * will make it morphed into a triple-fault.
 *
 * The supervisor code should clear the highest 8-bit and get all the
 * delivered events from event_vector in a appropriate way.
 *
 * PVM_PVCS_EVENT_VECTOR_STD:
 *	- The supervisor software should set this bit before access to PVCS
 *	  for ERETU/ERETS.  The event_vector remains to be this value during
 *	  user mode and upon delivering a SYSCALL event from user mode.
 *	  Since async-exception can be dilivered and access to PVCS any time,
 *	  so it is required for protecting the fields related to supervisor
 *	  event delivering.
 *	- When a non async-exception is delivered, this bit is set and the
 *	  lowest 8-bit is the vector number.
 *
 * PVM_PVCS_EVENT_VECTOR_NMI
 * PVM_PVCS_EVENT_VECTOR_MCE
 *	- An NMI or MCE is being delivered (or along with other events) or
 *	  pending (during the period the supervisor is about to ERETU/ERETS)
 */
#define PVM_PVCS_EVENT_VECTOR_STD_BIT		8
#define PVM_PVCS_EVENT_VECTOR_STD		_BITUL(PVM_PVCS_EVENT_VECTOR_STD_BIT)
#define PVM_PVCS_EVENT_VECTOR_NMI_BIT		9
#define PVM_PVCS_EVENT_VECTOR_NMI		_BITUL(PVM_PVCS_EVENT_VECTOR_NMI_BIT)
#define PVM_PVCS_EVENT_VECTOR_MCE_BIT		10
#define PVM_PVCS_EVENT_VECTOR_MCE		_BITUL(PVM_PVCS_EVENT_VECTOR_MCE_BIT)

#define PVM_LOAD_PGTBL_FLAGS_TLB	_BITUL(0)
#define PVM_LOAD_PGTBL_FLAGS_LA57	_BITUL(1)

#ifndef __ASSEMBLY__

/*
 * PVM event delivery saves the information about the event and the old context
 * into the PVCS structure if the event is from user mode or from supervisor
 * mode with vector >=32. And ERETU synthetic instruction reads the return
 * state from the PVCS structure to restore the old context.
 */
struct pvm_vcpu_struct {
	/*
	 * This flag is only used in supervisor mode, with only bit 8 and
	 * bit 9 being valid. The other bits are reserved.
	 */
	u64 event_flags;
	u64 cr2;
	u64 reserved0[6];

	// For ERETS and the event from supervisor mode, user_cs, user_ss
	// user_gsbase, and pkru are ignored and kept untouched.
	u16 user_cs, user_ss;
	u16 event_errcode;
	u16 event_vector;
	u64 user_gsbase;
	u32 eflags;
	u32 pkru;
	u64 rip;
	u64 rcx;
	u64 r11;
	u64 reserved1[2];
};

#endif /* __ASSEMBLY__ */

#endif /* _UAPI_ASM_X86_PVM_PARA_H */
