/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PVM_PARA_H
#define _ASM_X86_PVM_PARA_H

#include <linux/init.h>
#include <uapi/asm/pvm_para.h>

#ifndef __ASSEMBLY__
typedef void (*idtentry_t)(struct pt_regs *regs);

#ifdef CONFIG_PVM_GUEST
#include <asm/irqflags.h>
#include <uapi/asm/kvm_para.h>

void __init pvm_early_setup(void);
void __init pvm_install_sysvec(unsigned int sysvec, idtentry_t handler);
bool __init pvm_kernel_layout_relocate(void);

static inline void pvm_cpuid(unsigned int *eax, unsigned int *ebx,
			     unsigned int *ecx, unsigned int *edx)
{
	asm(__ASM_FORM(.byte PVM_SYNTHETIC_CPUID ;)
		: "=a" (*eax),
		  "=b" (*ebx),
		  "=c" (*ecx),
		  "=d" (*edx)
		: "0" (*eax), "2" (*ecx));
}

/*
 * pvm_detect() is called before event handling is set up and it might be
 * possibly called under any hypervisor other than PVM, so it should not
 * trigger any trap in all possible scenarios. PVM_SYNTHETIC_CPUID is supposed
 * to not trigger any trap in the real or virtual x86 kernel mode and is also
 * guaranteed to trigger a trap in the underlying hardware user mode for the
 * hypervisor emulating it.
 */
static inline bool pvm_detect(void)
{
	unsigned long cs;
	uint32_t eax, signature[3];

	/* check underlying interrupt flags */
	if (arch_irqs_disabled_flags(native_save_fl()))
		return false;

	/* check underlying CS */
	asm volatile("mov %%cs,%0\n\t" : "=r" (cs) : );
	if ((cs & 3) != 3)
		return false;

	/* check KVM_SIGNATURE and KVM_CPUID_VENDOR_FEATURES */
	eax = KVM_CPUID_SIGNATURE;
	pvm_cpuid(&eax, &signature[0], &signature[1], &signature[2]);
	if (memcmp(KVM_SIGNATURE, signature, 12))
		return false;
	if (eax < KVM_CPUID_VENDOR_FEATURES)
		return false;

	/* check PVM_CPUID_SIGNATURE */
	eax = KVM_CPUID_VENDOR_FEATURES;
	pvm_cpuid(&eax, &signature[0], &signature[1], &signature[2]);
	if (signature[0] != PVM_CPUID_SIGNATURE)
		return false;

	return true;
}
#else
static inline void pvm_early_setup(void)
{
}

static inline void pvm_install_sysvec(unsigned int sysvec, idtentry_t handler)
{
}

static inline bool pvm_kernel_layout_relocate(void)
{
	return false;
}
#endif /* CONFIG_PVM_GUEST */

void entry_SYSCALL_64_pvm(void);
void pvm_user_event_entry(void);
void pvm_retu_rip(void);
void pvm_rets_rip(void);
#endif /* !__ASSEMBLY__ */

#endif /* _ASM_X86_PVM_PARA_H */
