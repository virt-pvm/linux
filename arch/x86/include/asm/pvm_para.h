/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PVM_PARA_H
#define _ASM_X86_PVM_PARA_H

#include <linux/init.h>
#include <uapi/asm/pvm_para.h>

#ifndef __ASSEMBLY__

#ifdef CONFIG_PVM_GUEST
#include <asm/irqflags.h>
#include <uapi/asm/kvm_para.h>

void pvm_relocate_kernel(struct boot_params *bp);
void __init pvm_early_setup(void);
void __init pvm_setup_early_traps(void);
void pvm_setup_event_handling(void);
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
 * pvm_detect() is required to be called before event handling is set up, but
 * it might also be possibly called under any hypervisor other than PVM.
 *
 * Any hypervisor that places the guest kernel in a state where the underlying
 * interrupt flag is enabled and the underlying CS is 3 should intercept
 * the CPUID instruction in the PVM_SYNTHETIC_CPUID, which must not trigger
 * any trap according to the corresponding [paravirtual] architecture.
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

	/* check the KVM_SIGNATURE leaf */
	eax = KVM_CPUID_SIGNATURE;
	pvm_cpuid(&eax, &signature[0], &signature[1], &signature[2]);
	if (memcmp(KVM_SIGNATURE, signature, 12))
		return false;

	/*
	 * PVM is the only KVM variant that places the guest kernel in
	 * a state where the underlying IF == 1 and underlying CS == 3.
	 */
	return true;
}
#else
static inline void pvm_early_setup(void)
{
}

static inline void pvm_setup_early_traps(void)
{
}

static inline void pvm_setup_event_handling(void)
{
}

static inline bool pvm_kernel_layout_relocate(void)
{
	return false;
}
#endif /* CONFIG_PVM_GUEST */

void entry_SYSCALL_64_pvm(void);
void pvm_user_event_entry(void);
void pvm_hypercall(void);
void pvm_retu_rip(void);
void __init pvm_early_event(struct pt_regs *regs, u32 vector, u32 errcode);
__visible noinstr void pvm_event(struct pt_regs *regs, u32 vector, u32 errcode);
void pvm_save_fl(void);
void pvm_irq_disable(void);
void pvm_irq_enable(void);
#endif /* !__ASSEMBLY__ */

#endif /* _ASM_X86_PVM_PARA_H */
