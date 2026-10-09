/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KVM_IRQBYPASS_COMPAT_H
#define KVM_IRQBYPASS_COMPAT_H
#include <linux/irqbypass.h>

static inline int kvm_irq_bypass_register_consumer(
	struct irq_bypass_consumer *consumer, void *token)
{
	consumer->token = token;
	return irq_bypass_register_consumer(consumer);
}
#endif
