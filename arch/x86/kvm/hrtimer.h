/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KVM_X86_HRTIMER_COMPAT_H
#define KVM_X86_HRTIMER_COMPAT_H
#include <linux/hrtimer.h>

static inline void kvm_hrtimer_init(struct hrtimer *timer, clockid_t clock,
				    enum hrtimer_mode mode,
				    enum hrtimer_restart (*callback)(struct hrtimer *))
{
	hrtimer_init(timer, clock, mode);
	timer->function = callback;
}
#endif
