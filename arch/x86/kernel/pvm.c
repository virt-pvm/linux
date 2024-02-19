// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * KVM PVM paravirt_ops implementation
 *
 * Copyright (C) 2020 Ant Group
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */
#define pr_fmt(fmt) "pvm-guest: " fmt

#include <asm/cpufeature.h>
#include <asm/pvm_para.h>

void __init pvm_early_setup(void)
{
	if (!pvm_detect())
		return;

	setup_force_cpu_cap(X86_FEATURE_KVM_PVM_GUEST);
}
