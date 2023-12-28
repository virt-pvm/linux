// SPDX-License-Identifier: GPL-2.0-only
/*
 * Pagetable-based Virtual Machine driver for Linux
 *
 * Copyright (C) 2020 Ant Group
 * Copyright (C) 2020 Alibaba Group
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */
#include <linux/module.h>

MODULE_AUTHOR("AntGroup");
MODULE_LICENSE("GPL");

static void pvm_exit(void)
{
}
module_exit(pvm_exit);

static int __init pvm_init(void)
{
	return 0;
}
module_init(pvm_init);
