/* SPDX-License-Identifier: GPL-2.0 */

SECTIONS {
#ifdef CONFIG_X86_PIE
	.got 0 : { BYTE(0) }
#endif
}
