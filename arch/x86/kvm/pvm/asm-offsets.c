// SPDX-License-Identifier: GPL-2.0
/*
 * Generate definitions needed by assembly language modules.
 * This code generates raw asm output which is post-processed to extract
 * and format the required data.
 */
#define COMPILE_OFFSETS

#include <linux/kbuild.h>

#include <asm/cpu_entry_area.h>
#include <asm/pvm_para.h>
#include "pvm_switcher.h"

static void __used common(void)
{
	DEFINE(CEA_ENTRY_STACK, offsetof(struct cpu_entry_area, entry_stack_page) +
				sizeof(struct entry_stack_page));
	DEFINE(CEA_DF_STACK, offsetof(struct cpu_entry_area, estacks.DF_stack) +
			     EXCEPTION_STKSZ);
	DEFINE(CEA_NMI_STACK, offsetof(struct cpu_entry_area, estacks.NMI_stack) +
			      EXCEPTION_STKSZ);
	DEFINE(CEA_DEBUG_STACK, offsetof(struct cpu_entry_area, estacks.DB_stack) +
			      EXCEPTION_STKSZ);
	DEFINE(CEA_MCE_STACK, offsetof(struct cpu_entry_area, estacks.MCE_stack) +
			      EXCEPTION_STKSZ);
	BLANK();

	DEFINE(TSS_EX_OFFSET, TSS_EX_OFFSET);
	DEFINE(CEA_TSS_EXTRA, offsetof(struct cpu_entry_area, tss) + TSS_EX_OFFSET);
	BLANK();

#define ENTRY(entry) OFFSET(TSS_EX_ ## entry, tss_extra, entry)
	ENTRY(host_cr3);
	ENTRY(host_rsp);
	ENTRY(host_gs_base);
	ENTRY(enter_cr3);
	ENTRY(switch_flags);
	ENTRY(smod_cr3);
	ENTRY(umod_cr3);
	ENTRY(pvcs);
	ENTRY(retu_rip);
	ENTRY(smod_entry);
	ENTRY(smod_gsbase);
	BLANK();
#undef ENTRY

#define ENTRY(entry) OFFSET(PVCS_ ## entry, pvm_vcpu_struct, entry)
	ENTRY(event_flags);
	ENTRY(event_errcode);
	ENTRY(event_vector);
	ENTRY(user_cs);
	ENTRY(user_ss);
	ENTRY(user_gsbase);
	ENTRY(eflags);
	ENTRY(rip);
	ENTRY(rcx);
	ENTRY(r11);
	BLANK();
#undef ENTRY
}
