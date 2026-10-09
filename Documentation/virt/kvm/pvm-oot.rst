.. SPDX-License-Identifier: GPL-2.0

PVM out-of-tree host modules
===========================

PVM OOT builds a matched replacement ``kvm.ko`` and ``kvm-pvm.ko`` against an
existing host kernel. The host kernel binary remains unchanged. A separate
PVM-enabled guest kernel is required.

Source and host interface boundaries
-----------------------------------

The KVM core, KVM-private headers, trace definitions and core object list must
come from the same PVM source baseline. Public host interfaces and generated
TSS/page-table offsets come from the target kernel build tree. Do not mix a
newer host's private KVM structures or build recipe with the older source core.

The baseline uses its native host APIs. Timer initialization, syscore
registration and IRQ-bypass registration have small adapter boundaries so
target patches can change their implementation without adding release-number
conditionals to core call sites. OOT mode builds only the core and PVM backend;
in-tree builds retain the usual vendor selection.

Build and deployment
--------------------

Use the target kernel's configured headers, generated configuration and
``Module.symvers``. Its KVM core must be an unloadable module. Use the matching
compiler and satisfy the host module-signing policy::

    make -C /lib/modules/$(uname -r)/build \
      M="$PWD/arch/x86/kvm" PVM_OOT_MODE=1 modules

Cross-version host support requires a separately qualified target patch set.
Successful compilation or matching vermagic alone does not qualify entry,
MMU or guest-state behavior. Keep source baseline and target qualification
separate; host version numbers do not identify distribution backports.

Load the pair only on an idle dedicated host or isolated L1 after stopping
existing KVM users. Unload stock vendor/core modules before loading both OOT
modules. Do not combine the OOT core with distribution VMX/SVM modules. To
return to hardware KVM, stop PVM users, unload both modules and reload the
complete original stock pair.

Current OOT requirements include FSGSBASE, RDTSCP and CMPXCHG16B. CPUID
faulting is required when interception is enabled. VMX/SVM is not required.
Host KASLR memory randomization, KPTI and FRED must be disabled; KASAN is
unsupported. Module-only deployment does not remove these boot constraints.
Keep networking/storage modules supplied by the distribution.
