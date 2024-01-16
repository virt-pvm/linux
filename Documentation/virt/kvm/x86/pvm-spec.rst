.. SPDX-License-Identifier: GPL-2.0

=====================
X86 PVM Specification
=====================

Underlying states
-----------------

**The PVM guest is only running on the underlying CPU with underlying
CPL=3.**

The term ``underlying`` refers to the actual hardware architecture
state. For example ``underlying CR3`` is the physic ``CR3`` of the
architecture. On the contrary, ``CR3`` or ``PVM CR3`` is the virtualized
``PVM CR3`` register. Any x86 states or registers in this document are
PVM states or registers unless any of "underlying", "physic", or
"hardware" is used to describe the states or registers. The doc uses
"underlying" mostly to describe the actual hardware architecture.

When the PVM guest is only running on the underlying CPU, it not only
runs with underlying CPL=3 but also with the following underlying states
and registers:

+-------------------+--------------------------------------------------+
| Registers         | Values                                           |
+===================+==================================================+
| Underlying RFLAGS | IOPL=VM=VIF=VIP=0, IF=1, fixed-bit1=1.           |
+-------------------+--------------------------------------------------+
| Underlying CR3    | implementation-defined value, typically          |
|                   | shadows the ``PVM CR3`` with extra pages         |
|                   | mapped including the switcher.                   |
+-------------------+--------------------------------------------------+
| Underlying CR0    | PE=PG=WP=ET=NE=AM=MP=1, CD=NW=EM=TS=0            |
+-------------------+--------------------------------------------------+
| Underlying CR4    | VME=PVI=0, PAE=FSGSBASE=1,                       |
|                   | others=implementation-defined                    |
+-------------------+--------------------------------------------------+
| Underlying EFER   | SCE=LMA=LME=1, NXE=implementation-defined.       |
+-------------------+--------------------------------------------------+
| Underlying GDTR   | All Entries with DPL<3 in the table are          |
|                   | hypervisor-defined values. The table must        |
|                   | have entries with DPL=3 for the selectors:       |
|                   | ``__USER32_CS``, ``__USER_CS``,                  |
|                   | ``__USER_DS`` (``__USER32_CS`` is                |
|                   | implementation-defined value,                    |
|                   | ``__USER_CS``\ =\ ``__USER32_CS``\ +8,           |
|                   | ``__USER_DS``\ =\ ``__USER32_CS``\ +16)          |
|                   | and may have other hypervisor-defined            |
|                   | DPL=3 data entries. Typically a                  |
|                   | host-defined CPUNODE entry is also in the        |
|                   | underlying ``GDT`` table for each host CPU       |
|                   | and its content (segment limit) can be           |
|                   | visible to the PVM guest.                        |
+-------------------+--------------------------------------------------+
| Underlying TR     | implementation-defined, no IOPORT is             |
|                   | allowed.                                         |
+-------------------+--------------------------------------------------+
| Underlying LDTR   | must be NULL                                     |
+-------------------+--------------------------------------------------+
| Underlying IDT    | implementation-defined. All gate entries         |
|                   | are with DPL=0, except for the entries for       |
|                   | vector=3,4 and a vector>32 (for legacy           |
|                   | syscall, normally 0x80) with DPL=3.              |
+-------------------+--------------------------------------------------+
| Underlying CS     | loaded with the selector ``__USER_CS`` or        |
|                   | ``__USER32_CS``.                                 |
+-------------------+--------------------------------------------------+
| Underlying SS     | loaded with the selector ``__USER_DS``.          |
+-------------------+--------------------------------------------------+
| Underlying        | loaded with the selector NULL or                 |
| DS/ES/FS/GS       | ``__USER_DS`` or other DPL=3 data entries        |
|                   | in the underlying ``GDT`` table.                 |
+-------------------+--------------------------------------------------+
| Underlying DR6    | 0xFFFF0FF0, until a hardware #DB is              |
|                   | delivered and the hardware exits the guest       |
+-------------------+--------------------------------------------------+
| Underlying DR7    | ``DR7_GD``\ =0; illegitimate linear              |
|                   | address (see address space separation) in        |
|                   | ``DR0-DR3`` causes the corresponding bits        |
|                   | in the ``underlying DR7`` cleared.               |
+-------------------+--------------------------------------------------+

In summary, the underlying states are typical x86 states to run
unprivileged software with stricter limitations.

PVM modes and states
--------------------

PVM has three PVM modes and they are modified IA32-e mode with PVM ABI.

- PVM 64bit supervisor mode: modified X86 64bit supervisor mode with
  PVM ABI

- PVM 64bit user mode: X86 64bit user mode with PVM event handling

- PVM 32bit compatible user mode: x86 compatible user mode with PVM
  event handling

| A VMM or hypervisor may also support non-PVM mode. They are non-IA32-e
  mode or IA32-e compatible kernel mode.
| The specification has nothing to do with any non-PVM mode. But if the
  hypervisor or the VMM can not boot the software directly into PVM
  mode, the hypervisor can implement non-PVM mode as bootstrap.
| Bootstrapping is implementation-defined. Bootstrapping in non-PVM mode
  should conform to pure X86 ABI until it enters X86 64bit supervisor
  mode and then the PVM hypervisor changes privilege registers(``CR0``,
  ``CR4,`` ``EFER``, ``MSR_STAR``) to conform to PVM mode and transits
  it into PVM 64bit supervisor mode.

States or registers on PVM modes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

+-----------------------+----------------------------------------------+
| Register              | Values                                       |
+=======================+==============================================+
| ``CR3`` and           | PVM switches ``CR3`` with                    |
| MSR_PVM_SWITCH_CR3    | MSR_PVM_SWITCH_CR3 when switching            |
|                       | supervisor/user mode. Hypercall              |
|                       | HC_LOAD_PGTBL can load ``CR3`` and           |
|                       | MSR_PVM_SWITCH_CR3 in one call. It           |
|                       | is recommended software to use               |
|                       | different ``CR3`` for supervisor             |
|                       | and user modes like KPTI.                    |
+-----------------------+----------------------------------------------+
| ``CR0``               | PE=PG=WP=ET=NE=AM=MP=1,                      |
|                       | CD=NW=EM=TS=0                                |
+-----------------------+----------------------------------------------+
| ``CR4``               | VME/PVI=0; PAE/FSGSBASE=1;                   |
|                       | UMIP/PKE/OSXSAVE/OSXMMEXCPT/OSFXSR=host.     |
|                       | PCID is recommended to be set even           |
|                       | if the ``underlying CR4.PCID`` is            |
|                       | not set. SMAP=SMEP=0 and the                 |
|                       | corresponding features are                   |
|                       | disabled in CPUID leaves.                    |
+-----------------------+----------------------------------------------+
| ``EFER``              | SCE=LMA=LME=1; NXE=underlying;               |
+-----------------------+----------------------------------------------+
| ``RFLAGS``            | Mapped to the underlying RFLAGS except for   |
|                       | the RFLAGS.IF. (The underlying RFLAGS.IF     |
|                       | is always 1.)                                |
|                       |                                              |
|                       | IOPL=VM=VIF=VIP=0, fixed-bit1=1.             |
|                       | AC is not recommended to be set in           |
|                       | the supervisor mode.                         |
|                       |                                              |
|                       | The PVM interrupt flag is defined as:        |
|                       |                                              |
|                       | - the bit 9 of the PVCS::event_flags when in |
|                       |   supervisor mode.                           |
|                       | - 1, when in user mode.                      |
|                       | - 0, when in supervisor mode if              |
|                       |   MSR_PVM_VCPU_CTRL_STRUCT=0.                |
+-----------------------+----------------------------------------------+
| ``GDTR``              | ignored (can be written and read             |
|                       | to get the last written value but            |
|                       | take no effect). The effective PVM           |
|                       | ``GDT`` table can be considered to           |
|                       | be a read-only table consisting of           |
|                       | entries: emulated supervisor mode            |
|                       | ``CS/SS`` and entries in                     |
|                       | ``underlying GDT`` with DPL=3. The           |
|                       | hypercall PVM_HC_LOAD_TLS can                |
|                       | modify part of the                           |
|                       | ``underlying GDT``.                          |
+-----------------------+----------------------------------------------+
| ``TR``                | ignored. Replaced by PVM event               |
|                       | handling                                     |
+-----------------------+----------------------------------------------+
| ``IDT``               | ignored. Replaced by PVM event               |
|                       | handling                                     |
+-----------------------+----------------------------------------------+
| ``LDTR``              | ignored. No replacement so it can            |
|                       | be considered disabled.                      |
+-----------------------+----------------------------------------------+
| ``CS`` in             | emulated. the ``underlying CS`` is           |
| supervisor mode       | ``__USER_CS``.                               |
+-----------------------+----------------------------------------------+
| ``CS`` in             | mapped to the ``underlying CS``              |
| user mode             | which is ``__USER_CS`` or                    |
|                       | ``__USER32_CS``                              |
+-----------------------+----------------------------------------------+
| ``SS`` in             | emulated. the ``underlying SS`` is           |
| supervisor mode       | ``__USER_DS``.                               |
+-----------------------+----------------------------------------------+
| ``SS`` in             | mapped to the ``underlying SS``              |
| user mode             | whose value is ``__USER_DS``.                |
+-----------------------+----------------------------------------------+
| DS/ES/FS/GS           | mapped to the                                |
|                       | ``underlying DS/ES/FS/GS``, loaded           |
|                       | with the selector NULL or                    |
|                       | ``__USER_DS`` or other DPL=3 data            |
|                       | entries in the ``underlying GDT``            |
|                       | table.                                       |
+-----------------------+----------------------------------------------+
| interrupt shadow mask | no interrupt shadow mask                     |
+-----------------------+----------------------------------------------+
| NMI shadow mask       | set when #NMI is delivered and               |
|                       | cleared when and only when                   |
|                       | EVENT_RETURN_USER or                         |
|                       | EVENT_RETURN_SUPERVISOR                      |
+-----------------------+----------------------------------------------+

MSR_PVM_VCPU_CTRL_STRUCT
~~~~~~~~~~~~~~~~~~~~~~~~

.. code::

   struct pvm_vcpu_struct {
       u64 event_flags;
       u32 event_errcode;
       u32 event_vector;
       u64 cr2;
       u64 reserved0[5];

       u16 user_cs, user_ss;
       u32 reserved1;
       u64 reserved2;
       u64 user_gsbase;
       u32 eflags;
       u32 pkru;
       u64 rip;
       u64 rsp;
       u64 rcx;
       u64 r11;
   }

PVCS::event_flags
^^^^^^^^^^^^^^^^^

| ``PVCS::event_flags.IF``\ (bit 9): interrupt enable flag: The flag
  is set to respond to maskable external interrupts; and cleared to
  inhibit maskable external interrupts.
|   The flag works only in supervisor mode. The VCPU always responds to
    maskable external interrupts regardless of the value of this flag in
    user mode. The flag is unchanged when the VCPU switches
    user/supervisor modes, even when handling the synthetic instruction
    EVENT_RETURN_USER. The guest is responsible for clearing the flag
    before switching to user mode (issuing EVENT_RETURN_USER) to ensure
    that the external interrupt is disabled when the VCPU is switched back
    from user mode later.

| ``PVCS::event_flags.IP``\ (bit 8): interrupt pending flag: The
  hypervisor sets it if it fails to inject a maskable event to the VCPU
  due to the interrupt-enable flag being cleared in supervisor mode.
|   The guest is responsible for issuing a hypercall PVM_HC_IRQ_WIN when
    the guest sees this bit after setting the PVCS::event_flags.IF.
    The hypervisor clears this bit in handling
    PVM_HC_IRQ_WIN/IRQ_HLT/EVENT_RETURN_USER/EVENT_RETURN_HYPERVISOR.

Other bits are reserved (Software should set them to zero).

PVCS::event_vector, PVCS::event_errcode
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If the vector event being delivered is from user mode or with vector >= 32
from supervisor mode ``PVCS::event_vector`` is set to the vector number. And
if the event has an error code, ``PVCS::event_errcode`` is set to the code.

PVCS::cr2
^^^^^^^^^

If the event being delivered is a page fault (#PF), ``PVCS::cr2`` is set
to be ``CR2`` (the faulting linear address).

PVCS::user_cs, PVCS::user_ss, PVCS::user_gsbase, PVCS::pkru, PVCS::rsp, PVCS::eflags, PVCS::rip, PVCS::rcx, PVCS::r11
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

| ``CS``, ``SS``, ``GSBASE``, ``PKRU``, ``RSP``, ``EFLAGS``, ``RIP``,
  ``RCX``, and ``R11`` are saved to ``PVCS::user_cs``,
  ``PVCS::user_ss``, ``PVCS::user_gsbase``, ``PVCS::pkru``,
  ``PVCS::rsp``, ``PVCS::eflags``, ``PVCS::rip``, ``PVCS::rcx``,
  ``PVCS::r11`` correspondingly when handling the synthetic instruction
  EVENT_RETURN_USER or vice vers when the architecture is switching to
  supervisor mode on any event in user mode.
| The value of ``PVCS::user_gsbase`` is semi-canonicalized before being
  set to the ``underlying GSBASE`` by adjusting bits 63:N to get the
  value of bit N–1, where N is the host’s linear address width (48 or
  57).
| The value of ``PVCS::eflags`` is standardized before setting to the
  ``underlying RFLAGS``. IOPL, VM, VIF, and VIP are cleared, and IF and
  FIXED1 are set.
| If an event with vector>=32 happens in supervisor mode, ``RSP``,
  ``EFLAGS``, ``RIP``, ``RCX``, and ``R11`` are saved to ``PVCS::rsp``,
  ``PVCS::eflags``, ``PVCS::rip``, ``PVCS::rcx``, ``PVCS::r11``
  correspondingly.

TSC MSRs
~~~~~~~~

TSC ABI is not settled down yet.

X86 MSR
~~~~~~~

MSR_GS_BASE/MSR_KERNEL_GS_BASE
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``MSR_GS_BASE`` is mapped to the ``underlying GSBASE``.

The ``MSR_KERNEL_GS_BASE`` is recommended to be synced with
``MSR_GS_BASE`` when in supervisor mode, and supervisor software is
recommended to maintain its version of ``MSR_KERNEL_GS_BASE``, and
``PVCS::user_gsbase`` is recommended to be used on this purpose.

When the CPU is switching from user mode to supervisor mode,
``PVCS::user_gsbase`` is updated as the value of ``MSR_GS_BASE`` (the
``underlying GSBASE``), and the value of ``MSR_GS_BASE`` is reset to
``MSR_KERNEL_GS_BASE`` atomically at the same time.

When the CPU is switching from supervisor mode to user mode,
``MSR_KERNEL_GS_BASE`` is normally set with the value of
``MSR_GS_BASE`` (but the hypervisor is allowed to omit this operation
because ``MSR_GS_BASE`` and ``MSR_KERNEL_GS_BASE`` are expected to be
the same when in supervisor), and the ``MSR_GS_BASE`` is loaded with
``PVCS::user_gsbase``.

WRGSBASE is not recommended to be used in supervisor mode.

MSR_SYSCALL_MASK
^^^^^^^^^^^^^^^^

Ignored, when syscall, ``RFLAGS`` is set to a default value.

MSR_STAR
^^^^^^^^

| ``__USER_CS,`` ``__USER_DS`` derived from it must be the same as
  host's ``__USER_CS,`` ``__USER_DS`` and have RPL=3. ``__KERNEL_CS``,
  ``__KERNEL_DS`` derived from it must have RPL=0 and be the same value
  as the current PVM ``CS`` ``SS`` registers hold respectively.
  Otherwise #GP.
| X86 forces RPL for derived ``__USER_CS,`` ``__USER_DS``,
  ``__USER32_CS``, ``__KERNEL_CS``, (not ``__KERNEL_DS``) when using
  them, so the RPLs can be an arbitrary value.

MSR_CSTAR, MSR_IA32_SYSENTER_CS/EIP/ESP
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Ignored, the software should use INTn instead for compatibility
syscalls.

MSR_IA32_PKRS
^^^^^^^^^^^^^

See "`Protection Keys <#protection-keys>`__".

PVM MSRs
~~~~~~~~

MSR_PVM_SWITCH_CR3
^^^^^^^^^^^^^^^^^^

Switched with ``CR3`` when mode switching. No TLB request is issued when
mode switching.

MSR_PVM_EVENT_ENTRY
^^^^^^^^^^^^^^^^^^^

| The value is the entry point for vector events from the PVM user mode.
| The value+256 is the entry point for vector events (vector < 32) from
  the PVM supervisor mode.
| The value+512 is the entry point for vector events (vector >= 32) from
  the PVM supervisor mode.

MSR_PVM_SUPERVISOR_RSP
^^^^^^^^^^^^^^^^^^^^^^

When switching from supervisor mode to user mode, this MSR is
automatically saved with ``RSP`` which is restored from it when
switching back from user mode.

MSR_PVM_SUPERVISOR_REDZONE
^^^^^^^^^^^^^^^^^^^^^^^^^^

When delivering the event from supervisor mode, a fixed-size area
is reserved below the current ``RSP`` and can be safely used by
guest. The size is specified in this MSR.

MSR_PVM_LINEAR_ADDRESS_RANGE
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

See "`Paging <#paging>`__".

PML4_INDEX_START, PML4_INDEX_END, PML5_INDEX_START, and PML5_INDEX_END
are encoded in the MSR and they are all 9 bits value with the most
significant bit set:

- bit 57-63 are all set; bit 48-56: PML5_INDEX_END, bit 56 must be set.
- bit 41-47 are all set; bit 32-40: PML5_INDEX_START, bit 40 must be set.
- bit 25-31 are all set; bit 16-24:PML4_INDEX_END, bit 24 must be set.
- bit 9-15 are all set; bit 0-8:PML4_INDEX_START, bit 8 must be set.

constraints:

- 256 <= PML5_INDEX_START < PML5_INDEX_END < 511
- 256 <= PML4_INDEX_START < PML4_INDEX_END < 511
- PML5_INDEX_START = PML5_INDEX_END = 0x1FF if the
  ``underlying CR4.LA57`` is not set.

The three legitimate address ranges for PVM virtual addresses:

::

  [ (1UL << 48) * (0xFE00 | PML5_INDEX_START), (1UL << 48) * (0xFE00 | PML5_INDEX_END) )
  [ (1UL << 39) * (0x1FFFE00 | PML4_INDEX_START), (1UL << 39) * (0x1FFFE00 | PML4_INDEX_END) )
  Lower half address (canonical address with bit63=0)

The MSR is initialized as the widest ranges when the CPU is reset. The
ranges should be sub-ranges of these initialized ranges when writing to
the MSR or migration.

| Pagetable walking is confined to these legitimate address ranges.
| Note:

- the top 2G is not in the range, so the guest supervisor software should
  be PIE kernel.
- Breakpoints (``DR0-DR3``) out of these ranges are not activated in the
  underlying DR7.

MSR_PVM_RETU_RIP, MSR_PVM_RETS_RIP
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The bare SYSCALL instruction staring at ``MSR_PVM_RETU_RIP`` or
``MSR_PVM_RETS_RIP`` is synthetic instructions to return to
user/supervisor mode. See "`PVM Synthetic
Instructions <#pvm-synthetic-instructions>`__" and "`Events and Mode
Changing <#events-and-mode-changing>`__".

.. pvm-synthetic-instructions:

PVM Synthetic Instructions
~~~~~~~~~~~~~~~~~~~~~~~~~~

PVM_SYNTHETIC_CPUID: invlpg 0xffffffffff4d5650;cpuid
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Works the same as the bare CPUID instruction generally, but it is
ensured to be handled by the PVM hypervisor and reports the corresponding
CPUID results for PVM.

PVM_SYNTHETIC_CPUID is supposed to not trigger any trap in the real or virtual
x86 kernel mode and is also guaranteed to trigger a trap in the underlying
hardware user mode for the hypervisor emulating it. The hypervisor emulates
both of the basic instructions, while the INVLPG is often emulated as an NOP
since 0xffffffffff4d5650 is normally out of the allowed linear address ranges.

EVENT_RETURN_SUPERVISOR: SYSCALL instruction starting at MSR_PVM_RETS_RIP
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

EVENT_RETURN_SUPERVISOR instruction returns from supervisor mode to
supervisor mode with the return state on the stack.

EVENT_RETURN_USER: SYSCALL instruction starting at MSR_PVM_RETU_RIP
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

EVENT_RETURN_USER instruction returns from supervisor mode to user
mode with the return state on the PVCS.

X86 Instructions with changed behavior
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

CPUID
^^^^^

Guest CPUID instruction would get the host's CPUID information normally
(when CPUID faulting is not enabled), and the synthetic instruction
KVM_CPUID is recommended to be used instead in guest supervisor
software.

SGDT/SIDT/SLDT/STR/SMSW
^^^^^^^^^^^^^^^^^^^^^^^

Guest SGDT/SIDT/SLDT/STR/SMSW instructions would get the host's
information. ``CR4.UMIP`` is in effect for guests only when the host
enables it.

LAR/LSL/VERR/VERW
^^^^^^^^^^^^^^^^^

Guest LAR/LSL/VERR/VERW instructions would get segment information from
host ``GDT``.

STAC/CLAC, SWAPGS, SYSEXIT, SYSRET
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

These instructions are not allowed for PVM supervisor software, using
them would result in unexpected behavior for the guest.

SYSENTER
^^^^^^^^

Results in #GP.

INT n
^^^^^

Only 0x80 and 0x3 are allowed in guests. Other INT n results in #GP.

RDPKRU/WRPKRU
^^^^^^^^^^^^^

When the guest is in supervisor mode, RDPKRU/WRPKRU would access the
``underlying PKRU`` register which is effectively PVM's
``MSR_IA32_PKRS``, so the guest supervisor software should access user
``PKRU`` via ``PVCS::pkru``.

CPUID leaf
~~~~~~~~~~

- Features disabled in the host are also disabled in the guest except for
  some specially handled features such as PCID and PKS.

  - PCID can be enabled even host PCID is disabled or the hardware doesn't
    support PCID.
  - PKS can be enabled if the host ``CR4.PKE`` is set because guest PKS is
    handled via hardware PKE.

- Features that require the hypervisor's handling but are not yet
  implemented are disabled in the guest.

- Some features that require hardware-privileged instructions are
  disabled in the guest.

  - XSAVES/XRESTORES/MSR_IA32_XSS is not enabled.

- Features that require distinguishing U/S pages are disabled in the
  guest.

  - SMEP/SMAP is disabled. LASS is also disabled.

KVM and PVM specific CPUID leafs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- When CPUID.EAX = KVM_CPUID_SIGNATURE (0x40000000) is entered, the
  output CPUID.EAX will be at least 0x40000002 which is
  KVM_CPUID_VENDOR_FEATURES (iff the hypervisor is a PVM hypervisor).
- When CPUID.EAX = KVM_CPUID_VENDOR_FEATURES(0x40000002) is entered,
  the output CPUID.EAX is PVM features; CPUID.EBX is 0x6d7670 ("pvm");
  CPUID.ECX and CPUID.EDX are reserved (0).

PVM booting sequence
^^^^^^^^^^^^^^^^^^^^

The PVM supervisor software has to relocate itself to conform its
allowed address ranges (See MSR_PVM_LINEAR_ADDRESS_RANGE) and prepare
itself for its special event handling mechanism on booting.

PVM software can be booted via linux general booting entry points, so
the software must detect whether itself is PVM as early as possible.

Booting sequence for detecting PVM in 64 bit linux general booting entry:

- check if the underlying EFLAGS.IF is 1
- check if the underlying CS.CPL is 3
- use the synthetic instruction KVM_CPUID to check KVM_CPUID_SIGNATURE
  and KVM_CPUID_VENDOR_FEATURES including checking the signature.

PVM is the first to define such booting sequence, so any later paravirt
hypervisor that can boot a 64 bit linux guest with underlying
EFLAGS.IF==1 and CS.CPL == 3 from the linux general booting entry points
should support the synthetic instruction KVM_CPUID for compatibility.

.. paging:

Paging
------

PVM MMU has two registers for pagetables: ``CR3`` and ``MSR_PVM_SWITCH_CR3``
and they are automatically switched on switching user/supervisor modes.
When in supervisor mode, ``CR3`` holds the kernel pagetable and
``MSR_PVM_SWITCH_CR3`` holds the user pagetable. These two pagetables work
in the same way as the two pagetables for KPTI.

The U/S bit in the paging struct is not always honored in PVM and is
sometimes ignored. User mode software may or may not access the final
page even if it is a supervisor page (in the view of X86). In fact, due
to the lack of legacy segment-based isolation, both the user page and
kernel page in PVM are shadowed as user pages in the underlying
pagetable with only hypervisor pages with the U bit cleared in the
underlying pagetable.

It is recommended to have no supervisor pages in the user pagetable. (To
make more use of the existing KPTI code, this rule can be relaxed as "it
is recommended that any paging tree should be all supervisor pages or
all user pages in the user pagetable except for the root PGD
pagetable.")

And the lack of legacy segment-based isolation is also the reason why
PVM has two registers for pagetables and the automatically switching
feature.

Due to the ignoring U/S bit, some features are disabled in PVM.

- SMEP is disabled and ``CR4.SMEP`` can not be set. The guest can use
  the NX bit for the user pages in the supervisor pagetable to regain
  the protection.

- SMAP is disabled and ``CR4.SMAP`` can not be set. The guest can
  emulate it via PKS.

- PKS feature is changed. Protection Key protection doesn't consider
  the U/S bit, it protects all the data access based on the key. The
  software should distribute different keys for supervisor pages and
  user pages.

TLB
~~~

| TLB entries are considered to be tagged by the root page table (PGD)
  pointer.

- Hypercall HC_TLB_FLUSH_CURENT, HC_TLB_FLUSH, and HC_TLB_LOAD_PGTBL
  flush TLB entries based on the tags (PGD of ``CR3`` and
  ``MSR_PVM_SWITCH_CR3``).
- ``CR3`` and ``MSR_PVM_SWITCH_CR3`` are swapped on switching
  user/supervisor mode but no TLB flushing is performed.
- Writing to ``CR3`` may not flush TLB for ``MSR_PVM_SWITCH_CR3``.
- WRMSR or HC_WRMSR to ``MSR_PVM_SWITCH_CR3`` doesn't flush TLB.
- ``CR4.PCID`` bit is recommended to be set even if the
  ``underlying CR4.PCID`` is cleared so that the PVM TLB can be flushed
  only on demand.

Exclusive address ranges
~~~~~~~~~~~~~~~~~~~~~~~~

A portion of the upper half of the linear address is separated from
the host kernel and the host doesn't use this separated portion. Only
the address in this separated portion and the lower half is the
guest-allowed linear address.

.. protection-keys:

Protection Keys
~~~~~~~~~~~~~~~

There are no distinctions between PVM user pages and PVM supervisor
pages in the real hardware. Protection Keys protection protects all data
accesses if enabled. ``CR4.PKE`` enables Protection Keys protection in
user mode while ``CR4.PKS`` enables Protection Keys protection in
supervisor mode.

``CR4.PKS`` can only be enabled when ``CR4.PKE`` is enabled and
``CR4.PKE`` can only be enabled when the underlying ``CR4.PKE`` is
enabled.

The ``underlying PKRU`` is the effective protection key register in both
supervisor mode and user mode.

The supervisor software should distribute different keys for supervisor
mode and user mode so that the PVM ``PKRU`` and ``MSR_IA32_PKRS``\ (in
guest supervisor view) are mapped to the different parts of the
``underlying PKRU`` at the same time. With distributed different keys,
``SUPERVISOR_KEYS_MASK`` can be defined in the guest supervisor.

- The ``MSR_IA32_PKRS`` (in guest supervisor view) is the
  ``underlying PKRU`` masked with ``SUPERVISOR_KEYS_MASK``, and it is
  invisible to the hypervisor since ``SUPERVISOR_KEYS_MASK`` is
  invisible to the hypervisor.
- ``MSR_IA32_PKRS`` (in hypervisor view) is recommended to be set as the
  same as ``MSR_IA32_PKRS`` (in guest supervisor view) before returning
  to the user mode so that after the next switchback, the user part of
  the ``underlying PKRU`` is access-denied and the supervisor part is
  already set properly.

If host/hardware ``CR4.PKE`` is set: the hypervisor/switcher will do
these no matter what the value of ``CR4.PKE`` or ``CR4.PKS:``

- supervisor -> user switching: load the ``underlying PKRU`` with
  ``PVCS::pkru``

- user -> supervisor switching: save the ``underlying PKRU`` to
  ``PVCS::pkru``\ ， load the ``underlying PKRU`` with a default value
  (0 or ``MSR_IA32_PKRS`` if ``CR4.PKS``).

SMAP
~~~~

| PVM doesn't support SMAP, if the guest supervisor wants to protect
  user access, it should use ``CR4.PKS``.

- The software should distribute different keys for supervisor mode and
  user mode.
- ``MSR_IA32_PKRS`` should be set with the user keys as access-denied.
- Events handlers in supervisor mode

  - Save the old ``underlying PKRU`` and set it to ``MSR_IA32_PKRS`` on entry
    so that the user part of the ``underlying PKRU`` is access-denied.
  - Restore the ``underlying PKRU`` on exit.

- When accessing to 'PVM user page' in supervisor mode

  - Set the ``underlying PKRU`` to (``MSR_IA32_PKRS`` &
    ``SUPERVISOR_KEYS_MASK``) \| ``PVCS::pkru``
  - Restore the ``underlying PKRU`` when after it finishes the access.


Events and Mode Changing
------------------------

Special Events
~~~~~~~~~~~~~~

No DoubleFault
^^^^^^^^^^^^^^

#DF is always promoted to TripleFault and brings down the PVM instance.

Discarded #DB
^^^^^^^^^^^^^

When MOV/POP SS from a watched address is followed by any
instruction-trap-induced supervisor mode entries, the MOV/POP SS that
hits the watchpoint will be discarded instead.

Vector events in user mode
~~~~~~~~~~~~~~~~~~~~~~~~~~

When vector events happen in user mode, the hypervisor is responsible
for saving guest registers into ``PVCS``, including ``SS``, ``CS``,
``PKRU``, ``GSBASE``, ``RSP``, ``RFLAGS``, ``RIP``, ``RCX``, and
``R11``.

The PVM hypervisor should also save the event vector into
``PVCS::event_vector`` and the error code in ``PVCS::event_errcode``,
and ``CR2`` into ``PVCS::cr2`` if it is pagefault event.

No change to ``PVCS::event_flags.IF``\ (bit 9) during delivering any
event in user mode, and the supervisor software is recommended to ensure
it unset.

Before returning to the guest supervisor, the PVM hypervisor will also
load values to vCPU with the following actions:

- Inexplicitly load ``CS/SS`` with the value the supervisor expects
  from ``MSR_STAR``.

  - The ``underlying CS/SS`` is loaded with host-defined ``__USER_CS``
    and ``__USER_DS``.

- Switch ``CR3`` with ``MSR_PVM_SWITCH_CR3`` without flushing TLB

  - The ``underlying CR3`` is the actual shadow root page table for
    the new ``PVM CR3``.

- Load ``GSBASE`` with ``MSR_KERNEL_GS_BASE``.

- Load ``RSP`` with ``MSR_PVM_KERNEL_RSP``.

- Load ``RIP/RCX`` with ``MSR_PVM_EVENT_ENTRY``.

- Load ``R11`` with (``X86_EFLAGS_IF`` \| ``X86_EFLAGS_FIXED``).

- Load ``RFLAGS`` with ``X86_EFLAGS_FIXED``.

  - The ``underlying RFLAGS`` is the same as ``R11`` which is
    (``X86_EFLAGS_IF`` \| ``X86_EFLAGS_FIXED``).

Vector events in supervisor mode
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The hypervisor handles vector events differently based on the vector
and there is no IST stacks.

The hypervisor handles vector events occurring in supervisor mode with
vector number < 32 as these uninterruptible steps:

- Subtract the fixed size (MSR_PVM_SUPERVISOR_REDZONE) from RSP.
- Align RSP down to a 16-byte boundary.
- Push R11
- Push Rcx
- Push SS
- Push original RSP
- Push RFLAGS

  - ``RFLAGS.IF`` comes from ``PVCS::event_flags.IF`` (bit 9),
     which means the pushed ``RFLAGS`` is ``(underlying RFLAGS ~
     X86_EFLAGS_IF) | (PVCS::event_flags & X86_EFLAGS_IF)``

- Push CS
- Push RIP
- Push vector (4 bytes), ERRCODE (4 bytes)
- If it is pagefault, save CR2 into PVCS:cr2
- No change to ``CS/SS.``
- Load ``RSP`` with the result after the last push as described above.
- Load ``R11`` with (``X86_EFLAGS_IF`` \| ``X86_EFLAGS_FIXED``).
- Load ``RFLAGS`` with ``X86_EFLAGS_FIXED``.

  - The ``underlying RFLAGS`` is the same as ``R11`` which is
    (``X86_EFLAGS_IF`` \| ``X86_EFLAGS_FIXED``).
  - PVCS::event_flags.IF will be cleared if it is previously set.

- Load ``RIP/RCX`` with ``MSR_PVM_EVENT_ENTRY``\ +256

The hypervisor handles vector events occurring in supervisor mode with
vector number => 32 as these uninterruptible steps:

- Save R11,RCX,RSP,EFLAGS,RIP to PVCS.
- Save the vector number to PVCS:event_vector.
- No change to ``CS/SS.``
- Subtract the fixed size (MSR_PVM_SUPERVISOR_REDZONE) from RSP.
- Load RSP with the current RSP value aligned down to a 16-byte boundary.
- Load ``R11`` with (``X86_EFLAGS_IF`` \| ``X86_EFLAGS_FIXED``).
- Load ``RFLAGS`` with ``X86_EFLAGS_FIXED``

  - The ``underlying RFLAGS`` is the same as ``R11`` which is
    (``X86_EFLAGS_IF`` \| ``X86_EFLAGS_FIXED``).
  - PVCS::event_flags.IF will be cleared if it is previously set.

- Load ``RIP/RCX`` with ``MSR_PVM_EVENT_ENTRY``\ +512

User SYSCALL event
~~~~~~~~~~~~~~~~~~

SYSCALL instruction in PVM user mode is a user SYSCALL event and the
hypervisor handles it almost as the same as vector events in user mode
except that no change to ``PVCS::event_vector``, ``PVCS::event_errcode``
and ``PVCS::cr2`` and ``RIP/RCX`` is loaded with ``MSR_LSTAR``.

Specifically, the hypervisor saves guest registers into ``PVCS``,
including ``SS``, ``CS``, ``PKRU``, ``GSBASE``, ``RSP``, ``RFLAGS``,
RIP, ``RCX``, and ``R11``, and loads values to vCPU with the following
actions:

- Inexplicitly load ``CS/SS`` with the value the supervisor expects
  from ``MSR_STAR``.

  - The ``underlying CS/SS`` is loaded with host-defined ``__USER_CS``
    and ``__USER_DS``.

- Switch ``CR3`` with ``MSR_PVM_SWITCH_CR3`` without flushing TLB

  - The ``underlying CR3`` is the actual shadow root page table for
    the new ``PVM CR3``.

- Load ``GSBASE`` with ``MSR_KERNEL_GS_BASE``.
- Load ``RSP`` with ``MSR_PVM_KERNEL_RSP``.
- Load ``RIP/RCX`` with ``MSR_LSTAR``.
- Load ``R11`` with (``X86_EFLAGS_IF`` \| ``X86_EFLAGS_FIXED``).
- Load ``RFLAGS`` with ``X86_EFLAGS_FIXED``.

  - The ``underlying RFLAGS`` is the same as ``R11`` which is
    (``X86_EFLAGS_IF`` \| ``X86_EFLAGS_FIXED``).
  - No change to ``PVCS::event_flags.IF``\ (bit 9) during delivering
    the SYSCALL event, and the supervisor software is recommended to
    ensure it unset.


Synthetic Instruction: EVENT_RETURN_USER
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This synthetic instruction is the only way for the PVM supervisor to
switch to user mode.

It works as the opposite operations of the event in user mode: load
``CS``, ``SS``, ``GSBASE``, ``PKRU``, ``RSP``, ``RFLAGS``, RIP, ``RCX``,
and ``R11`` from the ``PVCS`` respectively with some conversions to
``GSBASE`` and ``RFLAGS``; switch ``CR3`` and ``MSR_PVM_SWITCH_CR3`` and
return to user mode. The origian ``RSP`` is saved into
``MSR_PVM_SUPERVISOR_RSP``.

No change to ``PVCS::event_flags.IF``\ (bit 9) during handling it
and the supervisor software is recommended to ensure it unset.

Synthetic Instruction: EVENT_RETURN_SUPERVISOR
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

| Return to PVM supervisor mode.
| Work almost the same as IRETQ instruction except for ``RCX``, ``R11`` and
  ``ERRCODE`` are also in the stack.

It expects the stack frame:

.. code::

   R11
   RCX
   SS
   RSP
   RFLAGS
   CS
   RIP
   ERRCODE

Return to the context with RIP, RFLAGS, RSP, RCX, and R11 restored from the
stack.

The ``CS/SS`` and ``ERRCODE`` in the stack are ignored and the current PVM
``CS/SS`` are unchanged.

Hypercall event in supervisor mode
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Except for the synthetic instructions, SYSCALL instructions in PVM
supervisor mode is a HYPERCALL.

``RAX`` is the request number of the HYPERCALL. Some hypercall request
numbers are PVM-specific HYPERCALLs. Other values are KVM-specific
HYPERCALL.

HYPERCALL be issued in supervisor software
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

PVM supervisor software saves ``R10``, ``R11`` onto the stack and copies
``RCX`` into ``R10``, and then invokes the SYSCALL instruction. After
the HYPERCALL(SYSCALL instruction) returns, the software should get
``RCX`` from ``R10`` and restore ``R10`` and ``R11`` from the stack.

Hypercall's behavior should treat ``R10`` as ``RCX`` (in PVM
hypervisor):

.. code::

   RCX := R10
   pvm or kvm hypercall handling.
   R10 := RCX

If not specific, the return result is in ``RAX``.

PVM_HC_LOAD_PGTBL
^^^^^^^^^^^^^^^^^

| Parameters: *flags*, *supervisor_pgd*, *user_pgd*.
| Loads the pagetables
|  \* flags bit0: flush the new supervisor_pgd and user_pgd.
|  \* flags bit1: 4-level(bit1=0) or 5-level(bit1=1 && LA57 is supported
  in the VCPU's cpuid features) pagetable, the ``CR4.LA57`` bit is also
  changed correspondingly.
|  \* supervisor_pgd: set to ``CR3``
|  \* user_pgd: set to ``MSR_PVM_SWITCH_CR3``

PVM_HC_IRQ_WIN
^^^^^^^^^^^^^^

| No parameters.
| Infos the hypervisor that IRQ is enabled.

PVM_HC_IRQ_HLT
^^^^^^^^^^^^^^

| No parameters.
| Emulates the combination of X86 instructions "STI; HLT;".

PVM_HC_TLB_FLUSH
^^^^^^^^^^^^^^^^

| No parameters.
| Flush all TLB

PVM_HC_TLB_FLUSH_CURRENT
^^^^^^^^^^^^^^^^^^^^^^^^

| No parameters.
| Flush the TLB associated with the current ``PVM CR3`` and
  ``MSR_PVM_SWITCH_CR3``.

PVM_HC_TLB_INVLPG
^^^^^^^^^^^^^^^^^

| Parameters: *addr*.
| Emulates INVLPG and Flush the TLB entries of the address.

PVM_HC_LOAD_GS
^^^^^^^^^^^^^^

| Parameters: *gs_sel*.
| Load GS with the selector gs_sel, if it fails, load GS with the NULL
  selector.
| Return the resulting GS_BASE.

PVM_HC_RDMSR
^^^^^^^^^^^^

| Parameters: msr_index
| Returns the MSR value or zero if the MSR index is invalid

PVM_HC_WRMSR
^^^^^^^^^^^^

| Parameters: msr_index, msr_value
| return 0 or -EINVAL.

PVM_HC_LOAD_TLS
^^^^^^^^^^^^^^^

| Parameters: gdt_entry0, gdt_entry1, gdt_entry2
| Rectify gdt_entry0, gdt_entry1, and gdt_entry2 and set them
  continuously in the HOST ``GDT``.
| Return HOST ``GDT`` index for *gdt_entry0*.
