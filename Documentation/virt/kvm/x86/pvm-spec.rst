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
| Underlying RFLAGS | IOPL=VM=VIF=VIP=0, IF=1, fixed-bit1=1. Other     |
|                   | flags are guest-controlled and passed through    |
|                   | to the hardware.                                 |
+-------------------+--------------------------------------------------+
| Underlying CR3    | implementation-defined value, typically          |
|                   | shadows the ``PVM CR3`` with extra pages         |
|                   | mapped including the switcher.                   |
+-------------------+--------------------------------------------------+
| Underlying CR0    | PE=PG=WP=ET=NE=AM=MP=1, CD=NW=EM=TS=0.           |
+-------------------+--------------------------------------------------+
| Underlying CR4    | VME=PVI=0, PAE=FSGSBASE=1. Others are            |
|                   | implementation-defined.                          |
+-------------------+--------------------------------------------------+
| Underlying EFER   | SCE=LMA=LME=1, NXE is implementation-defined.    |
+-------------------+--------------------------------------------------+
| Underlying GDTR   | All entries with DPL < 3 in the table are        |
|                   | hypervisor-defined values. The table must have   |
|                   | entries with DPL=3 for the selectors:            |
|                   | ``__USER32_CS``, ``__USER_CS``, and              |
|                   | ``__USER_DS``.                                   |
|                   | (``__USER32_CS`` is an implementation-defined    |
|                   | value, ``__USER_CS`` = ``__USER32_CS`` + 8,      |
|                   | ``__USER_DS`` = ``__USER32_CS`` + 16).           |
|                   | The table may have other hypervisor-defined      |
|                   | DPL=3 data entries. Typically, a host-defined    |
|                   | CPUNODE entry is also in the underlying ``GDT``  |
|                   | table for each host CPU, and its content         |
|                   | (segment limit) can be visible to the PVM guest. |
+-------------------+--------------------------------------------------+
| Underlying TR     | implementation-defined, no IOPORT is allowed.    |
+-------------------+--------------------------------------------------+
| Underlying LDTR   | must be NULL                                     |
+-------------------+--------------------------------------------------+
| Underlying IDT    | implementation-defined. All gate entries are     |
|                   | with DPL=0, except for the entries for vector=3, |
|                   | 4 and a vector > 32 (for legacy syscall,         |
|                   | normally 0x80) with DPL=3.                       |
+-------------------+--------------------------------------------------+
| Underlying CS     | loaded with the selector ``__USER_CS`` or        |
|                   | ``__USER32_CS``.                                 |
+-------------------+--------------------------------------------------+
| Underlying SS     | loaded with the selector ``__USER_DS``.          |
+-------------------+--------------------------------------------------+
| Underlying        | loaded with the selector NULL or ``__USER_DS``   |
| DS/ES/FS/GS       | or other DPL=3 data entries in the underlying    |
|                   | ``GDT`` table.                                   |
+-------------------+--------------------------------------------------+
| Underlying DR6    | 0xFFFF0FF0, until a hardware #DB is delivered    |
|                   | and the hardware exits the guest.                |
+-------------------+--------------------------------------------------+
| Underlying DR7    | ``DR7_GD`` = 0; illegitimate linear addresses    |
|                   | (see address space separation) in ``DR0-DR3``    |
|                   | cause the corresponding bits in the              |
|                   | ``underlying DR7`` to be cleared.                |
+-------------------+--------------------------------------------------+

In summary, the underlying states are typical x86 states to run
unprivileged software with stricter limitations.

PVM modes and states
--------------------

PVM has three PVM modes and they are modified IA32-e mode with PVM ABI.

- PVM 64bit supervisor mode: modified X86 64bit supervisor mode with
  PVM ABI

- PVM 64bit user mode: X86 64bit user mode

- PVM 32bit compatible user mode: x86 compatible user mode

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
| ``CR0``               | PE=PG=WP=ET=NE=AM=MP=1,                      |
|                       | CD=NW=EM=TS=0                                |
+-----------------------+----------------------------------------------+
| ``CR4``               | VME/PVI/SMAP=0; PAE/FSGSBASE=1;              |
|                       | UMIP/PKE/OSXSAVE/OSXMMEXCPT/OSFXSR=host;     |
|                       | PCID=1 even if the ``underlying CR4.PCID``   |
|                       | is not set.                                  |
|                       | SMEP = ``underlying EFER.NXE``               |
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
|                       |   supervisor mode if MSR_PVM_VCPU_STRUCT     |
|                       |   is set.                                    |
|                       | - 0, when in supervisor mode if              |
|                       |   MSR_PVM_VCPU_STRUCT=0.                     |
|                       | - 1, when in user mode.                      |
+-----------------------+----------------------------------------------+
| ``GDTR``              | ignored (can be set and get but takes no     |
|                       | effect). The effective PVM ``GDT`` table can |
|                       | be considered to be a read-only table        |
|                       | consisting of the following entries:         |
|                       |                                              |
|                       | - emulated supervisor mode ``CS/SS``         |
|                       | - entries in ``underlying GDT`` with DPL=3.  |
|                       |   The hypercall PVM_HC_LOAD_TLS can modify   |
|                       |   part of the ``underlying GDT``.            |
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
| ``CS`` in             | emulated, specified by ``MSR_STAR``.         |
| supervisor mode       | the ``underlying CS`` is ``__USER_CS``.      |
+-----------------------+----------------------------------------------+
| ``CS`` in             | mapped to the ``underlying CS``              |
| user mode             | which is ``__USER_CS`` or ``__USER32_CS``.   |
+-----------------------+----------------------------------------------+
| ``SS`` in             | emulated, specified by ``MSR_STAR``.         |
| supervisor mode       | the ``underlying SS`` is ``__USER_DS``.      |
+-----------------------+----------------------------------------------+
| ``SS`` in             | mapped to the ``underlying SS``              |
| user mode             | which normally is ``__USER_DS``.             |
+-----------------------+----------------------------------------------+
| DS/ES/FS/GS           | mapped to the                                |
|                       | ``underlying DS/ES/FS/GS``, can be loaded    |
|                       | with the selector NULL or                    |
|                       | ``__USER_DS`` or other DPL=3 data            |
|                       | entries in the ``underlying GDT`` table.     |
+-----------------------+----------------------------------------------+
| interrupt shadow mask | no interrupt shadow mask                     |
+-----------------------+----------------------------------------------+
| NMI shadow mask       | NMI is alwasy allowed when PVCS is           |
|                       | configured.                                  |
+-----------------------+----------------------------------------------+

MSR_PVM_VCPU_STRUCT
~~~~~~~~~~~~~~~~~~~

.. code::

   struct pvm_vcpu_struct {
       u64 event_flags;
       u64 cr2;
       u64 reserved0[6];

       u16 user_cs, user_ss;
       u16 event_errcode;
       u16 event_vector;
       u64 user_gsbase;
       u32 eflags;
       u32 pkru;
       u64 rip;
       u64 rcx;
       u64 r11;
       u64 reserved1[2];
   }

PVCS::event_flags
^^^^^^^^^^^^^^^^^

| ``PVCS::event_flags.IF`` (bit 9): interrupt enable flag. The flag
  is set to respond to maskable external interrupts, and cleared to
  inhibit them.
|   The flag works only in supervisor mode. The VCPU always responds to
    maskable external interrupts regardless of the value of this flag in
    user mode. The flag is unchanged when the VCPU switches
    user/supervisor modes. The guest is responsible for clearing the flag
    before switching to user mode (issuing EVENT_RETURN_USER) to ensure
    that the external interrupt is disabled when the VCPU is switched back
    from user mode later.

| ``PVCS::event_flags.IP`` (bit 8): interrupt pending flag. The
  hypervisor sets it if it fails to inject a maskable event to the VCPU
  due to the interrupt-enable flag being cleared in supervisor mode.
|   The guest is responsible for issuing a hypercall PVM_HC_IRQ_WIN when
    the guest sees this bit after setting the PVCS::event_flags.IF.
    This bit might be left over without an actual pending interrupt in some
    cases, which is harmless.  The hypervisor clears this bit in handling
    PVM_HC_IRQ_WIN/IRQ_HLT/EVENT_RETURN_USER when interrupt is enabled.

Other bits are reserved (Software should set them to zero).

PVCS::event_vector, PVCS::event_errcode
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If a vector event is being delivered, ``PVCS::event_vector`` is set. And
if the event has an error code, ``PVCS::event_errcode`` is set to the
error code.

The lowest 8-bit of ``PVCS::event_vector`` is the vector number for
non async-exception vector events.

The highest 8-bit is defined as following.  When the highest 8-bit is
non-zero in supervisor mode, only async-exception can be delivered without
jumping to the entry point.  The guest supervisor should check any pending
NMI/MCE when handling any events.  The hypervisor will also check it
for pending NMI/MCE in handling ERETU.  Trying to deliver a non
async-exception when the highest 8-bit is non-zero in supervisor mode
will make it morphed into a triple-fault.

The supervisor code should clear the highest 8-bit and get all the
delivered events from event_vector in a appropriate way.

PVM_PVCS_EVENT_VECTOR_STD:

- When a non async-exception is delivered, this bit is set and the
  lowest 8-bit is the vector number.
- The supervisor software should set this bit before access to PVCS
  for ERETU.  The event_vector remains to be this value during
  user mode and upon delivering a SYSCALL event from user mode.
  Since async-exception can be dilivered and access to PVCS any time,
  so it is required for protecting the fields related to supervisor
  event delivering.

PVM_PVCS_EVENT_VECTOR_NMI
PVM_PVCS_EVENT_VECTOR_MCE

- An NMI or MCE is being delivered (or along with other events) or
  pending (during the period the supervisor is about to ERETU)

PVCS::cr2
^^^^^^^^^

If the event being delivered is a page fault (#PF), ``PVCS::cr2`` is set
to be ``CR2`` (the faulting linear address).

PVCS::user_cs, PVCS::user_ss, PVCS::user_gsbase, PVCS::pkru, PVCS::eflags, PVCS::rip, PVCS::rcx, PVCS::r11
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

| These fields are stored with the corresponding registers' values when
  an event occurs and are loaded into the corresponding registers when
  EVENT_RETURN_USER.
| ``PVCS::user_cs``, ``PVCS::user_ss`` and ``PVCS::user_gsbase`` are for
  events that occurred in user mode or for EVENT_RETURN_USER only.
| The value of ``PVCS::user_gsbase`` is semi-canonicalized before being
  set to the ``underlying GSBASE`` by adjusting bits 63:N to the
  value of bit N-1, where N is the host’s linear address width (48 or
  57).
| The value of ``PVCS::eflags`` is standardized before being set to the
  ``underlying RFLAGS``, which means IOPL, VM, VIF, and VIP are cleared,
  and IF and FIXED1 are set.

TSC MSRs
~~~~~~~~

TSC is mapped to the underlying TSC and it is not stable and its scale
can be changed due to host schdedule, migration.

Use KVM clock for guest clocks.

X86 MSR
~~~~~~~

MSR_GS_BASE/MSR_KERNEL_GS_BASE
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``MSR_GS_BASE`` is mapped to the ``underlying GSBASE``.

When the CPU is switching from supervisor mode to user mode,
the ``MSR_GS_BASE`` is loaded with ``PVCS::user_gsbase``.

When the CPU is switching from user mode to supervisor mode,
``PVCS::user_gsbase`` is stored with the value of ``MSR_GS_BASE`` (the
``underlying GSBASE``), and the value of ``MSR_GS_BASE`` is reset to
``MSR_KERNEL_GS_BASE`` atomically at the same time.

The ``MSR_KERNEL_GS_BASE`` is recommended to be synced with
``MSR_GS_BASE`` when in supervisor mode at least before the next
EVENT_RETURN_USER.

MSR_SYSCALL_MASK
^^^^^^^^^^^^^^^^

Ignored, when syscall, ``RFLAGS`` is set to a default value.

MSR_STAR
^^^^^^^^

| ``__USER_CS`` and ``__USER_DS`` derived from it must be the same as
  the host's ``__USER_CS`` and ``__USER_DS`` and have RPL=3. ``__KERNEL_CS``
  and ``__KERNEL_DS`` derived from it must have RPL=0 and be the same value
  as the current PVM ``CS`` and ``SS`` registers hold respectively.
  Otherwise, a #GP fault will be triggered.
| X86 forces RPL for the derived ``__USER_CS``, ``__USER_DS``,
  ``__USER32_CS``, and ``__KERNEL_CS`` (not ``__KERNEL_DS``) when using
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

MSR_PVM_EVENT_ENTRY
^^^^^^^^^^^^^^^^^^^

| The value is the entry point for vector events from the PVM user mode.
| The value+512 is the entry point for vector events from
  the PVM supervisor mode.

MSR_PVM_LINEAR_ADDRESS_RANGE
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

See "`Paging <#paging>`__".

PML4_INDEX_START, PML4_INDEX_END, PML5_INDEX_START, and PML5_INDEX_END
are encoded in the MSR and they are all 9-bit values with the most
significant bit set:

- bit 57-63 are all set; bit 48-56: PML5_INDEX_END, bit 56 must be set.
- bit 41-47 are all set; bit 32-40: PML5_INDEX_START, bit 40 must be set.
- bit 25-31 are all set; bit 16-24: PML4_INDEX_END, bit 24 must be set.
- bit 9-15 are all set; bit 0-8: PML4_INDEX_START, bit 8 must be set.

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
  be a PIE kernel.
- Breakpoints (``DR0-DR3``) out of these ranges are not activated in the
  underlying DR7.

MSR_PVM_RETU_RIP
^^^^^^^^^^^^^^^^

The bare SYSCALL instruction starting at ``MSR_PVM_RETU_RIP`` is a synthetic
instruction to return to user mode. See "`PVM Synthetic Instructions
<#pvm-synthetic-instructions>`__" and "`Events and Mode Changing
<#events-and-mode-changing>`__".

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
both of the basic instructions, while the INVLPG is often emulated as a NOP
since 0xffffffffff4d5650 is normally out of the allowed linear address ranges.

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
PVM_SYNTHETIC_CPUID is recommended to be used instead in the guest
supervisor software.

SGDT/SIDT/SLDT/STR/SMSW
^^^^^^^^^^^^^^^^^^^^^^^

Guest SGDT/SIDT/SLDT/STR/SMSW instructions would get the host's
information. ``CR4.UMIP`` is in effect for guests only when the host
enables ``underlying CR4.UMIP``.

LAR/LSL/VERR/VERW
^^^^^^^^^^^^^^^^^

Guest LAR/LSL/VERR/VERW instructions would get segment information from
the host ``GDT``.

STAC/CLAC, SWAPGS, SYSEXIT, SYSRET
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

These instructions are not allowed for PVM supervisor software, using
them would result in unexpected behavior for the guest.

SYSENTER
^^^^^^^^

Results in #GP.

INT n
^^^^^

Only ``INT 3`` (breakpoint), ``INT 4`` (overflow) and ``INT 0x80`` (legacy
syscall) are allowed to be issued by the guest. Other ``INT n`` instructions
will result in a #GP fault.

RDPKRU/WRPKRU
^^^^^^^^^^^^^

When the guest is in supervisor mode, RDPKRU/WRPKRU would access the
``underlying PKRU`` register which is effectively PVM's
``MSR_IA32_PKRS``, so the guest supervisor software should access user
``PKRU`` via ``PVCS::pkru``.

CPUID leaf
~~~~~~~~~~

- Features disabled in the host are also disabled in the guest except for
  some specially handled features such as SMEP, PCID and PKS.

  - SMEP is enabled iff underlying EFER.NXE is enabled.
  - PCID must be enabled even if the host PCID is disabled or the hardware doesn't
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

  - SMAP is disabled.
  - LASS is disabled.
  - SMEP also requires distinguishing U/S pages but is emulated in other
    ways.

PVM booting sequence
^^^^^^^^^^^^^^^^^^^^

The PVM supervisor software has to relocate itself to conform to its
allowed address ranges (See MSR_PVM_LINEAR_ADDRESS_RANGE) and prepare
itself for its special event handling mechanism on booting.

PVM software can be booted via linux general booting entry points, so
the software must detect whether it is PVM as early as possible.

Booting sequence for detecting PVM in 64-bit linux general booting entry:

- check if the underlying EFLAGS.IF is 1
- check if the underlying CS.CPL is 3
- use the synthetic instruction PVM_SYNTHETIC_CPUID to check
  KVM_CPUID_SIGNATURE

PVM is the first to define such a booting sequence, so any later paravirt
hypervisor that can boot a 64-bit linux guest with underlying
EFLAGS.IF==1 and CS.CPL == 3 from the linux general booting entry points
should support the synthetic instruction PVM_SYNTHETIC_CPUID for
compatibility.

.. paging:

Paging
------

The hypervisor manages two underlying shadow page tables for each guest
pagetable to maintain proper kernel/user isolation based on the U/S bit
in the guest paging struct with no kernel page-table-entry shadowed into
the underlying user pagetables.

Both the underlying user page and kernel page are shadowed as user pages
(with the U bit), and some features based on the hardware U/S bit are disabled
or changed in PVM.

- SMEP is forced enabled and ``CR4.SMEP`` is always set if the underlying
  hardware supports NX.

- SMAP is disabled and ``CR4.SMAP`` can not be set. The guest can
  emulate it via PKS.

- The PKS feature is changed. Protection Key protection doesn't consider
  the U/S bit; it protects all the data access based on the key. The
  software should distribute different keys for supervisor pages and
  user pages.


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
mode and user mode so that the PVM ``PKRU`` and ``MSR_IA32_PKRS`` (in
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

If host/hardware ``CR4.PKE`` is set, the hypervisor/switcher will do
these no matter what the value of ``CR4.PKE`` or ``CR4.PKS`` is:

- supervisor -> user switching: load the ``underlying PKRU`` with
  ``PVCS::pkru``

- user -> supervisor switching: save the ``underlying PKRU`` to
  ``PVCS::pkru``, and load the ``underlying PKRU`` with a default value
  (0 or ``MSR_IA32_PKRS`` if ``CR4.PKS``).

SMAP
~~~~

| PVM doesn't support SMAP. If the guest supervisor wants to protect
  user access, it should use ``CR4.PKS``.

- The software should distribute different keys for supervisor mode and
  user mode.
- ``MSR_IA32_PKRS`` should be set with the user keys as access-denied.
- Events handlers in supervisor mode

  - Save the old ``underlying PKRU`` and set it to ``MSR_IA32_PKRS`` on entry
    so that the user part of the ``underlying PKRU`` is access-denied.
  - Restore the ``underlying PKRU`` on exit.

- When accessing a 'PVM user page' in supervisor mode

  - Set the ``underlying PKRU`` to (``MSR_IA32_PKRS`` &
    ``SUPERVISOR_KEYS_MASK``) | ``PVCS::pkru``
  - Restore the ``underlying PKRU`` after it finishes the access.


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

PVM events
~~~~~~~~~~

The hypervisor handles events with saved context in ``PVCS``, and no
change to the stacks nor the stack pointer ``RSP``.

The hypervisor handles vector events with these uninterruptible steps:

- If it is an async event in supervisor mode, set the async event bit in
  ``PVCS::event_vector`` and skip all following steps.

- Set PVM_PVCS_EVENT_VECTOR_STD in ``PVCS::event_vector`` if the hight
  8-bit in ``PVCS::event_vector`` is zero and it is a supervisor event.

  - If the hight 8-bit in ``PVCS::event_vector`` is not zero and it is
    a supervisor event, morph the event to tripple fault.
  - If it is a user event, no checks on ``PVCS::event_vector``.

- Save ``RFLAGS``, ``RIP``, ``RCX``, and ``R11`` into ``PVCS``

- Save ``SS``, ``CS``, ``PKRU``, and ``GSBASE`` into ``PVCS`` if it is a user event.

- Save the event vector into lowest 8-bit in ``PVCS::event_vector`` and
  the error code into ``PVCS::event_errcode`` if it is a vector event.

- Save ``CR2`` into ``PVCS::cr2`` if it is a pagefault event.

- Change the mode to supervisor mode if it is a user event.

  - ``CS/SS`` is changed with the value from ``MSR_STAR``.
  - The ``underlying CS/SS`` is loaded with host-defined ``__USER_CS``
    and ``__USER_DS``.
  - No mode change and no change to ``CS/SS`` if it is a supervisor event.

- Load ``GSBASE`` with ``MSR_KERNEL_GS_BASE`` if it is a user event.

- Load ``underlying PKRU`` with a special value.

- Load ``R11`` with (``X86_EFLAGS_IF`` | ``X86_EFLAGS_FIXED``).

- Load ``RFLAGS`` with ``X86_EFLAGS_FIXED``

  - The ``underlying RFLAGS`` is the same as ``R11`` which is
    (``X86_EFLAGS_IF`` | ``X86_EFLAGS_FIXED``).
  - PVCS::event_flags.IF will be cleared if it was previously set if it is a
    supervisor event.
  - No change to ``PVCS::event_flags.IF`` if it is a user event and the
    supervisor software must clear it on switching to user.

- Load ``RIP/RCX`` with ``MSR_LSTAR`` if it is a syscall event.
- Load ``RIP/RCX`` with ``MSR_PVM_EVENT_ENTRY`` if it is a user mode vector event.
- Load ``RIP/RCX`` with ``MSR_PVM_EVENT_ENTRY`` + 512 if it is a supervisor mode
  vector event.

Synthetic Instruction: EVENT_RETURN_USER
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This synthetic instruction is the only way for the PVM supervisor to
switch to user mode.

It works as the opposite operations of the event in user mode: load
``CS``, ``SS``, ``GSBASE``, ``PKRU``, ``RFLAGS``, ``RIP``, ``RCX``,
and ``R11`` from the ``PVCS`` respectively with some conversions to
``GSBASE`` and ``RFLAGS``.

No change to ``PVCS::event_flags.IF`` (bit 9) during handling it
and the supervisor software should clear it.

Finally, it checks the async event bits in ``PVCS::event_vector``
and reinject them if any.

Hypercall event in supervisor mode
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Except for the synthetic instructions, SYSCALL instructions in PVM
supervisor mode are HYPERCALLs.

``RAX`` is the request number of the HYPERCALL. Some hypercall request
numbers are PVM-specific HYPERCALLs. Other values are KVM-specific
HYPERCALLs.

HYPERCALL be issued in supervisor software
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

PVM supervisor software saves ``R10`` and ``R11`` onto the stack and copies
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

| Parameters: *flags*, *cr3*.
| Loads the pagetables
|  *flags* bit0: flush the TLB tagged with the PCID of *cr3*.
|  *flags* bit1: 4-level(bit1=0) or 5-level(bit1=1) pagetable, the
      ``CR4.LA57`` bit is also updated correspondingly.
|  *cr3*: set to ``CR3``

PVM_HC_IRQ_WIN
^^^^^^^^^^^^^^

| No parameters.
| Informs the hypervisor that IRQ is enabled.

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
| Flush the TLB associated with the current ``PCID``

PVM_HC_TLB_INVLPG
^^^^^^^^^^^^^^^^^

| Parameters: *addr*.
| Emulates INVLPG and flushes the TLB entries of the address.

PVM_HC_LOAD_GS
^^^^^^^^^^^^^^

| Parameters: *gs_sel*.
| Load GS with the selector *gs_sel*, if it fails, load GS with the NULL
  selector.
| Return the resulting GS_BASE.

PVM_HC_RDMSR
^^^^^^^^^^^^

| Parameters: *msr_index*
| Returns the MSR value or zero if the MSR index is invalid

PVM_HC_WRMSR
^^^^^^^^^^^^

| Parameters: *msr_index*, *msr_value*
| return 0 or -EINVAL.

PVM_HC_LOAD_TLS
^^^^^^^^^^^^^^^

| Parameters: *gdt_entry0*, *gdt_entry1*, *gdt_entry2*
| Rectify *gdt_entry0*, *gdt_entry1*, and *gdt_entry2* and set them
  continuously in the HOST ``GDT``.
| Return HOST ``GDT`` index for *gdt_entry0*.
