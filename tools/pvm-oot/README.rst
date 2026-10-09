.. SPDX-License-Identifier: GPL-2.0

PVM OOT target patches
======================

The source baseline remains native to 6.12. Distribution adaptation lives in
ordered patches and is applied to a fresh export, never to the baseline working
tree. The initial profile targets only Ubuntu 26.04.1 LTS x86-64,
``7.0.0-30-generic``, with its recorded configuration and exported-symbol table.
It does not imply support for other 7.0 kernels or Ubuntu ABIs.

This directory provides patches, their locked example profile, and a small
preparation tool. A separate OOT build/release repository can consume them and
own CI, artifacts, signatures and releases. No release repository or automatic
distribution-selection system is introduced here.

Prepare and build
-----------------

From this repository, select a fresh output directory::

    python3 tools/pvm-oot/prepare.py \
      --profile tools/pvm-oot/profiles/ubuntu-7.0.0-30-generic/profile.json \
      --source "$PWD" --kernel-build /lib/modules/7.0.0-30-generic/build \
      --cc gcc-15 --output /path/to/fresh-pvm-source
    make -C /lib/modules/7.0.0-30-generic/build \
      M=/path/to/fresh-pvm-source/arch/x86/kvm PVM_OOT_MODE=1 CC=gcc-15 -j2 modules

The preparation tool exports the exact source commit pinned in the profile,
checks its content digest, verifies the target release/config/symbols/compiler,
and applies checksum-verified patches in ``series`` order. It stops on unknown
inputs, a changed series, a patch failure or an existing output directory.
It does not retry with fuzzy context, skip patches or select another profile.
For an offline source export, ``--source-export`` checks the same content
digest before preparation. Generated build objects are not valid baseline
inputs. ``.pvm-oot-prepared.json`` records the source, patches, target fingerprints
and prepared source digest; retain it with build logs and the matched modules.

Compilation includes modpost against the actual target's ``Module.symvers``.
No host headers, kernel binary, export allowlist or symbol versions are changed.
The resulting ``kvm.ko`` and ``kvm-pvm.ko`` replace the complete stock KVM pair.
See ``Documentation/virt/kvm/pvm-oot.rst`` for load/rollback and CPU/boot
constraints. Keep guest source and guest bundle pins separate.

Patch responsibilities
----------------------

The five patches cover host headers/configuration, timer setup, syscore
registration, IRQ-bypass registration, and module export bridges. Timer,
syscore and IRQ-bypass adaptations are confined to baseline adapter boundaries.
Backend calls use explicit bridge names. One scoped FRED header redirect is
needed for calls inside host inline helpers; it applies only to backend objects
and does not affect the bridge's own host call. The IBPB feature condition and
``noinstr`` guest-transition requirements are retained.

These are interface-oriented patches selected by a target profile. A future
profile may reuse them after reviewing that target's actual APIs, configuration
and semantics. Move shared patches to a common location when a second profile
needs them; do not copy a series for every ABI. NOPKU/PKRU correctness fixes and
the optional DEBUGCTL optimization are independent changes and are excluded.

Baseline updates and qualification
----------------------------------

Released profiles pin a commit, not a moving branch. To update a baseline,
create a candidate profile, refresh each affected patch, update its content
digest and hashes, and run ordered apply, build/modpost and runtime gates.
Report the first failing patch and affected profiles. Conflict-free application
does not prove entry/TSS/MMU or guest-state semantics remain correct.

Native-baseline regression and target runtime qualification are separate gates.
Record build-only, load-tested and runtime-tested results separately. The
existing 6.12-core-on-7.0 target is a bounded transitional choice; it does not
inherit newer stock KVM fixes. Moving PVM to a newer core needs its own port,
review and qualification. Other ABIs (including ``7.0.0-31-generic``), AMD,
Secure Boot policies, suspend/resume and heterogeneous migration require their
own evidence. Prior qualification of a different commit cannot qualify a new
profile automatically.
