#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

# Before GCC 14.0, it would generate a 6-bytes GOT indirect call
# for fentry instead of a 5-bytes direct call when -fPIE is enabled.
# so we need to use different nop patching for this GOT indirect call.

echo "int foo(void) { return 3; }" | gcc -S -x c -m64 -O0 -pg -mfentry -fPIE - -o - 2>/dev/null | grep -q "GOT"
