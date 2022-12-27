#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

echo "unsigned long __stack_chk_guard; int foo(void) { char X[200]; return 3; }" | $* -S -x c -c -m64 -O0 -mcmodel=kernel -fno-PIE -fstack-protector -mstack-protector-guard-reg=gs -mstack-protector-guard-symbol=__stack_chk_guard - -o - 2> /dev/null | grep -q "%gs:__stack_chk_guard(%rip)"
