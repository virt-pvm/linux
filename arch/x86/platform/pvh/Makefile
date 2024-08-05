# SPDX-License-Identifier: GPL-2.0
OBJECT_FILES_NON_STANDARD_head.o := y

CFLAGS_REMOVE_enlighten.o = $(CC_FLAGS_FTRACE)

obj-$(CONFIG_PVH) += enlighten.o
obj-$(CONFIG_PVH) += head.o
