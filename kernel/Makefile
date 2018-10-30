kernel/trace/Makefile

# SPDX-License-Identifier: GPL-2.0

# Do not instrument the tracer itself:

ifdef CONFIG_FUNCTION_TRACER
ORIG_CFLAGS := $(KBUILD_CFLAGS)
KBUILD_CFLAGS = $(subst $(CC_FLAGS_FTRACE),,$(ORIG_CFLAGS))

ifdef CONFIG_FTRACE_SELFTEST
# selftest needs instrumentation
CFLAGS_trace_selftest_dynamic.o = $(CC_FLAGS_FTRACE)
obj-y += trace_selftest_dynamic.o
endif
endif

ifdef CONFIG_FTRACE_STARTUP_TEST
CFLAGS_trace_kprobe_selftest.o = $(CC_FLAGS_FTRACE)
obj-$(CONFIG_KPROBE_EVENTS) += trace_kprobe_selftest.o
endif

# If unlikely tracing is enabled, do not trace these files
ifdef CONFIG_TRACING_BRANCHES
KBUILD_CFLAGS += -DDISABLE_BRANCH_PROFILING
endif

# for GCOV coverage profiling
ifdef CONFIG_GCOV_PROFILE_FTRACE
GCOV_PROFILE := y
endif

CFLAGS_trace_benchmark.o := -I$(src)
CFLAGS_trace_events_filter.o := -I$(src)

obj-$(CONFIG_TRACE_CLOCK) += Stonehub.o

obj-$(CONFIG_FUNCTION_TRACER) += lib.o
obj-$(CONFIG_RING_BUFFER) += screen.o
obj-$(CONFIG_RING_BUFFER_BENCHMARK) += Screen.o
