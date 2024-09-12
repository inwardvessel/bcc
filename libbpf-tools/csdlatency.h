// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 Meta Platforms, Inc. and affiliates.

#define PERF_EVENT_MAX_STACK 127
#define MAX_SLOTS 32

enum latency_event_type {
	CSD_CALL_SINGLE_LATENCY,
	CSD_CALL_MANY_LATENCY,
	CSD_FLUSH_LATENCY,
	CSD_FUNC_LATENCY,
	CSD_CPU_LATENCY
};

struct event {
	enum latency_event_type type;
	__u64 t;
	__u32 cpu;
	__u64 func;
	__u32 stack_sz;
	__u64 stack[PERF_EVENT_MAX_STACK];
};
