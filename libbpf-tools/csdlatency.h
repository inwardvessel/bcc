// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 Meta Platforms, Inc. and affiliates.

#define PERF_EVENT_MAX_STACK 127
#define MAX_SLOTS 32

struct event {
	__u32 stack_len;
	__u64 stack[PERF_EVENT_MAX_STACK];
	__u64 t;
};
