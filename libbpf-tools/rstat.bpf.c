// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "rstat.h"
#include "bits.bpf.h"

#define CLOCK_MONOTONIC 1

#define ARRAY_ELEM_PTR(arr, i, n) (typeof(arr[i]) *)({ \
	u64 __base = (u64)arr; \
	u64 __addr = (u64)&(arr[i]) - __base; \
	asm volatile ( \
		"if %0 <= %[max] goto +2\n" \
		"%0 = 0\n" \
		"goto +1\n" \
		"%0 += %1\n" \
		: "+r"(__addr) \
		: "r"(__base), \
		[max]"r"(sizeof(arr[0]) * ((n) - 1))); \
	__addr; \
})

extern void generic_smp_call_function_single_interrupt(void) __ksym;
extern bool bpf_cpumask_test_cpu(u32 cpu, const struct cpumask *cpumask) __ksym;

/* key for single element percpu arrays */
static const __u32 percpu_key = 0;

const volatile __u32 nr_cpus;
const volatile __u64 latency_threshold_ns;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128); /* TODO set in user prog */
	__type(key, u64);
	__type(value, u64);
} my_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* time from csd func entry to func exit */
__u32 my_hist[MAX_SLOTS] = {};

/* counts of ipi's sent to cpu's (resized to cpu count in user prog) */
__u32 my_array[1] SEC(".data.my_hist");

SEC("fentry/my_func")
int BPF_PROG(handle_my_func_entry, ...)
{
	return 0;
}

SEC("fexit/my_func")
int BPF_PROG(handle_my_func_exit, ...)
{
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
