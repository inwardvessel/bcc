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
	__uint(max_entries, 128);
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
__u32 my_array[1] SEC(".data.my_array");

/**
 * __mod_memcg_state - update cgroup memory statistics
 * @memcg: the memory cgroup
 * @idx: the stat item - can be enum memcg_stat_item or enum node_stat_item
 * @val: delta to add to the counter, can be negative
 */
SEC("fentry/__mod_memcg_state")
int BPF_PROG(handle__mod_memcg_state, struct mem_cgroup *memcg, int idx, int val)
{
	return 0;
}

/**
 * __mod_lruvec_state - update lruvec memory statistics
 * @lruvec: the lruvec
 * @idx: the stat item
 * @val: delta to add to the counter, can be negative
 *
 * The lruvec is the intersection of the NUMA node and a cgroup. This
 * function updates the all three counters that are affected by a
 * change of state at this level: per-node, per-cgroup, per-lruvec.
 */
SEC("fentry/__mod_memcg_lruvec_state")
int BPF_PROG(handle__mod_memcg_lruvec_state, struct lruvec *lruvec, enum node_stat_item idx,
		                  int val)
{
	return 0;
}

/**
 * __count_memcg_events - account VM events in a cgroup
 * @memcg: the memory cgroup
 * @idx: the event item
 * @count: the number of events that occurred
 */
SEC("fentry/__count_memcg_events")
int BPF_PROG(handle__count_memcg_events, struct mem_cgroup *memcg, enum vm_event_item idx,
		              unsigned long count)
{
	return 0;
}


SEC("fentry/cgroup_rstat_updated")
int BPF_PROG(handle_cgroup_rstat_updated, struct cgroup *cgrp,
				     int cpu)
{
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
