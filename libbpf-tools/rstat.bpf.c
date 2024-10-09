// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "rstat.h"

#define MAX_STATS MEMCG_NR_STAT + 1
#define MAX_EVENTS NR_VM_EVENT_ITEMS + 1

const volatile size_t max_stats = MAX_STATS;
const volatile size_t max_events = MAX_EVENTS;

__u32 stat_update_count[MAX_STATS] = {};
__u32 event_update_count[MAX_EVENTS] = {};

SEC("fentry/__mod_memcg_state")
int BPF_PROG(handle__mod_memcg_state, struct mem_cgroup *memcg, int idx, int val)
{
	if (idx < 0 || idx >= MAX_STATS)
		idx = MAX_STATS - 1;

	__sync_fetch_and_add(&stat_update_count[idx], 1);

	return 0;
}

SEC("fentry/__mod_memcg_lruvec_state")
int BPF_PROG(handle__mod_memcg_lruvec_state, struct lruvec *lruvec, enum node_stat_item idx,
		                  int val)
{
	if (idx < 0 || idx >= MAX_STATS)
		idx = MAX_STATS - 1;

	__sync_fetch_and_add(&stat_update_count[idx], 1);

	return 0;
}

SEC("fentry/__count_memcg_events")
int BPF_PROG(handle__count_memcg_events, struct mem_cgroup *memcg, enum vm_event_item idx,
		              unsigned long count)
{
	if (idx < 0 || idx >= MAX_EVENTS)
		idx = MAX_EVENTS - 1;

	__sync_fetch_and_add(&event_update_count[idx], 1);

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
