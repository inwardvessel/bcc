// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cgstat.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024); /* one kB */
} rb SEC(".maps");

extern bool mem_stat_skip(int i) __ksym;
extern const char *mem_stat_name(int i) __ksym;
extern int mem_stat_item(int i) __ksym;
extern int mem_stat_index(int idx) __ksym;
extern int mem_stat_unit(int item) __ksym;
extern bool mem_stat_is_slab_unreclaimable_b(int i) __ksym;
extern int memcg_events_index(enum vm_event_item idx) __ksym;
size_t memcg_event_count(void) __ksym;
const char *memcg_event_name(enum vm_event_item item) __ksym;

struct visit_ctx {
	struct mem_cgroup *memcg;
};

static int mem_stat_submit(int item, long size, const char *name)
{
	struct mem_stat_event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 1;

	bpf_probe_read_str(&e->name, sizeof(e->name), name);
	e->idx = item;
	e->size = size;
	bpf_ringbuf_submit(e, 0);

	return 0;
}

static long mem_stat_visit(u32 i, void *ctx)
{
	struct mem_cgroup *memcg = ((struct visit_ctx *)ctx)->memcg;

	if (mem_stat_skip(i))
		return 0;

	const char *name = mem_stat_name(i);
	int item = mem_stat_item(i);
	int idx = mem_stat_index(item);
	int unit = mem_stat_unit(item);
	long x = BPF_CORE_READ(memcg, vmstats, state[idx]);
	long size = x * unit;

	int err = mem_stat_submit(item, size, name);
	if (err)
		return err;

	if (mem_stat_is_slab_unreclaimable_b(i)) {
		size += BPF_CORE_READ(memcg, vmstats, state[idx]);
		name = "slab";
		return mem_stat_submit(item, size, name);
	}

	return 0;
}

static long memcg_event_visit(u32 i, void *ctx)
{
	struct mem_cgroup *memcg = ((struct visit_ctx *)ctx)->memcg;

	int idx = memcg_events_index(i);
	const char *name = memcg_event_name(i);
	long count = BPF_CORE_READ(memcg, vmstats, events[idx]);

	mem_stat_submit(idx, count, name);

	return 0;
}

SEC("iter/cgroup")
int memcg_iter(struct bpf_iter__cgroup *ctx)
{
	struct cgroup *cgrp;
	struct mem_cgroup *memcg;

	cgrp = ctx->cgroup;
	memcg = ctx->memcg;

	if (!cgrp || !memcg)
		return 1;

	struct visit_ctx visit_ctx = {
		.memcg = memcg
	};

	size_t nr_mem_stats = mem_stat_count();
	bpf_loop(nr_mem_stats, mem_stat_visit, &visit_ctx, 0);

	long total_pgscan =
		BPF_CORE_READ(memcg, vmstats, events[memcg_events_index(PGSCAN_KSWAPD)]) +
		BPF_CORE_READ(memcg, vmstats, events[memcg_events_index(PGSCAN_DIRECT)]) +
		BPF_CORE_READ(memcg, vmstats, events[memcg_events_index(PGSCAN_KHUGEPAGED)]);
	mem_stat_submit(-1, total_pgscan, "pgscan");

	long total_pgsteal =
		BPF_CORE_READ(memcg, vmstats, events[memcg_events_index(PGSTEAL_KSWAPD)]) +
		BPF_CORE_READ(memcg, vmstats, events[memcg_events_index(PGSTEAL_DIRECT)]) +
		BPF_CORE_READ(memcg, vmstats, events[memcg_events_index(PGSTEAL_KHUGEPAGED)]);
	mem_stat_submit(-1, total_pgsteal, "pgsteal");

	size_t nr_memcg_events = memcg_event_count();
	bpf_loop(nr_memcg_events, memcg_event_visit, &visit_ctx, 0);

	return 0;
}
