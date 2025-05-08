// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "memcgstat.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024); /* one kB */
} rb SEC(".maps");

struct loop_ctx {
	struct mem_cgroup *memcg;
};

extern void mem_cgroup_flush_stats(struct mem_cgroup *memcg) __ksym;
extern size_t memory_stat_count(void) __ksym;
extern int memory_stat_fetch(struct mem_cgroup *memcg, int i,
		char *name, u64 *val) __ksym;
extern void memory_event_pgscan_fetch(struct mem_cgroup *memcg,
		unsigned long *val) __ksym;
extern void memory_event_pgsteal_fetch(struct mem_cgroup *memcg,
		unsigned long *val) __ksym;

static int mem_stat_submit(const char *name, u64 val)
{
	struct mem_stat_event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 1;

	bpf_probe_read_str(&e->name, sizeof(e->name), name);
	e->val = val;
	bpf_ringbuf_submit(e, 0);

	return 0;
}

static int mem_stat_visit(u32 i, void *ctx)
{
	struct mem_cgroup *memcg = ((struct loop_ctx *)ctx)->memcg;
	int err;
	char name[64] = {};
	u64 val = 0;

	err = memory_stat_fetch(memcg, i, name, &val);
	if (err)
		return 1;

	bpf_printk("val:%llu", val);
	mem_stat_submit(name, val);

	/* TODO handle unreclaimable b */

	return 0;
}

SEC("iter.s/cgroup")
int memcg_iter(struct bpf_iter__cgroup *ctx)
{
	struct cgroup *cgrp;
	struct mem_cgroup *memcg;

	cgrp = ctx->cgroup;
	memcg = ctx->memcg;

	if (!cgrp || !memcg)
		return 1;

	mem_cgroup_flush_stats(memcg);

	struct loop_ctx loop_ctx = {
		.memcg = memcg
	};
	size_t nr_mem_stats = memory_stat_count();
	bpf_loop(nr_mem_stats, mem_stat_visit, &loop_ctx, 0);

	unsigned long val = 0;
	memory_event_pgscan_fetch(memcg, &val);
	mem_stat_submit("pgscan", val);
	memory_event_pgsteal_fetch(memcg, &val);
	mem_stat_submit("pgsteal", val);

	return 0;
}
