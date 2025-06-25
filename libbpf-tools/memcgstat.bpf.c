// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "memcgstat.h"

char _license[] SEC("license") = "GPL";

extern void memcg_flush(struct cgroup *cgrp) __ksym;
extern unsigned long memcg_stat_fetch(struct cgroup *cgrp, int item) __ksym;
extern unsigned long memcg_event_fetch(struct cgroup *cgrp, int event) __ksym;

SEC("iter/cgroup")
int BPF_PROG(query, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	struct seq_file *seq = meta->seq;

	if (!cgrp)
		return 1;

	memcg_flush(cgrp);

	int values[4] = {
		memcg_stat_fetch(cgrp, bpf_core_enum_value(enum node_stat_item, NR_INACTIVE_ANON)),
		memcg_stat_fetch(cgrp, bpf_core_enum_value(enum node_stat_item, NR_ACTIVE_ANON)),
		memcg_stat_fetch(cgrp, bpf_core_enum_value(enum node_stat_item, NR_INACTIVE_FILE)),
		memcg_stat_fetch(cgrp, bpf_core_enum_value(enum node_stat_item, NR_ACTIVE_FILE)),
	};

	bpf_seq_write(seq, &values[0], sizeof(int) * 4);

	return 0;
}
