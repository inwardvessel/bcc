// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "memcgstat.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

extern void memcg_flush_stats(struct cgroup *cgrp) __ksym;
extern unsigned long memcg_node_stat_fetch(struct cgroup *cgrp, enum node_stat_item item) __ksym;
extern unsigned long memcg_vm_event_fetch(struct cgroup *cgrp, enum vm_event_item item) __ksym;
extern unsigned long memcg_stat_fetch(struct cgroup *cgrp, enum memcg_stat_item item) __ksym;

const volatile size_t nr_items;
enum memcg_item items[1] SEC(".data.items");
long results[1] SEC(".data.results");

#define node_stat_fetch_if_exists(cgrp, item) \
	bpf_core_enum_value_exists(enum node_stat_item, item) ? \
		 memcg_node_stat_fetch(cgrp, bpf_core_enum_value(enum node_stat_item, item)) \
				 : -1;

#define memcg_stat_fetch_if_exists(cgrp, item) \
	bpf_core_enum_value_exists(enum memcg_stat_item, item) ? \
		 memcg_node_stat_fetch(cgrp, bpf_core_enum_value(enum memcg_stat_item, item)) \
				 : -1;

#define vm_event_fetch_if_exists(cgrp, item) \
	bpf_core_enum_value_exists(enum vm_event_item, item) ? \
		 memcg_vm_event_fetch(cgrp, bpf_core_enum_value(enum vm_event_item, item)) \
				 : -1;

SEC("iter/cgroup")
int BPF_PROG(query, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	if (!cgrp)
		return 1;

	memcg_flush_stats(cgrp);

	enum memcg_item item;
	for (item = 0; item < USER_ITEM_COUNT; item++) {
		switch (item) {
			/* node_stat_item */
			case USER_NR_ANON_MAPPED:
				results[item] = node_stat_fetch_if_exists(cgrp, NR_ANON_MAPPED);
				break;
			case USER_NR_FILE_PAGES:
				results[item] = node_stat_fetch_if_exists(cgrp, NR_FILE_PAGES);
				break;
			case USER_NR_KERNEL_STACK_KB:
				results[item] = node_stat_fetch_if_exists(cgrp, NR_KERNEL_STACK_KB);
				break;
			case USER_NR_SHMEM:
				results[item] = node_stat_fetch_if_exists(cgrp, NR_SHMEM);
				break;
			case USER_NR_FILE_MAPPED:
				results[item] = node_stat_fetch_if_exists(cgrp, NR_FILE_MAPPED);
				break;
			case USER_NR_FILE_DIRTY:
				results[item] = node_stat_fetch_if_exists(cgrp, NR_FILE_DIRTY);
				break;
			case USER_NR_WRITEBACK:
				results[item] = node_stat_fetch_if_exists(cgrp, NR_WRITEBACK);
				break;
			case USER_NR_FILE_THPS:
				results[item] = node_stat_fetch_if_exists(cgrp, NR_FILE_THPS);
				break;
			case USER_NR_ANON_THPS:
				results[item] = node_stat_fetch_if_exists(cgrp, NR_ANON_THPS);
				break;
			case USER_NR_INACTIVE_ANON:
				results[item] = node_stat_fetch_if_exists(cgrp, NR_INACTIVE_ANON);
				break;
			case USER_NR_ACTIVE_ANON:
				results[item] = node_stat_fetch_if_exists(cgrp, NR_ACTIVE_ANON);
				break;
			case USER_NR_INACTIVE_FILE:
				results[item] = node_stat_fetch_if_exists(cgrp, NR_INACTIVE_FILE);
				break;
			case USER_NR_ACTIVE_FILE:
				results[item] = node_stat_fetch_if_exists(cgrp, NR_ACTIVE_FILE);
				break;
			case USER_NR_UNEVICTABLE:
				results[item] = node_stat_fetch_if_exists(cgrp, NR_UNEVICTABLE);
				break;
			case USER_NR_SLAB_RECLAIMABLE_B:
				results[item] = node_stat_fetch_if_exists(cgrp, NR_SLAB_RECLAIMABLE_B);
				break;
			case USER_NR_SLAB_UNRECLAIMABLE_B:
				results[item] = node_stat_fetch_if_exists(cgrp, NR_SLAB_UNRECLAIMABLE_B);
				break;
			case USER_WORKINGSET_REFAULT_ANON:
				results[item] = node_stat_fetch_if_exists(cgrp, WORKINGSET_REFAULT_ANON);
				break;
			case USER_WORKINGSET_REFAULT_FILE:
				results[item] = node_stat_fetch_if_exists(cgrp, WORKINGSET_REFAULT_FILE);
				break;
			case USER_WORKINGSET_ACTIVATE_ANON:
				results[item] = node_stat_fetch_if_exists(cgrp, WORKINGSET_ACTIVATE_ANON);
				break;
			case USER_WORKINGSET_ACTIVATE_FILE:
				results[item] = node_stat_fetch_if_exists(cgrp, WORKINGSET_ACTIVATE_FILE);
				break;
			case USER_WORKINGSET_RESTORE_ANON:
				results[item] = node_stat_fetch_if_exists(cgrp, WORKINGSET_RESTORE_ANON);
				break;
			case USER_WORKINGSET_RESTORE_FILE:
				results[item] = node_stat_fetch_if_exists(cgrp, WORKINGSET_RESTORE_FILE);
				break;
			case USER_WORKINGSET_NODERECLAIM:
				results[item] = node_stat_fetch_if_exists(cgrp, WORKINGSET_NODERECLAIM);
				break;
			/* memcg_stat_item */
			case USER_MEMCG_KMEM:
				results[item] = memcg_stat_fetch_if_exists(cgrp, MEMCG_KMEM);
				break;
			case USER_MEMCG_SOCK:
				results[item] = memcg_stat_fetch_if_exists(cgrp, MEMCG_SOCK);
				break;
			case USER_MEMCG_ZSWAP_B:
				results[item] = memcg_stat_fetch_if_exists(cgrp, MEMCG_ZSWAP_B);
				break;
			case USER_MEMCG_ZSWAPPED:
				results[item] = memcg_stat_fetch_if_exists(cgrp, MEMCG_ZSWAPPED);
				break;
			/* vm_event_item */
			case USER_PGSCAN_KSWAPD:
				results[item] = vm_event_fetch_if_exists(cgrp, PGSCAN_KSWAPD);
				break;
			case USER_PGSCAN_DIRECT:
				results[item] = vm_event_fetch_if_exists(cgrp, PGSCAN_DIRECT);
				break;
			case USER_PGSCAN_KHUGEPAGED:
				results[item] = vm_event_fetch_if_exists(cgrp, PGSCAN_KHUGEPAGED);
				break;
			case USER_PGSCAN_PROACTIVE:
				results[item] = vm_event_fetch_if_exists(cgrp, PGSCAN_PROACTIVE);
				break;
			case USER_PGSTEAL_KSWAPD:
				results[item] = vm_event_fetch_if_exists(cgrp, PGSTEAL_KSWAPD);
				break;
			case USER_PGSTEAL_DIRECT:
				results[item] = vm_event_fetch_if_exists(cgrp, PGSTEAL_DIRECT);
				break;
			case USER_PGSTEAL_KHUGEPAGED:
				results[item] = vm_event_fetch_if_exists(cgrp, PGSTEAL_KHUGEPAGED);
				break;
			case USER_PGSTEAL_PROACTIVE:
				results[item] = vm_event_fetch_if_exists(cgrp, PGSTEAL_PROACTIVE);
				break;
			case USER_PGFAULT:
				results[item] = vm_event_fetch_if_exists(cgrp, PGFAULT);
				break;
			case USER_PGMAJFAULT:
				results[item] = vm_event_fetch_if_exists(cgrp, PGMAJFAULT);
				break;
			case USER_PGREFILL:
				results[item] = vm_event_fetch_if_exists(cgrp, PGREFILL);
				break;
			case USER_PGACTIVATE:
				results[item] = vm_event_fetch_if_exists(cgrp, PGACTIVATE);
				break;
			case USER_PGDEACTIVATE:
				results[item] = vm_event_fetch_if_exists(cgrp, PGDEACTIVATE);
				break;
			case USER_PGLAZYFREE:
				results[item] = vm_event_fetch_if_exists(cgrp, PGLAZYFREE);
				break;
			case USER_PGLAZYFREED:
				results[item] = vm_event_fetch_if_exists(cgrp, PGLAZYFREED);
				break;
			case USER_THP_FAULT_ALLOC:
				results[item] = vm_event_fetch_if_exists(cgrp, THP_FAULT_ALLOC);
				break;
			case USER_THP_COLLAPSE_ALLOC:
				results[item] = vm_event_fetch_if_exists(cgrp, THP_COLLAPSE_ALLOC);
				break;
			case USER_ITEM_COUNT:
				/* no-op: this item included to avoid the need for a default case */
				break;
		}
	}

	return 0;
}
