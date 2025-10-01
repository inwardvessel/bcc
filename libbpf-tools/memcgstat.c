// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "memcgstat.h"
#include "memcgstat.skel.h"

/* items to be queried */
static enum memcg_item items[] = {
	USER_NR_ANON_MAPPED,
	USER_NR_FILE_PAGES,
	USER_NR_KERNEL_STACK_KB,
	USER_NR_SHMEM,
	USER_NR_FILE_MAPPED,
	USER_NR_FILE_DIRTY,
	USER_NR_WRITEBACK,
	USER_NR_FILE_THPS,
	USER_NR_ANON_THPS,
	USER_NR_INACTIVE_ANON,
	USER_NR_ACTIVE_ANON,
	USER_NR_INACTIVE_FILE,
	USER_NR_ACTIVE_FILE,
	USER_NR_UNEVICTABLE,
	USER_NR_SLAB_RECLAIMABLE_B,
	USER_NR_SLAB_UNRECLAIMABLE_B,
	USER_WORKINGSET_REFAULT_ANON,
	USER_WORKINGSET_REFAULT_FILE,
	USER_WORKINGSET_ACTIVATE_ANON,
	USER_WORKINGSET_ACTIVATE_FILE,
	USER_WORKINGSET_RESTORE_ANON,
	USER_WORKINGSET_RESTORE_FILE,
	USER_WORKINGSET_NODERECLAIM,
	USER_MEMCG_KMEM,
	USER_MEMCG_SOCK,
	USER_MEMCG_ZSWAP_B,
	USER_MEMCG_ZSWAPPED,
	USER_PGSCAN_KSWAPD,
	USER_PGSCAN_DIRECT,
	USER_PGSCAN_KHUGEPAGED,
	USER_PGSCAN_PROACTIVE,
	USER_PGSTEAL_KSWAPD,
	USER_PGSTEAL_DIRECT,
	USER_PGSTEAL_KHUGEPAGED,
	USER_PGSTEAL_PROACTIVE,
	USER_PGFAULT,
	USER_PGMAJFAULT,
	USER_PGREFILL,
	USER_PGACTIVATE,
	USER_PGDEACTIVATE,
	USER_PGLAZYFREE,
	USER_PGLAZYFREED,
	USER_THP_FAULT_ALLOC,
	USER_THP_COLLAPSE_ALLOC,
	USER_ITEM_COUNT
};

/* names corresponding to query items */
static char *names[] = {
	"nr_anon_mapped",
	"nr_file_pages",
	"nr_kernel_stack_kb",
	"nr_shmem",
	"nr_file_mapped",
	"nr_file_dirty",
	"nr_writeback",
	"nr_file_thps",
	"nr_anon_thps",
	"nr_inactive_anon",
	"nr_active_anon",
	"nr_inactive_file",
	"nr_active_file",
	"nr_unevictable",
	"nr_slab_reclaimable_b",
	"nr_slab_unreclaimable_b",
	"workingset_refault_anon",
	"workingset_refault_file",
	"workingset_activate_anon",
	"workingset_activate_file",
	"workingset_restore_anon",
	"workingset_restore_file",
	"workingset_nodereclaim",
	"memcg_kmem",
	"memcg_sock",
	"memcg_zswap_b",
	"memcg_zswapped",
	"pgscan_kswapd",
	"pgscan_direct",
	"pgscan_khugepaged",
	"pgscan_proactive",
	"pgsteal_kswapd",
	"pgsteal_direct",
	"pgsteal_khugepaged",
	"pgsteal_proactive",
	"pgfault",
	"pgmajfault",
	"pgrefill",
	"pgactivate",
	"pgdeactivate",
	"pglazyfree",
	"pglazyfreed",
	"thp_fault_alloc",
	"thp_collapse_alloc",
	"(sentinel)"
};

static int results[USER_ITEM_COUNT];

int main(int argc, char *argv[])
{
	struct memcgstat_bpf *skel;
	struct bpf_map *map;
	struct bpf_link *link;
	size_t sz_items_desired, sz_items_final;
	size_t sz_results_desired, sz_results_final;
	size_t nr_items;
	int ret, n, i;
	int cgroup_fd;
	char *cgroup_path;
	bool debug = false;

	if (argc < 3) {
		fprintf(stderr, "USAGE: %s <cgroup_path> <N> <debug>\n", argv[0]);

		return 1;
	}

	cgroup_path = argv[1];
	n = atoi(argv[2]);
	nr_items = sizeof(items) / sizeof(items[0]);

	if (argc > 3)
		debug = true;

	skel = memcgstat_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open bpf object\n");
		ret = 1;

		goto out;
	}

	/* resize array of items to be queried */
	map = skel->maps.data_items;
	sz_items_desired = sizeof(skel->data_items->items[0]) * nr_items;
	ret = bpf_map__set_value_size(map, sz_items_desired);
	if (ret) {
		goto cleanup_skel;
	}
	skel->data_items = bpf_map__initial_value(skel->maps.data_items, &sz_items_final);
	if (sz_items_final != sz_items_desired) {
		fprintf(stderr, "failed to resize items map\n");
		ret = 1;

		goto cleanup_skel;
	}

	/* resize array that will store query results */
	sz_results_desired = sizeof(skel->data_results->results[0]) * nr_items;
	map = skel->maps.data_results;
	ret = bpf_map__set_value_size(map, sz_results_desired);
	if (ret) {
		goto cleanup_skel;
	}
	skel->data_results = bpf_map__initial_value(skel->maps.data_results, &sz_results_final);
	if (sz_results_final != sz_results_desired) {
		fprintf(stderr, "failed to resize results map\n");
		ret = 1;

		goto cleanup_skel;
	}

	/* store items to be queried in bpf array */
	for (i = 0; i < nr_items - 1; i++)
		skel->data_items->items[i] = items[i];

	ret = memcgstat_bpf__load(skel);
	if (ret) {
		fprintf(stderr, "failed to load bpf object\n");
		ret = 1;

		goto cleanup_skel;
	}

	cgroup_fd = open(cgroup_path, O_RDONLY);
	if (cgroup_fd < 0) {
		perror("open");
		ret = cgroup_fd;

		goto cleanup_skel;
	}

	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo = {
		.cgroup.cgroup_fd = cgroup_fd,
		.cgroup.order = BPF_CGROUP_ITER_SELF_ONLY,
	};
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	link = bpf_program__attach_iter(skel->progs.query, &opts);
	if (!link) {
		fprintf(stderr, "link\n");
		ret = 1;
		goto cleanup_cgroup_fd;
	}

for (i = 0; i < n; i++) {
	int iter_fd;
	ssize_t bytes;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (iter_fd < 0) {
		fprintf(stderr, "create\n");
		ret = 1;
		goto cleanup_link;
	}

	/* invoke iter program */
	bytes = read(iter_fd, results, 0);
	if (bytes < 0) {
		close(iter_fd);
		perror("read");
		ret = bytes;
		goto cleanup_link;
	}

	close(iter_fd);

	if (debug) {
		for (i = 0; i < nr_items - 1; i++) {
			printf("%s:%lu\n", names[i], skel->data_results->results[i]);
		}
	}
}

cleanup_link:
	bpf_link__destroy(link);
cleanup_cgroup_fd:
	close(cgroup_fd);
cleanup_skel:
	memcgstat_bpf__destroy(skel);
out:
	return ret;
}
