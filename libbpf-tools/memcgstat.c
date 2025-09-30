// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "memcgstat.h"
#include "memcgstat.skel.h"

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

int main()
{
	int ret = 0;
	struct memcgstat_bpf *skel;

	skel = memcgstat_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open bpf object\n");
		ret = 1;

		goto out;
	}

	skel->rodata->nr_items = sizeof(items) / sizeof(items[0]);

	size_t sz_map = sizeof(skel->data_items->items[0]) * skel->rodata->nr_items;
	size_t sz_map_final;

	struct bpf_map *map = skel->maps.data_items;
	ret = bpf_map__set_value_size(map, sz_map);
	if (ret) {
		goto cleanup_skel;
	}
	skel->data_items = bpf_map__initial_value(skel->maps.data_items, &sz_map_final);
	if (sz_map_final != sz_map) {
		fprintf(stderr, "mismatched size\n");
		ret = 1;
		goto cleanup_skel;
	}

	sz_map = sizeof(skel->data_results->results[0]) * skel->rodata->nr_items;
	map = skel->maps.data_results;
	ret = bpf_map__set_value_size(map, sz_map);
	if (ret) {
		goto cleanup_skel;
	}
	skel->data_results = bpf_map__initial_value(skel->maps.data_results, &sz_map_final);
	if (sz_map_final != sz_map) {
		fprintf(stderr, "mismatched size\n");
		ret = 1;
		goto cleanup_skel;
	}

	int i;
	for (i = 0; i < skel->rodata->nr_items - 1; i++)
		skel->data_items->items[i] = items[i];

	ret = memcgstat_bpf__load(skel);
	if (ret) {
		fprintf(stderr, "failed to load bpf object\n");
		ret = 1;
		goto cleanup_skel;
	}

	char *path = "/sys/fs/cgroup";
	int cgroup_fd = open(path, O_RDONLY);
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

	struct bpf_link *link = bpf_program__attach_iter(skel->progs.query, &opts);
	if (!link) {
		fprintf(stderr, "link\n");
		ret = 1;
		goto cleanup_skel;
	}

	int iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (iter_fd < 0) {
		fprintf(stderr, "create\n");
		ret = 1;
		goto cleanup_link;
	}

	size_t sz = sizeof(int) * skel->rodata->nr_items;
	int *values = malloc(sz);
	if (!values) {
		fprintf(stderr, "no mem\n");
		return 1;
	}

	ssize_t bytes = read(iter_fd, values, sz);
	if (bytes < 0) {
		perror("read");
		ret = bytes;
		goto cleanup;
	}

	for (i = 0; i < skel->rodata->nr_items - 1; i++) {
		printf("%s:%lu\n", names[i], skel->data_results->results[i]);
	}

cleanup:
	close(iter_fd);
cleanup_link:
	bpf_link__destroy(link);
cleanup_skel:
	memcgstat_bpf__destroy(skel);
out:
	return ret;
}
