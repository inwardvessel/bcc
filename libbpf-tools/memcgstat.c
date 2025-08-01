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
	USER_NR_INACTIVE_ANON,
	USER_NR_ACTIVE_ANON,
	USER_NR_INACTIVE_FILE,
	USER_NR_ACTIVE_FILE,
};

static char *names[] = {
	"inactive_anon",
	"active_anon",
	"inactive_file",
	"active_file",
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
	printf("nr_items:%zu\n", skel->rodata->nr_items);

	size_t sz_map = sizeof(skel->data_items->items[0]) * skel->rodata->nr_items;
	printf("desired map size:%zu\n", sz_map);
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
	printf("desired map size:%zu\n", sz_map);
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
	for (i = 0; i < skel->rodata->nr_items; i++)
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
	if (bytes != sz) {
		fprintf(stderr, "read: expected %zu bytes, got %zu\n", sz, bytes);
		ret = 1;
		goto cleanup;
	}

	for (i = 0; i < skel->rodata->nr_items; i++) {
		printf("%s:%d\n", names[i], values[i]);
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
