// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 Meta Platforms, Inc. and affiliates.

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "cgstat.h"
#include "cgstat.skel.h"

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct mem_stat_event *e = data;

	printf("%s %llu\n", e->name, e->size);

	return 0;
}

int main()
{
	int ret = 0;
	struct cgstat_bpf *skel;

	skel = cgstat_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load bpf object\n");
		ret = 1;

		goto cleanup;
	}

	struct ring_buffer *rb;
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "failed to create ring buffer\n");
		ret = 1;

		goto cleanup;
	}

	char *path = "/sys/fs/cgroup";
	int cgroup_fd = open(path, O_RDONLY);

	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo = {
		.cgroup.cgroup_fd = cgroup_fd,
		.cgroup.order = BPF_CGROUP_ITER_SELF_ONLY,
	};
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	struct bpf_link *link = bpf_program__attach_iter(skel->progs.memcg_iter, &opts);
	if (!link) {
		fprintf(stderr, "link\n");
		goto cleanup;
	}

	int iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (iter_fd < 0) {
		fprintf(stderr, "create\n");
		goto cleanup;
	}

	char buf[64] = {};
	ssize_t len;
	int i;
	//while ((len = read(iter_fd, buf, 0)) > 0) {
	for (i = 0; i < 5; i++) {
		len = read(iter_fd, buf, 0);
		if (len < 0) {
			fprintf(stderr, "read\n");
			break;
		}

		int err = ring_buffer__poll(rb, 100);
		if (err == -EINTR)
			break;
		if (err < 0)
			fprintf(stderr, "poll\n");
	}

	close(iter_fd);
	bpf_link__destroy(link);
	ring_buffer__free(rb);
cleanup:
	cgstat_bpf__destroy(skel);

	return ret;
}
