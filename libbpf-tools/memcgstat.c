// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "memcgstat.h"
#include "memcgstat.skel.h"

int main()
{
	int ret = 0;
	struct memcgstat_bpf *skel;

	skel = memcgstat_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load bpf object\n");
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

	struct bpf_link *link = bpf_program__attach_iter(skel->progs.query, &opts);
	if (!link) {
		fprintf(stderr, "link\n");
		goto cleanup;
	}

	int iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (iter_fd < 0) {
		fprintf(stderr, "create\n");
		goto cleanup;
	}

	int values[4] = {};
	ssize_t len = read(iter_fd, values, sizeof(int) * 4);
	if (len < 0) {
		fprintf(stderr, "read\n");
	}

	int i;
	for (i = 0; i < 4; i++) {
		printf("value %d:%d\n", i, values[i]);
	}

	close(iter_fd);
	bpf_link__destroy(link);
cleanup:
	memcgstat_bpf__destroy(skel);

	return ret;
}
