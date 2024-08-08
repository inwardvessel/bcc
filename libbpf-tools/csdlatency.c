// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "csdlatency.h"
#include "csdlatency.skel.h"
#include "trace_helpers.h"

static struct env {
	__u64 max_ipi_dispatch_ms;
	int perf_max_stack_depth;
	unsigned int stack_map_max_entries;
} env = {
	.max_ipi_dispatch_ms = 5,
	.perf_max_stack_depth = 127,
	.stack_map_max_entries = 10240,
};

static struct ksyms *ksyms;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int event_handler(void *ctx, void *data, size_t sz)
{
	printf("got event\n");
	struct event *event = (struct event *)data;
	size_t i;

	for (i = 0; i < event->stack_len; ++i) {
		const uint64_t addr = event->stack[i];
		const struct ksym *ksym = ksyms__map_addr(ksyms, addr);
		printf("%zu: %s\n", i, ksym->name);
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct csdlatency_bpf *skel;
	int err;

	ksyms = ksyms__load();
	if (!ksyms) {
		fprintf(stderr, "failed to load ksyms\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	skel = csdlatency_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open bpf object\n");
		return 1;
	}

	skel->rodata->nr_cpus = 16;
	skel->rodata->max_ipi_dispatch_ms = env.max_ipi_dispatch_ms;

	bpf_map__set_value_size(skel->maps.stacks,
				env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(skel->maps.stacks, env.stack_map_max_entries);

	err = csdlatency_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load bpf object\n");
		goto cleanup;
	}

	err = csdlatency_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach bpf program(s)\n");
		goto cleanup;
	}

	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), event_handler, NULL, NULL);

	ring_buffer__poll(rb, 1000 /* timeout ms */);

	//printf("latency of function queue time to remote function start time\n");
	//print_log2_hist(skel->bss->csd_queue_hist, MAX_SLOTS, "nsec");
	//printf("latency of total time spend in remote IPI callback\n");
	//print_log2_hist(skel->bss->ipi_hist, MAX_SLOTS, "nsec");
	//printf("latency of individual functions dispatched within a single IPI callback\n");
	//print_log2_hist(skel->bss->csd_func_hist, MAX_SLOTS, "nsec");

cleanup:
	csdlatency_bpf__destroy(skel);
	return -err;
}
