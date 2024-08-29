// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "csdlatency.h"
#include "csdlatency.skel.h"
#include "trace_helpers.h"

static struct env {
	int interval; /* dump histograms every N seconds */
	int nr_intervals; /* exit program after N intervals, ignore if negative */
	int perf_max_stack_depth;
	__u64 csd_ipi_response_threshold_ms; /* report remote cpu when time exceeded */
	__u64 csd_dispatch_threshold_ms; /* report stacks interrupted when time exceeded */
	__u64 csd_func_threshold_ms; /* report csd funcs that exceed this time */
} env = {
	.interval = 5,
	.nr_intervals = -1,
	.perf_max_stack_depth = 127, /* from sysctl kernel.perf_event_max_stack */
	.csd_ipi_response_threshold_ms = 500,
	.csd_dispatch_threshold_ms = 500,
	.csd_func_threshold_ms = 500,
};

static struct ksyms *ksyms;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int event_handler(void *ctx, void *data, size_t sz)
{
	struct event *event = (struct event *)data;

	switch (event->type) {
		case CSD_IPI_RESPONSE_LATENCY:
			printf("csd ipi response latency event\n");
			printf("\tthreshold exceeded on cpu %u\n", event->cpu);
			break;
		case CSD_DISPATCH_LATENCY:
			size_t i;

			printf("csd dispatch latency event\n");
			printf("\t delayed stack below\n");

			for (i = 0; i < event->stack_sz / sizeof(event->stack[0]); ++i) {
				const uint64_t addr = event->stack[i];
				const struct ksym *ksym = ksyms__map_addr(ksyms, addr);
				printf("%zu: %s\n", i, ksym->name);
			}

			break;
		case CSD_FUNC_LATENCY:
			const struct ksym *ksym = ksyms__map_addr(ksyms, event->func);
			printf("csd func latency event\n");
			printf("\tthreshold exceeded on %s %llx\n", ksym->name, event->func);
			break;
		default:
			printf("unknown event\n");
			break;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct csdlatency_bpf *skel;
	struct ring_buffer *rb;
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

	skel->rodata->csd_ipi_response_threshold_ms = env.csd_ipi_response_threshold_ms;
	skel->rodata->csd_dispatch_threshold_ms = env.csd_dispatch_threshold_ms;
	skel->rodata->csd_func_threshold_ms = env.csd_func_threshold_ms;

	bpf_map__set_max_entries(skel->maps.csd_queue_map, libbpf_num_possible_cpus() * 2);

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

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), event_handler, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "failed to create bpf ring buffer\n");
		goto cleanup;
	}

	ring_buffer__poll(rb, 1000 /* timeout ms */);

	printf("latency of function queue time to remote function start time\n");
	print_log2_hist(skel->bss->queue_hist, MAX_SLOTS, "nsec");
	printf("latency of total time spend in remote IPI callback\n");
	print_log2_hist(skel->bss->ipi_hist, MAX_SLOTS, "nsec");
	printf("latency of individual functions dispatched within a single IPI callback\n");
	print_log2_hist(skel->bss->func_hist, MAX_SLOTS, "nsec");

	if (rb)
		ring_buffer__free(rb);

cleanup:
	csdlatency_bpf__destroy(skel);
	return -err;
}
