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
	__u64 call_single_threshold_ms; /* report when smp_call_function_single() exceeds this */
	__u64 call_many_threshold_ms; /* report when smp_call_function_many() exceeds this */
	__u64 queue_lat_threshold_ms;
	__u64 queue_flush_threshold_ms;
	__u64 csd_func_threshold_ms;
} env = {
	.interval = 1,
	.nr_intervals = 10,
	.perf_max_stack_depth = 127, /* from sysctl kernel.perf_event_max_stack */
	.call_single_threshold_ms = 500,
	.call_many_threshold_ms = 500,
	.queue_lat_threshold_ms = 500,
	.queue_flush_threshold_ms = 500,
	.csd_func_threshold_ms = 500
};

static int nr_cpus = -1;
static struct ksyms *ksyms;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int event_handler(void *ctx, void *data, size_t sz)
{
	struct event *event = (struct event *)data;

	switch (event->type) {
		case CSD_CALL_SINGLE_LATENCY:
			printf("smp_call_function_single() took too long (%llu ms)\n", event->t / 1000000);
			break;
		case CSD_CALL_MANY_LATENCY:
			printf("smp_call_function_many*() took too long (%llu ms)\n", event->t / 1000000);
			break;
		case CSD_FLUSH_LATENCY:
			size_t i;

			printf("csd flush took too long (%llu ms)\n", event->t / 1000000);
			printf("the stack below was delayed during this time:\n");

			for (i = 0; i < event->stack_sz / sizeof(event->stack[0]); ++i) {
				const uint64_t addr = event->stack[i];
				const struct ksym *ksym = ksyms__map_addr(ksyms, addr);
				printf("%zu: %s\n", i, ksym->name);
			}

			break;
		case CSD_FUNC_LATENCY:
			const struct ksym *ksym = ksyms__map_addr(ksyms, event->func);
			printf("csd func %s(%llx) took too long (%llu ms)\n", ksym->name, event->func, event->t / 1000000);
			break;
		case CSD_FUNC_STALL:
			printf("csd func %s(%llx) has not run on cpu %u\n", ksym->name, event->func, event->t / 1000000);
			break;
		default:
			printf("unknown event\n");
			break;
	}

	return 0;
}

static void dump_histograms(const struct csdlatency_bpf *skel)
{
	if (nr_cpus < 1)
		return;

	printf("latency of smp_call_function_single\n");
	print_log2_hist(skel->bss->call_single_hist, MAX_SLOTS, "nsec");

	printf("latency of smp_call_function_many_cond\n");
	print_log2_hist(skel->bss->call_many_hist, MAX_SLOTS, "nsec");

	printf("latency of csd func enqueue to remote function entry\n");
	print_log2_hist(skel->bss->queue_lat_hist, MAX_SLOTS, "nsec");

	printf("latency of time spent in interrupt handler (generic_smp_call_function_single_interrupt)\n");
	print_log2_hist(skel->bss->queue_flush_hist, MAX_SLOTS, "nsec");

	printf("latency of individual csd functions entry to exit\n");
	print_log2_hist(skel->bss->func_lat_hist, MAX_SLOTS, "nsec");

	printf("frequency of csd ipi's sent to cpu's\n");
	print_linear_hist(skel->data_ipi_cpu_hist->ipi_cpu_hist, nr_cpus, 0, 1, "cpu");
}

int main(int argc, char **argv)
{
	struct csdlatency_bpf *skel;
	struct ring_buffer *rb;
	int err;

	nr_cpus = libbpf_num_possible_cpus();

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

	skel->rodata->nr_cpus = nr_cpus;

	skel->rodata->call_single_threshold_ms = env.call_single_threshold_ms;
	skel->rodata->call_many_threshold_ms = env.call_many_threshold_ms;
	skel->rodata->queue_lat_threshold_ms = env.queue_lat_threshold_ms;
	skel->rodata->queue_flush_threshold_ms = env.queue_flush_threshold_ms;
	skel->rodata->csd_func_threshold_ms = env.csd_func_threshold_ms;

	size_t sz = bpf_map__set_value_size(skel->maps.data_ipi_cpu_hist, sizeof(skel->data_ipi_cpu_hist->ipi_cpu_hist[0]) * nr_cpus);
	skel->data_ipi_cpu_hist = bpf_map__initial_value(skel->maps.data_ipi_cpu_hist, &sz);

	bpf_map__set_max_entries(skel->maps.csd_queue_map, nr_cpus * 2);

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

	int i;
	for (i = 0; i < env.nr_intervals; ++i) {
		ring_buffer__poll(rb, env.interval * 1000 /* timeout ms */);
		dump_histograms(skel);
	}

	if (rb)
		ring_buffer__free(rb);

cleanup:
	csdlatency_bpf__destroy(skel);
	return -err;
}
