// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
#include <argp.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "rstat.h"
#include "rstat.skel.h"
#include "trace_helpers.h"

static struct env {
	int interval; /* dump histograms every N seconds */
	int nr_intervals; /* exit program after N intervals, ignore if negative */
	int perf_max_stack_depth;
	__u64 latency_threshold_ms; /* report when given latency exceeds this */
} env = {
	.interval = 1,
	.nr_intervals = 10,
	.perf_max_stack_depth = 127, /* from sysctl kernel.perf_event_max_stack */
	.latency_threshold_ms = 500
};

const char *argp_program_version = "rstat 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";

const char argp_args_doc[] =
"Trace latencies within CSD pipeline\n"
"\n"
"USAGE: rstat [-h] [-t LATENCY_THRESHOLD] [INTERVAL] [INTERVALS]\n"
"\n"
"EXAMPLES:\n"
"./rstat 5\n"
"        Trace CSD latencies and dump histograms every 5 seconds\n"
"";

static const struct argp_option argp_options[] = {
	{"latency-threshold", 't', "LATENCY_THRESHOLD", 0, "max latency", 0 },
	{},
};

static int nr_cpus = -1;
static struct ksyms *ksyms;

inline uint64_t conv_ms_to_ns(uint64_t ms)
{
	return ms * 1000000;
}

inline uint64_t conv_ns_to_ms(uint64_t ms)
{
	return ms / 1000000;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int event_handler(void *ctx, void *data, size_t sz)
{
	const struct event *event = (struct event *)data;
	const struct ksym *ksym;

	switch (event->type) {
		default:
			printf("unknown event\n");
			break;
	}

	return 0;
}

static void dump_histograms(const struct rstat_bpf *skel)
{
	if (nr_cpus < 1)
		return;

	printf("frequency of csd ipi's sent to cpu's\n");
	print_linear_hist(skel->data_ipi_cpu_hist->ipi_cpu_hist, nr_cpus, 0, 1, "cpu");

	//printf("latency of csd func enqueue to remote function entry\n");
	//print_log2_hist(skel->bss->queue_lat_hist, MAX_SLOTS, "nsec");
}

static long argp_parse_long(int key, const char *arg, struct argp_state *state);
static error_t argp_parse_arg(int key, char *arg, struct argp_state *state);

int main(int argc, char *argv[])
{
	struct rstat_bpf *skel;
	struct ring_buffer *rb;
	int err;

	static const struct argp argp = {
		.options = argp_options,
		.parser = argp_parse_arg,
		.doc = argp_args_doc,
	};


	if (argp_parse(&argp, argc, argv, 0, NULL, NULL)) {
		fprintf(stderr, "failed to parse args\n");

		return 1;
	}

	nr_cpus = libbpf_num_possible_cpus();
	ksyms = ksyms__load();
	if (!ksyms) {
		fprintf(stderr, "failed to load ksyms\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	skel = rstat_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open bpf object\n");
		return 1;
	}

	skel->rodata->nr_cpus = nr_cpus;
	skel->rodata->latency_threshold_ns = conv_ms_to_ns(env.latency_threshold_ms);

	size_t sz = bpf_map__set_value_size(skel->maps.data_ipi_cpu_hist, sizeof(skel->data_ipi_cpu_hist->ipi_cpu_hist[0]) * nr_cpus);
	skel->data_ipi_cpu_hist = bpf_map__initial_value(skel->maps.data_ipi_cpu_hist, &sz);

	bpf_map__set_max_entries(skel->maps.csd_queue_map, nr_cpus * 2);

	err = rstat_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load bpf object\n");
		goto cleanup;
	}

	err = rstat_bpf__attach(skel);
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
	rstat_bpf__destroy(skel);
	return -err;
}

long argp_parse_long(int key, const char *arg, struct argp_state *state)
{
	errno = 0;
	const long temp = strtol(arg, NULL, 10);
	if (errno || temp <= 0) {
		fprintf(stderr, "error arg:%c %s\n", (char)key, arg);
		argp_usage(state);
	}

	return temp;
}

error_t argp_parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args = 0;

	switch (key) {
	case 't':
		printf("arg t\n");
		env.latency_threshold_ms = argp_parse_long(key, arg, state);
		break;
	case ARGP_KEY_ARG:
		pos_args++;
		printf("pos arg %d\n", pos_args);

		if (pos_args == 1) {
			env.interval = argp_parse_long(key, arg, state);
		}
		else if (pos_args == 2) {
			env.nr_intervals = argp_parse_long(key, arg, state);
		} else {
			fprintf(stderr, "Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}

		break;
	default:
		printf("arg unknown\n");
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}
