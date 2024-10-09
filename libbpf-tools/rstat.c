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
} env = {
	.interval = 1,
	.nr_intervals = 1,
	.perf_max_stack_depth = 127, /* from sysctl kernel.perf_event_max_stack */
};

const char *argp_program_version = "rstat 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";

const char argp_args_doc[] =
"Trace memcg stat update frequency\n"
"\n"
"USAGE: rstat [-h] [INTERVAL] [INTERVALS]\n"
"\n"
"EXAMPLES:\n"
"./rstat 5\n"
"        Trace and dump counts every 5 seconds\n"
"";

static const struct argp_option argp_options[] = {
	{}
};

static struct ksyms *ksyms;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void dump_histograms(const struct rstat_bpf *skel)
{
	printf("memcg and node stat updates\n");
	print_linear_hist(skel->bss->stat_update_count, skel->rodata->max_stats, 0, 1, "stat");
	printf("event updates\n");
	print_linear_hist(skel->bss->event_update_count, skel->rodata->max_events, 0, 1, "event");
}

static long argp_parse_long(int key, const char *arg, struct argp_state *state);
static error_t argp_parse_arg(int key, char *arg, struct argp_state *state);

int main(int argc, char *argv[])
{
	struct rstat_bpf *skel;
	int i, err;

	static const struct argp argp = {
		.options = argp_options,
		.parser = argp_parse_arg,
		.doc = argp_args_doc,
	};

	if (argp_parse(&argp, argc, argv, 0, NULL, NULL)) {
		fprintf(stderr, "failed to parse args\n");

		return 1;
	}

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

	for (i = 0; i < env.nr_intervals; ++i) {
		sleep(env.interval);
		dump_histograms(skel);
	}

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
