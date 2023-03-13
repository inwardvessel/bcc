// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "experiment.skel.h"
#include "trace_helpers.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args);

static bool verbose;

int main(int argc, char *argv[])
{
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	struct experiment_bpf *skel = experiment_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open bpf object\n");

		goto exit;
	}

	skel->rodata->pid = getpid();

	if (experiment_bpf__load(skel)) {
		fprintf(stderr, "failed to load bpf object\n");

		goto cleanup;
	}

	// attach uprobe to the function: puts()
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts,
			.func_name = "puts",
			.retprobe = false);
	skel->links.user_func = bpf_program__attach_uprobe_opts(
			skel->progs.user_func, 0, "libc.so.6", 0, &uprobe_opts);
	if (!skel->links.user_func) { \
		perror("no program attached for puts");

		goto cleanup;
	}

	if (experiment_bpf__attach(skel)) {
		fprintf(stderr, "failed to attach bpf program\n");
		goto cleanup;
	}

	// echo loop, quits on reading 'q' as first char
	for (;;) {
		char buffer[32] = {0};
		read(STDIN_FILENO, buffer, sizeof(buffer));

		if (buffer[0] == 'q')
			break;

		puts(buffer);
	}

cleanup:
	experiment_bpf__destroy(skel);

exit:
	printf("done\n");

	return 0;
}

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;

	return vfprintf(stderr, format, args);
}
