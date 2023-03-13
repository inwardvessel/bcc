// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <asm-generic/errno.h>

const volatile size_t pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, 1);
} mymap SEC(".maps");

SEC("kretprobe/htab_map_update_elem")
int BPF_KRETPROBE(my_update)
{
	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	long rax = PT_REGS_RC(ctx);
	bpf_printk("rax - long:%ld, hex:%lx\n", rax, rax);

	return 0;
}

SEC("uprobe")
int BPF_KPROBE(user_func, const char *s)
{
	const u64 key = 1;
	const u64 val = 42;
	long err;

	err = bpf_map_update_elem(&mymap, &key, &val, BPF_NOEXIST);

	if (err && err != -EEXIST) {
		bpf_printk("err - long:%ld, int:%d\n", err, err);
		bpf_printk("-EEXIST -long:%ld, int:%d\n", -EEXIST, -EEXIST);
	}

	bpf_printk("uprobe: %s\n", s);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
