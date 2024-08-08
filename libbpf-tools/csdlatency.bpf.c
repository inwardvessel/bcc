// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
#include "<vmlinux.h>"
#include <bpf/bpf_helpers.h>
#include <errno.h>
#include "csdlatency.h"
#include "bits.bpf.h"

extern struct bpf_cpumask *bpf_cpumask_create(void) __ksym;
extern void bpf_cpumask_copy(struct bpf_cpumask *dst, const struct cpumask *src) __ksym;
extern bool bpf_cpumask_test_cpu(u32 cpu, const struct cpumask *cpumask) __ksym;
extern void bpf_cpumask_release(struct bpf_cpumask *cpumask) __ksym;

extern void generic_smp_call_function_single_interrupt(void) __ksym;

/* key for single element percpu arrays */
static const __u32 percpu_key = 0;

const volatile unsigned int nr_cpus = 1;
const volatile __u64 max_ipi_dispatch_ms = 1000;

struct csd_queue_key {
	unsigned int cpu;
	void *func;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128); /* TODO set in user prog */
	__type(key, struct csd_queue_key);
	__type(value, u64);
} csd_queue_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} csd_func_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128); /* TODO set in user prog: nr_cpus**2 */
	__type(key, unsigned int);
	__type(value, u64);
} ipi_send_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} ipi_dispatch_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
} stacks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* time from func enqueue to func entry */
__u32 csd_queue_hist[MAX_SLOTS] = {};
/* time spent in func */
__u32 csd_func_hist[MAX_SLOTS] = {};
/* time from ipi send to interrupt handler */
__u32 ipi_hist[MAX_SLOTS] = {};

struct update_ipi_ctx {
	u64 t;
	struct bpf_cpumask *cpumask;
};

SEC("tracepoint/csd/csd_queue_cpu")
int handle_csd_queue(struct trace_event_raw_csd_queue_cpu *ctx)
{
	const u64 t = bpf_ktime_get_ns();
	const struct csd_queue_key key = {
		.cpu = (unsigned int)ctx->cpu,
		.func = (void *)ctx->func
	};

	bpf_map_update_elem(&csd_queue_map, &key, &t, BPF_NOEXIST);
	return 0;
}

SEC("tp/csd/csd_function_entry")
int handle_csd_function_entry(struct trace_event_raw_csd_function *ctx)
{
	u64 *t0, t1, slot;
	s64 dt;
	struct csd_queue_key csd_queue_key;

	t1 = bpf_ktime_get_ns();
	csd_queue_key.cpu = bpf_get_smp_processor_id();
	csd_queue_key.func = (void *)ctx->func;
	t0 = bpf_map_lookup_elem(&csd_queue_map, &csd_queue_key);
	if (!t0)
		return 0;

	dt = (s64)(t1 - *t0);
	if (dt < 0)
		goto cleanup;

	slot = log2(dt);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&csd_queue_hist[slot], 1);

	bpf_map_update_elem(&csd_func_map, &percpu_key, &t1, BPF_ANY);

cleanup:
	bpf_map_delete_elem(&csd_queue_map, &csd_queue_key);
	return 0;
}

SEC("tp/csd/csd_function_exit")
int handle_csd_function_exit(struct trace_event_raw_csd_function *ctx)
{
	u64 *t0, t1, slot;
	s64 dt;

	t1 = bpf_ktime_get_ns();
	t0 = bpf_map_lookup_elem(&csd_func_map, &percpu_key);
	if (!t0)
		return 0;

	dt = (s64)(t1 - *t0);
	if (dt < 0)
		return 0;

	slot = log2l(dt);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&csd_func_hist[slot], 1);

	return 0;
}

SEC("tp/ipi/ipi_send_cpu")
int handle_ipi_send_cpu(struct trace_event_raw_ipi_send_cpu *ctx)
{
	u64 t;
	unsigned int cpu;

	if (ctx->callback != generic_smp_call_function_single_interrupt)
		return 0;

	t = bpf_ktime_get_ns();
	cpu = ctx->cpu;
	bpf_map_update_elem(&ipi_send_map, &cpu, &t, BPF_NOEXIST);
	return 0;
}

static long maybe_update_ipi_map(u32 cpu, void *ctx)
{
	struct update_ipi_ctx *x = (struct update_ipi_ctx *)ctx;

	if (bpf_cpumask_test_cpu(cpu, (struct cpumask *)x->cpumask))
		bpf_map_update_elem(&ipi_send_map, &cpu, &x->t, BPF_NOEXIST);

	return 0;
}

SEC("tp_btf/ipi_send_cpumask")
int handle_ipi_send_cpumask(struct bpf_raw_tracepoint_args *ctx)
{
	struct update_ipi_ctx x;
	struct cpumask *cpumask;
	void *callback;

	cpumask = (struct cpumask *)ctx->args[0];
	callback = (void *)ctx->args[2];
	if (callback != generic_smp_call_function_single_interrupt)
		return 0;

	x.t = bpf_ktime_get_ns();
	x.cpumask = bpf_cpumask_create();
	if (!x.cpumask)
		return -ENOMEM;

	bpf_cpumask_copy(x.cpumask, cpumask);
	bpf_loop(16, maybe_update_ipi_map, &x, 0);
	bpf_cpumask_release(x.cpumask);

	return 0;
}

SEC("fentry/generic_smp_call_function_single_interrupt")
int handle_call_function_single_entry(void)
{
	u64 *t0, t1, slot;
	s64 dt;
	unsigned int cpu;

	t1 = bpf_ktime_get_ns();
	cpu = bpf_get_smp_processor_id();
	t0 = bpf_map_lookup_elem(&ipi_send_map, &cpu);
	if (!t0)
		return 0;

	dt = (s64)(t1 - *t0);
	if (dt < 0)
		goto cleanup;

	slot = log2l(dt);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&ipi_hist[slot], 1);

	bpf_map_update_elem(&ipi_dispatch_map, &percpu_key, &t1, BPF_ANY);

cleanup:
	bpf_map_delete_elem(&ipi_send_map, &cpu);
	return 0;
}

SEC("fexit/generic_smp_call_function_single_interrupt")
int handle_call_function_single_exit(void *ctx)
{
	u64 *t0, t1, slot;
	s64 dt;
	int ret = 0;

	t1 = bpf_ktime_get_ns();
	t0 = bpf_map_lookup_elem(&ipi_dispatch_map, &percpu_key);
	if (!t0)
		return 0;

	dt = (s64)(t1 - *t0);
	if (dt < 0)
		return 0;

	slot = log2l(dt);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&ipi_hist[slot], 1);

	if (dt >= max_ipi_dispatch_ms * 1000) {
		struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (e) {
			e->t = dt,
			e->stack_len = bpf_get_stack(ctx, e->stack, sizeof(e->stack), 0);
			bpf_ringbuf_submit(e, 0);
	bpf_printk("stack len: %u\n", e->stack_len);
		}
	}

out:
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
