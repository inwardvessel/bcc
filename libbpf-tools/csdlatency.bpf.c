// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
#include "<vmlinux.h>"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>
#include "csdlatency.h"
#include "bits.bpf.h"

extern void generic_smp_call_function_single_interrupt(void) __ksym;

extern bool bpf_cpumask_test_cpu(u32 cpu, const struct cpumask *cpumask) __ksym;

/* key for single element percpu arrays */
static const __u32 percpu_key = 0;

const volatile __u32 nr_cpus;

/* latency thresholds for notifying userspace when exceeded */
const volatile __u64 call_single_threshold_ms;
const volatile __u64 call_many_threshold_ms;
const volatile __u64 ipi_response_threshold_ms;
const volatile __u64 queue_lat_threshold_ms;
const volatile __u64 queue_flush_threshold_ms;
const volatile __u64 csd_func_threshold_ms;

static __u64 conv_ms_to_ns(__u64 ms)
{
	return ms * 1000000;
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} call_single_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} call_many_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128); /* TODO set in user prog */
	__type(key, u64);
	__type(value, u64);
} csd_queue_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} csd_func_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} csd_flush_map SEC(".maps");

struct ipi_queue {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 128); /* TODO set in user prog: nr_cpus**2 */
	__type(value, u64);
};
struct ipi_queue ipi_queue_0 SEC(".maps");
struct ipi_queue ipi_queue_1 SEC(".maps");
struct ipi_queue ipi_queue_2 SEC(".maps");
struct ipi_queue ipi_queue_3 SEC(".maps");
struct ipi_queue ipi_queue_4 SEC(".maps");
struct ipi_queue ipi_queue_5 SEC(".maps");
struct ipi_queue ipi_queue_6 SEC(".maps");
struct ipi_queue ipi_queue_7 SEC(".maps");
struct ipi_queue ipi_queue_8 SEC(".maps");
struct ipi_queue ipi_queue_9 SEC(".maps");
struct ipi_queue ipi_queue_10 SEC(".maps");
struct ipi_queue ipi_queue_11 SEC(".maps");
struct ipi_queue ipi_queue_12 SEC(".maps");
struct ipi_queue ipi_queue_13 SEC(".maps");
struct ipi_queue ipi_queue_14 SEC(".maps");
struct ipi_queue ipi_queue_15 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 16);
	__type(key, u32);
	__array(values, struct ipi_queue);
} ipi_queue_map SEC(".maps") = {
	.values = {
		&ipi_queue_0,
		&ipi_queue_1,
		&ipi_queue_2,
		&ipi_queue_3,
		&ipi_queue_4,
		&ipi_queue_5,
		&ipi_queue_6,
		&ipi_queue_7,
		&ipi_queue_8,
		&ipi_queue_9,
		&ipi_queue_10,
		&ipi_queue_11,
		&ipi_queue_12,
		&ipi_queue_13,
		&ipi_queue_14,
		&ipi_queue_15
	}
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* time spend in smp_call_function_single() */
__u32 call_single_hist[MAX_SLOTS] = {};

/* time spend in smp_call_function_many_cond() */
__u32 call_many_hist[MAX_SLOTS] = {};

/* time from csd func enqueue to func entry */
__u32 queue_lat_hist[MAX_SLOTS] = {};

/* time from exit */
__u32 queue_flush_hist[MAX_SLOTS] = {};

/* time from csd func entry to func exit */
__u32 func_lat_hist[MAX_SLOTS] = {};

/* time from ipi send to interrupt handler entry */
__u32 ipi_lat_hist[MAX_SLOTS] = {};


struct update_ipi_ctx {
	u64 t;
	struct cpumask *cpumask;
};

SEC("fentry/smp_call_function_single")
int BPF_PROG(handle_smp_call_function_single_entry, int cpu, smp_call_func_t func, void *info, int wait)
{
	const u64 t = bpf_ktime_get_ns();

	bpf_map_update_elem(&call_single_map, &percpu_key, &t, BPF_ANY);

	return 0;
}

SEC("fexit/smp_call_function_single")
int BPF_PROG(handle_smp_call_function_single_exit, int cpu, smp_call_func_t func, void *info, int wait)
{
	u64 *t0, t1, slot;
	s64 dt;

	t1 =  bpf_ktime_get_ns();
	t0 = bpf_map_lookup_elem(&call_single_map, &percpu_key);
	if (!t0)
		return 0;

	dt = (s64)(t1 - *t0);
	if (dt < 0)
		return 0;

	slot = log2(dt);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;

	__sync_fetch_and_add(&call_single_hist[slot], 1);

	if (dt >= conv_ms_to_ns(call_single_threshold_ms)) {
		struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (!e)
			return 0;

		e->type = CSD_CALL_SINGLE_LATENCY;
		e->t = dt;
		e->cpu = bpf_get_smp_processor_id();
		/* workaround for reading typedef funcs
		 * e->func = (u64)func;
		 */
		bpf_probe_read_kernel(&e->func, sizeof(e->func), &ctx[1]);
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

SEC("fentry/smp_call_function_many_cond")
int BPF_PROG(handle_smp_call_function_many_cond_entry, const struct cpumask *mask, smp_call_func_t func, void *info, unsigned int scf_flags, smp_cond_func_t cond_func)
{
	const u64 t = bpf_ktime_get_ns();

	bpf_map_update_elem(&call_many_map, &percpu_key, &t, BPF_ANY);

	return 0;
}

SEC("fexit/smp_call_function_many_cond")
int BPF_PROG(handle_smp_call_function_many_cond_exit, const struct cpumask *mask, smp_call_func_t func, void *info, unsigned int scf_flags, smp_cond_func_t cond_func)
{
	u64 *t0, t1, slot;
	s64 dt;

	t1 = bpf_ktime_get_ns();
	t0 = bpf_map_lookup_elem(&call_many_map, &percpu_key);
	if (!t0)
		return 0;

	dt = (s64)(t1 - *t0);
	if (dt < 0)
		return 0;

	slot = log2(dt);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;

	__sync_fetch_and_add(&call_many_hist[slot], 1);

	if (dt >= conv_ms_to_ns(call_many_threshold_ms)) {
		struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (!e)
			return 0;

		e->type = CSD_CALL_MANY_LATENCY;
		e->t = dt;
		e->cpu = bpf_get_smp_processor_id();
		/* workaround for reading typedef funcs
		 * e->func = (u64)func;
		 */
		bpf_probe_read_kernel(&e->func, sizeof(e->func), &ctx[1]);
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

SEC("tracepoint/csd/csd_queue_cpu")
int BPF_PROG(handle_csd_queue, unsigned int cpu, void *callsite, void *func, void *csd)
{
	const u64 t = bpf_ktime_get_ns();
	u64 csd_addr = (u64)csd;

	bpf_map_update_elem(&csd_queue_map, &csd_addr, &t, BPF_NOEXIST);

	return 0;
}

SEC("tracepoint/csd/csd_function_entry")
int BPF_PROG(handle_csd_function_entry, void *func, void *csd)
{
	u64 *t0, t1, slot;
	s64 dt;
	u64 csd_addr = (u64)csd;

	t1 = bpf_ktime_get_ns();
	t0 = bpf_map_lookup_elem(&csd_queue_map, &csd_addr);
	if (t0) {
		dt = (s64)(t1 - *t0);
		bpf_map_delete_elem(&csd_queue_map, &csd_addr);
		if (dt < 0)
			return 0;

		slot = log2(dt);
		if (slot >= MAX_SLOTS)
			slot = MAX_SLOTS - 1;
		__sync_fetch_and_add(&queue_lat_hist[slot], 1);
	}

	bpf_map_update_elem(&csd_func_map, &percpu_key, &t1, BPF_ANY);

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
	__sync_fetch_and_add(&func_lat_hist[slot], 1);

	if (dt >= conv_ms_to_ns(csd_func_threshold_ms)) {
		struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (!e)
			return 0;

		e->type = CSD_FUNC_LATENCY;
		e->t = dt;
		e->func = (u64)ctx->func;
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

SEC("tp/ipi/ipi_send_cpu")
int handle_ipi_send_cpu(struct trace_event_raw_ipi_send_cpu *ctx)
{
	u64 t;
	u32 cpu;
	struct bpf_map *map;

	if (ctx->callback != generic_smp_call_function_single_interrupt)
		return 0;

	t = bpf_ktime_get_ns();
	cpu = ctx->cpu;

	map = bpf_map_lookup_elem(&ipi_queue_map, &cpu);
	if (!map)
		return 0;

	if (bpf_map_push_elem(map, &t, BPF_ANY)) {
		bpf_printk("push fail 1\n");
	}

	return 0;
}

static long maybe_update_ipi_map(u32 cpu, void *ctx)
{
	struct bpf_map *map;
	struct update_ipi_ctx *x = (struct update_ipi_ctx *)ctx;

	if (bpf_cpumask_test_cpu(cpu, x->cpumask)) {
		map = bpf_map_lookup_elem(&ipi_queue_map, &cpu);
		if (map) {
			if (bpf_map_push_elem(map, &x->t, BPF_ANY)) {
				bpf_printk("push fail 2\n");
			}
		}
	}

	return 0;
}

SEC("tp_btf/ipi_send_cpumask")
int handle_ipi_send_cpumask(struct bpf_raw_tracepoint_args *ctx)
{
	struct update_ipi_ctx x;
	void *callback;

	callback = (void *)ctx->args[2];
	if (callback != generic_smp_call_function_single_interrupt)
		return 0;

	x.t = bpf_ktime_get_ns();
	x.cpumask = (struct cpumask *)ctx->args[0];
	bpf_loop(nr_cpus, maybe_update_ipi_map, &x, 0);

	return 0;
}

SEC("fentry/generic_smp_call_function_single_interrupt")
int handle_call_function_single_entry(void *ctx)
{
	u64 t0, t, slot;
	s64 dt;
	unsigned int cpu;
	struct bpf_map *map;

	t = bpf_ktime_get_ns();
	bpf_map_update_elem(&csd_flush_map, &percpu_key, &t, BPF_ANY);

	cpu = bpf_get_smp_processor_id();
	map = bpf_map_lookup_elem(&ipi_queue_map, &cpu);
	if (!map)
		return 0;

	if (bpf_map_pop_elem(map, &t0))
		return 0;

	dt = (s64)(t - t0);
	if (dt < 0)
		return 0;

	slot = log2l(dt);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&ipi_lat_hist[slot], 1);

	if (dt >= conv_ms_to_ns(ipi_response_threshold_ms)) {
		struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (!e)
			return 0;

		e->type = CSD_IPI_RESPONSE_LATENCY;
		e->t = dt;
		e->cpu = cpu;
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

SEC("fexit/generic_smp_call_function_single_interrupt")
int handle_call_function_single_exit(void *ctx)
{
	u64 *t0, t1, slot;
	s64 dt;

	t1 = bpf_ktime_get_ns();
	t0 = bpf_map_lookup_elem(&csd_flush_map, &percpu_key);
	if (!t0)
		return 0;

	dt = (s64)(t1 - *t0);
	if (dt < 0)
		return 0;

	slot = log2l(dt);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&queue_flush_hist[slot], 1);

	if (dt >= conv_ms_to_ns(queue_flush_threshold_ms)) {
		struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (!e)
			return 0;

		e->type = CSD_DISPATCH_LATENCY;
		e->t = dt;
		e->stack_sz = bpf_get_stack(ctx, e->stack, sizeof(e->stack), 0);
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
