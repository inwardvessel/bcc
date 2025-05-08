// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
#ifndef __MEMCGSTAT_H
#define __MEMCGSTAT_H

#define MAX_NAME_LEN 64

struct mem_stat_event {
	char name[MAX_NAME_LEN];
	__u64 val;
};

#endif /* __MEMCGSTAT_H */
