// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
#ifndef __CGSTAT_H
#define __CGSTAT_H

#define MAX_NAME_LEN 32

struct mem_stat_event {
	char name[MAX_NAME_LEN];
	unsigned int idx;
	__u64 size;
};

#endif /* __CGSTAT_H */
