// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Based on vfscount.py - 2015 Brendan Gregg

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);
	__type(value, __u64);
} counts SEC(".maps");

SEC("kprobe.multi/vfs_*")
int BPF_KPROBE(vfs_entry)
{
	static __u64 zero;
	__u64 ip = PT_REGS_IP(ctx);
	__u64 *count = bpf_map_lookup_or_try_init(&counts, &ip, &zero);

	if (!count)
		return 0;

	__sync_fetch_and_add(count, 1);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
