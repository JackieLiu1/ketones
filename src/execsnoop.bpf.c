// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "execsnoop.h"
#include "maps.bpf.h"

#define MAX_ENTRIES	10240

const volatile bool filter_memcg = false;
const volatile bool ignore_failed = true;
const volatile uid_t target_uid = INVALID_UID;
const volatile int max_args = DEFAULT_MAX_ARGS;

static const struct event zero;

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, pid_t);
	__type(value, struct event);
} execs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("ksyscall/execve")
int BPF_KSYSCALL(syscall_enter_execve, const char *filename, const char *argv[],
		 const char *env[])
{
	uid_t uid;
	pid_t pid, tgid;
	struct event *event;
	struct task_struct *task;
	unsigned int ret;
	const char *argp;

	if (filter_memcg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	uid = (uid_t)bpf_get_current_uid_gid();
	if (target_uid != INVALID_UID && target_uid != uid)
		return 0;

	task = (struct task_struct *)bpf_get_current_task();
	pid = BPF_CORE_READ(task, pid);
	tgid = BPF_CORE_READ(task, tgid);

	event = bpf_map_lookup_or_try_init(&execs, &pid, &zero);
	if (!event)
		return 0;

	event->pid = pid;
	event->uid = uid;
	event->ppid = BPF_CORE_READ(task, real_parent, tgid);
	event->args_count = 0;
	event->args_size = 0;

	/* record filenem */
	ret = bpf_probe_read_user_str(event->args, ARGSIZE, filename);
	if (ret <= ARGSIZE) {
		event->args_size += ret;
		event->args_count++;
	} else {
		/* write an empty string */
		event->args[0] = 0;
		return 0;
	}

	#pragma unroll
	for (int i = 1; i < TOTAL_MAX_ARGS && i < max_args; i++) {
		bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
		if (!argp)
			return 0;

		if (event->args_size > LAST_ARG)
			return 0;

		ret = bpf_probe_read_user_str(&event->args[event->args_size],
					      ARGSIZE, argp);

		event->args_size += ret;
		event->args_count++;
	}

	/* try to read one more argument to check if there is one */
	bpf_probe_read_user_str(&argp, sizeof(argp), &argv[max_args]);
	if (!argp)
		return 0;

	/* pointer to max_args+1 isn't null, asume we have more arguments */
	event->args_count++;
	return 0;
}

SEC("kretsyscall/execve")
int BPF_KSYSCALL(syscall_exit_execve, int ret)
{
	pid_t pid;
	uid_t uid;
	struct event *event;

	if (filter_memcg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	uid = (uid_t)bpf_get_current_uid_gid();
	if (target_uid != INVALID_UID && uid != target_uid)
		return 0;

	pid = (pid_t)bpf_get_current_pid_tgid();
	event = bpf_map_lookup_elem(&execs, &pid);
	if (!event)
		return 0;

	if (ignore_failed && ret < 0)
		goto cleanup;

	event->retval = ret;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	/* actual len is smaller than sizeof(struct event) */
	if (EVENT_SIZE(event) <= sizeof(struct event))
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
				      EVENT_SIZE(event));

cleanup:
	bpf_map_delete_elem(&execs, &pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
