// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "runqslower.h"
#include "runqslower.skel.h"

struct env {
	pid_t pid;
	__u64 min_us;
	bool verbose;
} env = {
	.min_us = 1000,
};

const char *argp_program_version = "runqslower 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"\n"
"This script traces high scheduling delays between tasks begin\n"
"ready to run and them running on CPU after that.\n"
"\n"
"USAGE: runqslower [-p PID] [min_us]\n"
"\n"
"EXAMPLES:\n"
"  runqslower         # trace run queue latency higher than 10000 us (default)\n"
"  runqslower 1000    # trace run queue latency higher than 1000 us\n"
"  runqslower -p 123  # trace pid 123 only\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static error_t parse_args(int key, char *arg, struct argp_state *state)
{
	static int pos_args;
	int pid;
	long long min_us;

	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env.pid = pid;
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		min_us = strtoll(arg, NULL, 10);
		if (errno || min_us <= 0) {
			fprintf(stderr, "Invalid delay (in us): %s\n", arg);
			argp_usage(state);
		}
		env.min_us = min_us;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int libbpf_print_fn(enum libbpf_print_level level,
		    const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct runq_event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	printf("%-8s %-16s %-6d %14llu\n", ts, e->task, e->pid, e->delta_us);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char *argv[])
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_args,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct runqslower_bpf *bpf_obj;
	int err;

	if (getuid()) {
		fprintf(stderr, "Please run the tool as root - Exiting.\n");
		return 1;
	}

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	/* Use libbpf 1.0 API mode */
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	bpf_obj = runqslower_bpf__open();
	if (!bpf_obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	bpf_obj->rodata->target_pid = env.pid;
	bpf_obj->rodata->min_us = env.min_us;

	err = runqslower_bpf__load(bpf_obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d", err);
		goto cleanup;
	}

	err = runqslower_bpf__attach(bpf_obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	printf("Tracing run queue latency higher than %llu us\n", env.min_us);
	printf("%-8s %-16s %-6s %14s\n", "TIME", "COMM", "PID", "LAT(us)");

	pb = perf_buffer__new(bpf_map__fd(bpf_obj->maps.events), 64,
			      handle_event, handle_lost_events, NULL, NULL);
	err = libbpf_get_error(pb);
	if (err) {
		pb = NULL;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	while ((err = perf_buffer__poll(pb, 100)) >= 0)
		;
	printf("Error polling perf buffer: %d\n", err);

cleanup:
	perf_buffer__free(pb);
	runqslower_bpf__destroy(bpf_obj);

	return err != 0;
}
