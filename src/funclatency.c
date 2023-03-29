// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "funclatency.h"
#include "funclatency.skel.h"
#include "trace_helpers.h"
#include "map_helpers.h"
#include "btf_helpers.h"
#include "uprobe_helpers.h"

static struct env {
	int units;
	pid_t pid;
	unsigned int duration;
	unsigned int interval;
	unsigned int iterations;
	bool timestamp;
	char *funcname;
	bool verbose;
	char *cgroupspath;
	bool cg;
} env = {
	.interval = 99999999,
	.iterations = 99999999,
};

const char *argp_program_version = "funclatency 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char args_doc[] = "FUNCTION";
const char argp_program_doc[] =
"Time functions and print latency as a histogram\n"
"\n"
"Usage: funclatency [-h] [-m|-u] [-p PID] [-d DURATION] [ -i INTERVAL ] [-c CG]\n"
"                   [-T] FUNCTION\n"
"       Choices for FUNCTION: FUNCTION         (kprobe)\n"
"                             LIBRARY:FUNCTION (uprobe a library in -p PID)\n"
"                             :FUNCTION        (uprobe the binary of -p PID)\n"
"                             PROGRAM:FUNCTION (uprobe the binary PROGRAM)\n"
"\v"
"Examples:\n"
"  ./funclatency do_sys_open         # time the do_sys_open() kernel function\n"
"  ./funclatency -m do_nanosleep     # time do_nanosleep(), in milliseconds\n"
"  ./funclatency -c CG               # Trace process under cgroupsPath CG\n"
"  ./funclatency -u vfs_read         # time vfs_read(), in microseconds\n"
"  ./funclatency -p 181 vfs_read     # time process 181 only\n"
"  ./funclatency -p 181 c:read       # time the read() C library function\n"
"  ./funclatency -p 181 :foo         # time foo() from pid 181's userspace\n"
"  ./funclatency -i 2 -d 10 vfs_read # output every 2 seconds, for 10s\n"
"  ./funclatency -mTi 5 vfs_read     # output every 5 seconds, with timestamps\n";

static const struct argp_option opts[] = {
	{ "milliseconds", 'm', NULL, 0, "Output in milliseconds" },
	{ "microseconds", 'u', NULL, 0, "Output in microseconds" },
	{ 0, 0, 0, 0, "" },
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ 0, 0, 0, 0, "" },
	{ "interval", 'i', "INTERVAL", 0, "Summary interval in seconds" },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path" },
	{ "duration", 'd', "DURATION", 0, "Duration to trace" },
	{ "timestamp", 'T', NULL, 0, "Print timestamp" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct env *env = state->input;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env->verbose = true;
		break;
	case 'T':
		env->timestamp = true;
		break;
	case 'c':
		env->cgroupspath = arg;
		env->cg = true;
		break;
	case 'p':
		errno = 0;
		env->pid = strtol(arg, NULL, 10);
		if (errno || env->pid <= 0) {
			warning("Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'm':
		if (env->units != NSEC) {
			warning("only set one of -m or -u\n");
			argp_usage(state);
		}
		env->units = MSEC;
		break;
	case 'u':
		if (env->units != NSEC) {
			warning("only set one of -m or -u\n");
			argp_usage(state);
		}
		env->units = USEC;
		break;
	case 'd':
		errno = 0;
		env->duration = strtol(arg, NULL, 10);
		if (errno || env->duration <= 0) {
			warning("Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'i':
		errno = 0;
		env->interval = strtol(arg, NULL, 10);
		if (errno || env->interval <= 0) {
			warning("Invalid interval: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		if (env->funcname) {
			warning("Too many function names: %s\n", arg);
			argp_usage(state);
		}
		env->funcname = arg;
		break;
	case ARGP_KEY_END:
		if (!env->funcname) {
			warning("Need a function to trace\n");
			argp_usage(state);
		}
		if (env->duration) {
			if (env->interval > env->duration)
				env->interval = env->duration;
			env->iterations = env->duration / env->interval;
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static const char *unit2str(void)
{
	switch (env.units) {
	case NSEC:
		return "nsec";
	case MSEC:
		return "msec";
	case USEC:
		return "usec";
	};

	return "bad units";
}

static int attach_kprobes(struct funclatency_bpf *obj)
{
	long err;

	obj->links.dummy_kprobe = bpf_program__attach_kprobe(obj->progs.dummy_kprobe, false,
							     env.funcname);
	if (!obj->links.dummy_kprobe) {
		err = -errno;
		warning("Failed to attach kprobe: %ld\n", err);
		return -1;
	}

	obj->links.dummy_kretprobe = bpf_program__attach_kprobe(obj->progs.dummy_kretprobe, true,
								env.funcname);
	if (!obj->links.dummy_kretprobe) {
		err = -errno;
		warning("Failed to attach kretprobe: %ld\n", err);
		return -1;
	}

	return 0;
}

static int attach_uprobes(struct funclatency_bpf *obj)
{
	char *binary, *function;
	char bin_path[PATH_MAX];
	off_t func_off;
	int ret = -1;
	long err;

	binary = strdup(env.funcname);
	if (!binary) {
		warning("strdup failed");
		return -1;
	}

	function = strchr(binary, ':');
	if (!function) {
		warning("Binary should have contained ':' (internal bug!)\n");
		return -1;
	}

	*function = '\0';
	function++;

	if (resolve_binary_path(binary, env.pid, bin_path, sizeof(bin_path)))
		goto out_binary;

	func_off = get_elf_func_offset(bin_path, function);
	if (func_off < 0) {
		warning("Could not find %s in %s\n", function, bin_path);
		goto out_binary;
	}

	obj->links.dummy_kprobe =
		bpf_program__attach_uprobe(obj->progs.dummy_kprobe, false,
					   env.pid ?: -1, bin_path, func_off);
	if (!obj->links.dummy_kprobe) {
		err = -errno;
		warning("Failed to attach uprobe: %ld\n", err);
		goto out_binary;
	}

	obj->links.dummy_kretprobe =
		bpf_program__attach_uprobe(obj->progs.dummy_kretprobe, true,
					   env.pid ?: -1, bin_path, func_off);
	if (!obj->links.dummy_kretprobe) {
		err = -errno;
		warning("Failed to attach uprobe: %ld\n", err);
		goto out_binary;
	}

	ret = 0;

out_binary:
	free(binary);
	return ret;
}

static int attach_probes(struct funclatency_bpf *obj)
{
	if (strchr(env.funcname, ':'))
		return attach_uprobes(obj);
	return attach_kprobes(obj);
}

static volatile bool exiting = false;

static void sig_hander(int sig)
{
	exiting = true;
}

static struct sigaction sigact = {
	.sa_handler = sig_hander
};

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.parser = parse_arg,
		.options = opts,
		.args_doc = args_doc,
		.doc = argp_program_doc,
	};
	struct funclatency_bpf *obj;
	int err, cgfd;

	err = argp_parse(&argp, argc, argv, 0, NULL, &env);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	sigaction(SIGINT, &sigact, 0);

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = funclatency_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to load BPF object\n");
		return 1;
	}

	obj->rodata->units = env.units;
	obj->rodata->target_tgid = env.pid;
	obj->rodata->filter_memcg = env.cg;

	err = funclatency_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object\n");
		return 1;
	}

	/* update cgroup path to map */
	if (env.cg) {
		int idx = 0;

		cgfd = open(env.cgroupspath, O_RDONLY);
		if (cgfd < 0) {
			warning("Failed opening Cgroup path: %s", env.cgroupspath);
			goto cleanup;
		}
		if (bpf_map_update_elem(bpf_map__fd(obj->maps.cgroup_map), &idx, &cgfd,
					BPF_ANY)) {
			warning("Failed adding target cgroup to map");
			goto cleanup;
		}
	}

	if (!obj->bss) {
		warning("Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		goto cleanup;
	}

	err = attach_probes(obj);
	if (err)
		goto cleanup;

	printf("Tracing %s. Hit Ctrl-C to exit\n", env.funcname);

	for (int i = 0; i < env.iterations && !exiting; i++) {
		sleep(env.interval);

		printf("\n");
		if (env.timestamp) {
			time_t t;
			struct tm *tm;
			char ts[32];

			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);

			printf("%-8s\n", ts);
		}

		print_log2_hist(obj->bss->hists, MAX_SLOTS, unit2str());
		memset(obj->bss->hists, 0, MAX_SLOTS * sizeof(__u32));
	}

	printf("Exiting trace of %s\n", env.funcname);

cleanup:
	funclatency_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}
