// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "loads.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include <linux/perf_event.h>
#include <sys/syscall.h>

static struct env {
	int interval;
	int times;
	bool verbose;
	bool timestamp;
} env = {
	.times = 99999999,
	.interval = 1,
};

static volatile bool exiting = false;

const char *argp_program_version = "loads 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Print load averages\n"
"\n"
"USAGE: loads [-i INTERVAL] [-t times]\n"
"\n"
"EXAMPLE:\n"
"    loads                 # print load average every 1 seconds\n"
"    loads -i 10           # print load average every 10 seconds\n"
"    loads -t 5            # print load average 5 times\n";

static const struct argp_option opts[] = {
	{ "interval", 'i', "INTERVAL", 0, "Output interval, in seconds (Default 1)" },
	{ "times", 't', "TIMES", 0, "The number of outputs" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "SHow the full help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 't':
		env.times = argp_parse_long(key, arg, state);
		break;
	case 'i':
		env.interval = argp_parse_long(key, arg, state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int open_and_attach_perf_event(struct bpf_program *prog, struct bpf_link *link)
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_CPU_CLOCK,
		.sample_period = env.interval * 500000000,
	};

	int fd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, 0);
	if (fd < 0) {
		warning("Failed to init perf sampling: %s\n", strerror(errno));
		return -1;
	}

	link = bpf_program__attach_perf_event(prog, fd);
	if (!link) {
		warning("Failed to attach perf event on CPU#0\n");
		close(fd);
		return 1;
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

static void sig_handler(int sig)
{
	exiting = true;
}

static void print_loads(struct loads_bpf__bss *bss)
{
	__u64 load1  = __atomic_load_n(&bss->loads[0], __ATOMIC_RELAXED);
	__u64 load5  = __atomic_load_n(&bss->loads[1], __ATOMIC_RELAXED);
	__u64 load15 = __atomic_load_n(&bss->loads[2], __ATOMIC_RELAXED);

	if (env.timestamp) {
		char ts[32];

		strftime_now(ts, sizeof(ts), "%H:%M:%S");
		printf("%s ", ts);
	}

	printf("load averages: %lld.%03lld %lld.%03lld %lld.%03lld\n",
	       load1 >> 11, ((load1 & ((1 << 11) - 1)) * 1000) >> 11,
	       load5 >> 11, ((load5 & ((1 << 11) - 1)) * 1000) >> 11,
	       load15 >> 11, ((load15 & ((1 << 11) - 1)) * 1000) >> 11);
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_link *link = NULL;
	struct loads_bpf *obj;
	struct ksyms *ksyms = NULL;
	const struct ksym *ksym;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n", strerror(-errno));
		return 1;
	}

	obj = loads_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		warning("Failed to load ksyms\n");
		err = 1;
		goto cleanup;
	}

	ksym = ksyms__get_symbol(ksyms, "avenrun");
	if (!ksym) {
		warning("Failed to get avenrun's kernel address\n");
		err = 1;
		goto cleanup;
	}

	obj->rodata->avenrun_kaddr = ksym->addr;

	err = loads_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	if (!obj->bss) {
		warning("Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		err = 1;
		goto cleanup;
	}

	err = open_and_attach_perf_event(obj->progs.do_sample, link);
	if (err)
		goto cleanup;

	printf("Reading load averages... Hit Ctrl-C to end.\n");

	signal(SIGINT, sig_handler);

	while (!exiting) {
		sleep(env.interval);
		print_loads(obj->bss);

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	bpf_link__destroy(link);
	loads_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);
	ksyms__free(ksyms);

	return err != 0;
}
