// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "numamove.skel.h"
#include "trace_helpers.h"

static struct env {
	bool verbose;
} env = {
	.verbose = false,
};

static volatile bool exiting = false;

const char *argp_program_version = "numamove 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Show page migrations of type NUMA misplaced per second.\n"
"\n"
"USAGE: numamove [--help]\n"
"\n"
"EXAMPLES:\n"
"    numamove              # Show page migrations' count and latency";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
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

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char *argv[])
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	struct numamove_bpf *bpf_obj;
	int err;
	bool has_bss;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	bpf_obj = numamove_bpf__open();
	if (!bpf_obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	/* It's fallback to kprobe when kernel does not support fentry. */
	if (fentry_can_attach("migrate_misplaced_page", NULL)) {
		bpf_program__set_autoload(bpf_obj->progs.kprobe_migrate_misplaced_page, false);
		bpf_program__set_autoload(bpf_obj->progs.kretprobe_migrate_misplaced_page, false);
	} else {
		bpf_program__set_autoload(bpf_obj->progs.fentry_migrate_misplaced_page, false);
		bpf_program__set_autoload(bpf_obj->progs.fexit_migrate_misplaced_page, false);
	}

	err = numamove_bpf__load(bpf_obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	has_bss = bpf_obj->bss;
	if (!has_bss)
		warning("Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n\n");

	err = numamove_bpf__attach(bpf_obj);
	if (err) {
		warning("Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Failed to set signal hander\n");
		err = 1;
		goto cleanup;
	}

	printf("%-10s %19s %18s\n", "TIME", "NUMA_migrations_num", "NUMA_migrateions_ms");
	while (!exiting) {
		time_t t;
		struct tm *tm;
		char ts[32];

		sleep(1);

		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		if (has_bss){
			printf("%-10s %18lld %18lld\n", ts,
			       __atomic_exchange_n(&bpf_obj->bss->num, 0, __ATOMIC_RELAXED),
			       __atomic_exchange_n(&bpf_obj->bss->latency, 0, __ATOMIC_RELAXED));
		} else {
			int num_fd = bpf_map__fd(bpf_obj->maps.num_map);
			int latency_fd = bpf_map__fd(bpf_obj->maps.latency_map);
			int key = 0, value = 0;
			__u64 num, latency;

			bpf_map_lookup_elem(num_fd, &key, &num);
			bpf_map_lookup_elem(latency_fd, &key, &latency);

			printf("%-10s %19lld %18lld\n", ts, num, latency);
			bpf_map_update_elem(num_fd, &key, &value, BPF_ANY);
			bpf_map_update_elem(latency_fd, &key, &value, BPF_ANY);
		}
	}

cleanup:
	numamove_bpf__destroy(bpf_obj);

	return err != 0;
}
