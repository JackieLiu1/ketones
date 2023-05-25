// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// WARNING: This program can only be run on kernels that support kprobe multi.
// If it is not supported, it will exit directly. Currently, on X86, at least
// the kernel must be greater than v5.18-rc1 and Config must be enable
// CONFIG_FPROBE, currently not supported on other platforms.
//
// Baseon vfscount.py - 2015 Brendan Gregg

#include "commons.h"
#include "vfscount.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
	bool verbose;
	int interval;
} env = {
	.interval = 99999999,
};

const char *argp_program_version = "vfscount 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Count VFS calls (\"vfs_*\").\n"
"\n"
"USAGE: vfscount [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "interval", 'i', "INTERVAL", 0, "Output interval, in seconds" },
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
	case 'i':
		env.interval = argp_parse_long(key, arg, state);
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
		return false;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = true;
}

#define MAX_ROWS	255
struct value {
	__u64 ip;
	__u64 count;
};

static int sort_column(const void *o1, const void *o2)
{
	const struct value *v1 = o1;
	const struct value *v2 = o2;

	return v2->count - v1->count;
}

struct ksyms *ksyms;

static int print_maps(struct vfscount_bpf *obj)
{
	struct value values[MAX_ROWS];
	int fd = bpf_map__fd(obj->maps.counts);
	__u64 *prev_key = NULL, next_key;
	int err = 0, rows = 0;

	while (!bpf_map_get_next_key(fd, prev_key, &values[rows].ip)) {
		err = bpf_map_lookup_elem(fd, &values[rows].ip, &values[rows].count);
		if (err) {
			warning("bpf_map_lookup_elem failed: %s\n", strerror(errno));
			return err;
		}
		prev_key = &values[rows++].ip;
	}

	qsort(values, rows, sizeof(struct value), sort_column);

	for (int i = 0; i < rows; i++) {
		const struct ksym *ksym = ksyms__map_addr(ksyms, values[i].ip);

		if (ksym) {
			char buf[26] = {};
			sprintf(buf, "b'%s'", ksym->name);
			printf("[<%016llx>] %-26s %8lld\n", values[i].ip, buf,
			       values[i].count);
		} else
			printf("[<%016llx>] b'%-26s' %8lld\n", values[i].ip, "<null sym>",
			       values[i].count);
	}

	prev_key = NULL;
	while (!bpf_map_get_next_key(fd, prev_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err) {
			warning("bpf_map_delete_elem failed: %s\n", strerror(errno));
			return err;
		}
		prev_key = &next_key;
	}

	return err;
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_kprobe_multi_opts, kmopts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct vfscount_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	obj = vfscount_bpf__open_and_load();
	if (!obj) {
		warning("Failed to open and load BPF object\n");
		return 1;
	}

	obj->links.vfs_entry = bpf_program__attach_kprobe_multi_opts(
					obj->progs.vfs_entry, "vfs_*", &kmopts);
	if (!obj->links.vfs_entry) {
		warning("Failed attach kprobe multi, kernel don't support: %s\n", strerror(errno));
		goto cleanup;
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		warning("Failed to load ksyms\n");
		err = 1;
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("Tracing %ld functions... Ctrl-C to end.\n", kmopts.cnt);
	while (!exiting) {
		sleep(env.interval);
		printf("\n%-20s %-26s %8s\n", "ADDR", "FUNC", "COUNT");
		print_maps(obj);
	}

cleanup:
	vfscount_bpf__destroy(obj);
	ksyms__free(ksyms);

	return err != 0;
}
