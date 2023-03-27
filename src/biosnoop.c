// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "blk_types.h"
#include "biosnoop.h"
#include "biosnoop.skel.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting = 0;

static struct env {
	char *disk;
	int duration;
	bool timestamp;
	bool queued;
	bool verbose;
	char *cgroupspath;
	bool cg;
} env;

static volatile __u64 start_ts;

const char *argp_program_version = "biosnoop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace block I/O.\n"
"\n"
"USAGE: biosnoop [--help] [-d DISK] [-c CG] [-Q]\n"
"\n"
"EXAMPLES:\n"
"    biosnoop              # trace all block I/O\n"
"    biosnoop -Q           # include OS queued time in I/O time\n"
"    biosnoop 10           # trace for 10 seconds only\n"
"    biosnoop -d sdc       # trace sdc only\n"
"    biosnoop -c CG        # Trace process under cgroupsPath CG\n";

static const struct argp_option opts[] = {
	{ "queued", 'Q', NULL, 0, "Include OS queued time in I/O time" },
	{ "disk", 'd', "DISK", 0, "Trace this disk only" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified/CG", 0, "Trace process in cgroup path" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'Q':
		env.queued = true;
		break;
	case 'c':
		env.cg = true;
		env.cgroupspath = arg;
		break;
	case 'd':
		env.disk = arg;
		if (strlen(arg) + 1 > DISK_NAME_LEN) {
			warning("Invalid disk name %s: too long\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			env.duration = strtoll(arg, NULL, 10);
			if (errno || env.duration <= 0) {
				warning("Invalid delay (in us): %s\n", arg);
				argp_usage(state);
			}
		} else {
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
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
	exiting = 1;
}

static void blk_fill_rwbs(char *rwbs, unsigned int op)
{
	int i = 0;

	if (op & REQ_PREFLUSH)
		rwbs[i++] = 'F';

	switch (op & REQ_OP_MASK) {
	case REQ_OP_WRITE:
	case REQ_OP_WRITE_SAME:
		rwbs[i++] = 'W';
		break;
	case REQ_OP_DISCARD:
		rwbs[i++] = 'D';
		break;
	case REQ_OP_SECURE_ERASE:
		rwbs[i++] = 'D';
		rwbs[i++] = 'E';
		break;
	case REQ_OP_FLUSH:
		rwbs[i++] = 'F';
		break;
	case REQ_OP_READ:
		rwbs[i++] = 'R';
		break;
	default:
		rwbs[i++] = 'N';
		break;
	}

	if (op & REQ_FUA)
		rwbs[i++] = 'F';
	if (op & REQ_RAHEAD)
		rwbs[i++] = 'A';
	if (op & REQ_SYNC)
		rwbs[i++] = 'S';
	if (op & REQ_META)
		rwbs[i++] = 'M';

	rwbs[i] = '\0';
}

static struct partitions *partitions;

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct partition *partition;
	const struct event *e = data;
	char rwbs[RWBS_LEN];

	if (!start_ts)
		start_ts = e->ts;

	blk_fill_rwbs(rwbs, e->cmd_flags);
	partition = partitions__get_by_dev(partitions, e->dev);
	printf("%-11.6f %-14.14s %-7d %-7s %-4s %-10lld %-7d ",
	       (e->ts - start_ts) / 1000000000.0,
	       e->comm, e->pid, partition ? partition->name : "Unknown", rwbs,
	       e->sector, e->len);
	if (env.queued)
		printf("%7.3f ", e->qdelta != -1 ?
			e->qdelta / 1000000.0 : -1);
	printf("%7.3f\n", e->delta / 1000000.0);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char *argv[])
{
	const struct partition *partition;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct ksyms *ksyms = NULL;
	struct biosnoop_bpf *obj;
	__u64 time_end = 0;
	int err;
	int cgfd = -1;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	obj = biosnoop_bpf__open();
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	partitions = partitions__load();
	if (!partitions) {
		warning("Failed to load partitions info\n");
		goto cleanup;
	}

	if (env.disk) {
		partition = partitions__get_by_name(partitions, env.disk);
		if (!partition) {
			warning("Invalid partition name: not exist\n");
			goto cleanup;
		}
		obj->rodata->filter_dev = true;
		obj->rodata->target_dev = partition->dev;
	}
	obj->rodata->target_queued = env.queued;
	obj->rodata->filter_memcg = env.cg;

	if (fentry_can_attach("blk_account_io_start", NULL))
		bpf_program__set_attach_target(obj->progs.blk_account_io_start, 0,
					       "blk_account_io_start");
	else
		bpf_program__set_attach_target(obj->progs.blk_account_io_start, 0,
					       "__blk_account_io_start");

	err = biosnoop_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	if (env.cg) {
		int idx = 0;
		int cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);

		cgfd = open(env.cgroupspath, O_RDONLY);
		if (cgfd < 0) {
			warning("Failed to opening cgroup path: %s\n", env.cgroupspath);
			goto cleanup;
		}
		if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY)) {
			warning("Failed to adding target cgroup to map\n");
			goto cleanup;
		}
	}

	obj->links.blk_account_io_start = bpf_program__attach(obj->progs.blk_account_io_start);
	if (!obj->links.blk_account_io_start) {
		err = - errno;
		warning("Failed to attach blk_account_io_start: %s\n",
			strerror(-err));
		goto cleanup;
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		err = -ENOMEM;
		warning("Failed to load kallsyms\n");
		goto cleanup;
	}
	if (ksyms__get_symbol(ksyms, "blk_account_io_merge_bio")) {
		obj->links.blk_account_io_merge_bio =
			bpf_program__attach(obj->progs.blk_account_io_merge_bio);
		if (!obj->links.blk_account_io_merge_bio) {
			err = -errno;
			warning("Failed to attach blk_account_io_merge_bio: %s\n",
				strerror(-err));
			goto cleanup;
		}
	}

	if (env.queued) {
		obj->links.block_rq_insert =
			bpf_program__attach(obj->progs.block_rq_insert);
		if (!obj->links.block_rq_insert) {
			err = -errno;
			warning("Failed to attach block_rq_insert: %s\n", strerror(-err));
			goto cleanup;
		}
	}

	obj->links.block_rq_issue = bpf_program__attach(obj->progs.block_rq_issue);
	if (!obj->links.block_rq_issue) {
		err = -errno;
		warning("Failed to attach block_rq_issue: %s\n", strerror(-err));
		goto cleanup;
	}

	obj->links.block_rq_complete = bpf_program__attach(obj->progs.block_rq_complete);
	if (!obj->links.block_rq_complete) {
		err = -errno;
		warning("Failed to attach block_rq_complete: %s\n", strerror(-err));
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		warning("Failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	printf("%-11s %-14s %-7s %-7s %-4s %-10s %-7s ",
	       "TIME(s)", "COMM", "PID", "DISK", "T", "SECTOR", "BYTES");
	if (env.queued)
		printf("%7s ", "QUE(ms)");
	printf("%7s\n", "LAT(ms)");

	/* setup duration */
	if (env.duration)
		time_end = get_ktime_ns() + env.duration * NSEC_PER_SEC;

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal hander: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* main poll */
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
		if (env.duration && get_ktime_ns() > time_end)
			break;
	}

cleanup:
	perf_buffer__free(pb);
	biosnoop_bpf__destroy(obj);
	ksyms__free(ksyms);
	partitions__free(partitions);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}
