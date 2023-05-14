// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "ttysnoop.h"
#include "ttysnoop.skel.h"
#include "compat.h"
#include <sys/stat.h>

static volatile bool exiting = false;

static struct env {
	bool verbose;
	bool clear_screen;
	int count;
	int pts_inode;
	bool record;
	char *record_filename;
} env = {
	.clear_screen = true,
	.pts_inode = -1,
	.count = 16,
};

const char *argp_program_version = "ttysnoop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Watch live output from a tty or pts device.\n"
"\n"
"USAGE:   ttysnoop [-Ch] {PTS | /dev/ttydev}  # try -h for help\n"
"\n"
"Example:\n"
"    ttysnoop /dev/pts/2          # snoop output from /dev/pts/2\n"
"    ttysnoop 2                   # snoop output from /dev/pts/2 (shortcut)\n"
"    ttysnoop /dev/console        # snoop output from the system console\n"
"    ttysnoop /dev/tty0           # snoop output from /dev/tty0\n"
"    ttysnoop /dev/pts/2 -c 2     # snoop output from /dev/pts/2 with 2 checks\n"
"                                   for 256 bytes of data in buffer\n"
"                                   (potentially retrieving 512 bytes)\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "noclear", 'C', NULL, 0, "Don't clear the screen" },
	{ "datacount", 'c', "COUNT", 0, "Number of times we check for 'data-size' data (default 16)" },
	{ "record", 'r', "RECORD", 0, "Record tty history" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
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
	case 'C':
		env.clear_screen = false;
		break;
	case 'c':
		env.count = argp_parse_long(key, arg, state);
		break;
	case 'r':
		env.record = true;
		env.record_filename = arg;
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num != 0) {
			warning("Unrecognized positional arguments: %s\n", arg);
			argp_usage(state);
		}

		char path[4096] = {};
		struct stat st;

		if (arg[0] != '/') {
			strcpy(path, "/dev/pts/");
			strcat(path, arg);
		} else {
			strcpy(path, arg);
		}

		if (stat(path, &st)) {
			warning("Failed to stat console file: %s\n", arg);
			argp_usage(state);
		}
		env.pts_inode = st.st_ino;
		break;
	case ARGP_KEY_END:
		if (env.pts_inode == -1)
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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	char buf[BUFSIZ+1] = {};
	int fd = *(int *)ctx;

	memcpy(buf, e->buf, e->count);
	printf("%s", buf);
	fflush(stdout);

	if (fd > 0)
		write(fd, buf, e->count);

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu event on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char *argv[])
{
	const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct ttysnoop_bpf *obj;
	struct bpf_buffer *buf = NULL;
	int err, fd = -1;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	obj = ttysnoop_bpf__open();
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	obj->rodata->user_data_count = env.count;
	obj->rodata->pts_inode = env.pts_inode;

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		warning("Failed to create ring/perf buffer: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	err = ttysnoop_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = ttysnoop_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF object: %d\n", err);
		goto cleanup;
	}

	if (env.record) {
		fd = creat(env.record_filename, 0644);
		if (fd < 0) {
			warning("Failed to creat record file\n");
			err = fd;
			goto cleanup;
		}
	}

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, &fd);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (env.clear_screen)
		system("clear");

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling ring/perf buffer: %d\n", err);
			break;
		}
		/* reset err to 0 when exiting */
		err = 0;
	}

cleanup:
	bpf_buffer__free(buf);
	ttysnoop_bpf__destroy(obj);

	if (fd > 0)
		close(fd);

	return err != 0;
}
