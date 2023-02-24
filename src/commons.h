#ifndef __COMMONS_H
#define __COMMONS_H

#include <argp.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define warning(...) fprintf(stderr, __VA_ARGS__)

static inline bool bpf_is_root()
{
	if (getuid()) {
		warning("Please run the tool as root - Exiting.\n");
		return false;
	} else
		return true;
}

static inline int get_pid_max(void)
{
	int pid_max;
	FILE *f;

	f = fopen("/proc/sys/kernel/pid_max", "r");
	if (!f)
		return -1;
	if (fscanf(f, "%d\n", &pid_max) != 1)
		pid_max = -1;
	fclose(f);
	return pid_max;
}

#endif
