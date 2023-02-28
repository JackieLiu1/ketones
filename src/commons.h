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

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC		1000000000ULL
#endif

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

static inline double time_since_start(struct timespec start_time)
{
	long nsec, sec;
	static struct timespec current_time;

	clock_gettime(CLOCK_MONOTONIC, &current_time);
	nsec = current_time.tv_nsec - start_time.tv_nsec;
	sec = current_time.tv_sec - start_time.tv_sec;
	if (nsec < 0) {
		nsec += NSEC_PER_SEC;
		sec--;
	}

	return sec + (double)nsec / NSEC_PER_SEC;
}

#endif