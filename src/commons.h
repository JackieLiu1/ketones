#ifndef __COMMONS_H
#define __COMMONS_H

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define warning(...) fprintf(stderr, __VA_ARGS__)

static inline bool bpf_is_root()
{
	if (getuid()) {
		warning("Please run the tool as root - Exiting.\n");
		return false;
	} else
		return true;
}

#endif
