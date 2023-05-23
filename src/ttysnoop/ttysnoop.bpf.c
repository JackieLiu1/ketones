// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "ttysnoop.h"
#include "compat.bpf.h"
#include "core_fixes.bpf.h"

#define WRITE	1

extern __u32 LINUX_KERNEL_VERSION __kconfig;

const volatile int user_data_count = 16;
const volatile int pts_inode = -1;

static __always_inline int
do_tty_write(void *ctx, const char *buf, size_t count)
{
	for (int i = 0; i < user_data_count && count; i++) {
		struct event *event = reserve_buf(sizeof(*event));
		if (!event)
			break;

		 /**
		  * bpf_probe_read_user() can only use a fixed size, so truncate to count
		  * in user space
		  */
		if (bpf_probe_read_user(&event->buf, sizeof(event->buf), (void *)buf)) {
			discard_buf(event);
			break;
		}

		event->count = count > BUFSIZE ? BUFSIZE : count;
		submit_buf(ctx, event, sizeof(*event));

		if (count < BUFSIZE)
			break;

		count -= BUFSIZE;
		buf += BUFSIZE;
	}

	return 0;
}

SEC("kprobe/tty_write")
int BPF_KPROBE(kprobe__tty_write)
{
	size_t count = 0;
	const char *buf = NULL;
	const struct file *file;

	/*
	 * commit 9bb48c82aced (v5.11-rc4) tty: implement write_iter
	 * hanged arguments of tty_write function
	 */
	if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 10, 11)) {
		file = (struct file *)PT_REGS_PARM1_CORE(ctx);
		buf = (const char *)PT_REGS_PARM2_CORE(ctx);
		count = (size_t)PT_REGS_PARM3_CORE(ctx);
	} else {
		struct kiocb *iocb = (struct kiocb *)PT_REGS_PARM1_CORE(ctx);
		struct iov_iter *from = (struct iov_iter *)PT_REGS_PARM2_CORE(ctx);

		file = BPF_CORE_READ(iocb, ki_filp);

		/* commit 8cd54c1c8480 ("iov_iter: separate direction from flavour")
		 * Instead of having them mixed in iter->type, use separate ->iter_type
		 * and ->data_source (u8 and bool resp.)
		 */
		if (iov_iter_has_iter_type()) {
			if (BPF_CORE_READ(from, iter_type) != ITER_IOVEC &&
			    BPF_CORE_READ(from, iter_type) != ITER_UBUF)
				return 0;
			if (BPF_CORE_READ(from, data_source) != WRITE)
				return 0;

			switch (BPF_CORE_READ(from, iter_type)) {
			case ITER_IOVEC:
				buf = BPF_CORE_READ(from, kvec, iov_base);
				count = BPF_CORE_READ(from, kvec, iov_len);
				break;
			/* commit fcb14cb1bdac ("new iov_iter flavour - ITER_UBUF")
			 * implement new iov_iter flavour ITER_UBUF
			 */
			case ITER_UBUF:
				if (iov_iter_has_ubuf()) {
					buf = BPF_CORE_READ(from, ubuf);
					count = BPF_CORE_READ(from, count);
				} else {
					return 0;
				}
				break;
			default:
				return 0;
			}
		} else {
			unsigned int type;

			if (iov_iter_has_iter_type())
				type = BPF_CORE_READ((struct iov_iter___x *)from, iter_type);
			else
				type = BPF_CORE_READ((struct iov_iter___o *)from, type);
			if (type != (ITER_IOVEC + WRITE))
				return 0;

			buf = BPF_CORE_READ(from, kvec, iov_base);
			count = BPF_CORE_READ(from, kvec, iov_len);
		}
	}

	if (BPF_CORE_READ(file, f_inode, i_ino) != pts_inode)
		return 0;

	return do_tty_write(ctx, buf, count);
}

char LICENSE[] SEC("license") = "GPL";
