# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT ?= $(abspath .output)/
CLANG ?= clang
LLVM_STRIP ?= llvm-strip

LIBBPF_SRC := $(abspath ../libbpf/src)
BPFTOOL_SRC := $(abspath ../bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bpftool
LIBBLAZESYM_SRC := $(abspath ../blazesym/target/release/libblazesym.a)

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
VMLINUX := ../vmlinux/$(ARCH)/vmlinux.h

ifeq ($(ARCH),x86)
CARGO ?= $(shell which cargo)
ifeq ($(strip $(CARGO)),)
USE_BLAZESYM ?= 0
else
USE_BLAZESYM ?= 1
endif
endif

INCLUDES := -I$(OUTPUT) -I../libbpf/include/uapi -I$(dir $(VMLINUX))
CFLAGS := -g -Wall $(CLANG_CROSS_FLAGS)
ifeq ($(USE_BLAZESYM),1)
CFLAGS  += -DUSE_BLAZESYM=1
LDFLAGS += $(OUTPUT)/libblazesym.a -lrt -lpthread -ldl
endif
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)
COMMON_HEADERS := commons.h

BZ_APPS += memleak
BZ_APPS += opensnoop

APPS += bashreadline
APPS += bindsnoop
APPS += biolatency
APPS += biopattern
APPS += biosnoop
APPS += biostacks
APPS += biotop
APPS += bitesize
APPS += cachestat
APPS += capable
APPS += cpudist
APPS += cpufreq
APPS += drsnoop
APPS += execsnoop
APPS += exitsnoop
APPS += filelife
APPS += filetop
APPS += fsdist
APPS += fsslower
APPS += funclatency
APPS += gethostlatency
APPS += hardirqs
APPS += javagc
APPS += klockstat
APPS += ksnoop
APPS += llcstat
APPS += loads
APPS += mdflush
APPS += mountsnoop
APPS += numamove
APPS += numasched
APPS += offcputime
APPS += oomkill
APPS += readahead
APPS += runqlen
APPS += runqslower
APPS += runqueue-latency
APPS += sigsnoop
APPS += slabratetop
APPS += softirqs
APPS += solisten
APPS += statsnoop
APPS += syscount
APPS += swapin
APPS += tcpconnect
APPS += tcpconnlat
APPS += tcplife
APPS += tcppktlat
APPS += tcprtt
APPS += tcpstates
APPS += tcpsynbl
APPS += tcptop
APPS += tcptracer
APPS += vfsstat
APPS += wakeuptime
APPS += $(BZ_APPS)

COMMON_LIBS_OBJ := $(OUTPUT)/trace_helpers.o
COMMON_LIBS_OBJ += $(OUTPUT)/uprobe_helpers.o
COMMON_LIBS_OBJ += $(OUTPUT)/btf_helpers.o
COMMON_LIBS_OBJ += $(OUTPUT)/map_helpers.o
COMMON_LIBS_OBJ += $(OUTPUT)/compat.o
COMMON_LIBS_OBJ += $(OUTPUT)/syscall_helpers.o
COMMON_LIBS_OBJ += $(OUTPUT)/errno_helpers.o

ifeq ($(USE_BLAZESYM),1)
COMMON_LIBS_OBJ += $(OUTPUT)/libblazesym.a
COMMON_LIBS_OBJ += $(OUTPUT)/blazesym.h
endif

FSDIST_ALIASES	 := btrfsdist ext4dist nfsdist xfsdist
FSSLOWER_ALIASES := btrfsslower ext4slower nfsslower xfsslower
SIGSNOOP_ALIAS := killsnoop
APP_ALIASES := $(FSDIST_ALIASES) $(FSSLOWER_ALIASES) $(SIGSNOOP_ALIAS)

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
			"$(1)"						\
			"$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
			"$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
	    $(findstring command line,$(origin $(1)))),,\
	$(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: $(APPS) $(APP_ALIASES)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS) $(APP_ALIASES)

$(LIBBLAZESYM_SRC)::
	$(Q)cd ../blazesym && cargo build --release

$(OUTPUT)/libblazesym.a: $(LIBBLAZESYM_SRC) | $(OUTPUT)
	$(call msg,LIB,$@)
	$(Q)cp $(LIBBLAZESYM_SRC) $@

$(OUTPUT)/blazesym.h: $(LIBBLAZESYM_SRC) | $(OUTPUT)
	$(call msg,INC,$@)
	$(Q)cp ../blazesym/include/blazesym.h $@

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf.a
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		\
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		\
		    INCLUDEDIR= LIBDIR= UAPIDIR=			\
		    install

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC)

# Build BPF Code
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c $(wildcard %.h) $(LIBBPF_OBJ) $(COMMON_HEADERS) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

numasched numamove: ALL_LDFLAGS += -lnuma

# Build application binary
$(APPS): %: $(OUTPUT)/%.o $(COMMON_LIBS_OBJ) $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

ifeq ($(USE_BLAZESYM),1)
$(patsubst %,$(OUTPUT)/%.o,$(BZ_APPS)): $(OUTPUT)/blazesym.h
endif

$(FSSLOWER_ALIASES): fsslower
	$(call msg,SYMLINK,$@)
	$(Q)ln -f -s $^ $@

$(FSDIST_ALIASES): fsdist
	$(call msg,SYMLINK,$@)
	$(Q)ln -f -s $^ $@

$(SIGSNOOP_ALIAS): sigsnoop
	$(call msg,SYMLINK,$@)
	$(Q)ln -f -s $^ $@

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
