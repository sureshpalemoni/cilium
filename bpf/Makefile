# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../Makefile.defs

.PHONY: all subdirs check preprocess assembly install clean

SUBDIRS = sockops

BPF_SIMPLE = bpf_network.o bpf_alignchecker.o bpf_hostdev_ingress.o
BPF = bpf_lxc.o bpf_overlay.o bpf_sock.o bpf_netdev.o bpf_xdp.o $(BPF_SIMPLE)

TARGET=cilium-map-migrate

include ./Makefile.bpf

ifeq ("$(PKG_BUILD)","")
all: $(BPF) $(TARGET) subdirs

build_all:
	@$(ECHO_CHECK)/*.c BUILD_PERMUTATIONS=1
	$(QUIET) $(MAKE) $(SUBMAKEOPTS) all BUILD_PERMUTATIONS=1

BUILD_PERMUTATIONS ?= ""

$(BPF_SIMPLE): %.o: %.ll
	@$(ECHO_CC)
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

# Hack to get make to replace : with a space
null :=
space := ${null} ${null}

# The following option combinations are compile tested
LB_OPTIONS = \
	-DSKIP_DEBUG \
	-DENABLE_IPV4:-DLB_L3 \
	-DENABLE_IPV4:-DLB_L4 \
	-DENABLE_IPV4:-DLB_L4:-DENABLE_IPV4_FRAGMENTS \
	-DENABLE_IPV4:-DLB_L3:-DLB_L4 \
	-DENABLE_IPV4:-DENABLE_IPSEC \
	-DENABLE_IPV6:-DLB_L3 \
	-DENABLE_IPV6:-DLB_L4 \
	-DENABLE_IPV6:-DLB_L3:-DLB_L4 \
	-DENABLE_IPV6:-DENABLE_IPSEC \
	-DENABLE_IPV4:-DENABLE_IPV6 \
	-DENABLE_IPV4:-DENABLE_IPV6:-DENABLE_IPSEC \
	-DENABLE_IPV4:-DENABLE_IPV6:-DLB_L3 \
	-DENABLE_IPV4:-DENABLE_IPV6:-DLB_L4 \
	-DENABLE_IPV4:-DENABLE_IPV6:-DLB_L3:-DLB_L4 \
	-DENABLE_IPV4:-DENABLE_IPV6:-DLB_L3:-DLB_L4:-DENABLE_HOST_SERVICES_UDP \
	-DENABLE_IPV4:-DENABLE_IPV6:-DLB_L3:-DLB_L4:-DENABLE_HOST_SERVICES_TCP \
	-DENABLE_IPV4:-DENABLE_IPV6:-DLB_L3:-DLB_L4:-DENABLE_IPSEC:-DENABLE_ENCAP_HOST_REMAP \
	-DENABLE_IPV4:-DENABLE_IPV6:-DLB_L3:-DLB_L4:-DENABLE_HOST_SERVICES_UDP:-DENABLE_NODEPORT \
	-DENABLE_IPV4:-DENABLE_IPV6:-DLB_L3:-DLB_L4:-DENABLE_HOST_SERVICES_TCP:-DENABLE_NODEPORT \
	-DENABLE_IPV4:-DENABLE_IPV6:-DLB_L3:-DLB_L4:-DENABLE_HOST_SERVICES_UDP:-DENABLE_HOST_SERVICES_TCP \
	-DENABLE_IPV4:-DENABLE_IPV6:-DLB_L3:-DLB_L4:-DENABLE_HOST_SERVICES_UDP:-DENABLE_HOST_SERVICES_TCP:-DENABLE_NODEPORT \
	-DENABLE_IPV4:-DENABLE_IPV6:-DLB_L3:-DLB_L4:-DENABLE_HOST_SERVICES_UDP:-DENABLE_HOST_SERVICES_TCP:-DENABLE_NODEPORT:-DENABLE_EXTERNAL_IP \
	-DENABLE_IPV4:-DENABLE_IPV6:-DENABLE_IPSEC:-DLB_L3:-DLB_L4:-DENABLE_HOST_SERVICES_UDP:-DENABLE_HOST_SERVICES_TCP:-DENABLE_NODEPORT:-DENABLE_EXTERNAL_IP \
	-DENABLE_IPV4:-DENABLE_IPV6:-DENABLE_IPSEC:-DLB_L3:-DLB_L4:-DENABLE_HOST_SERVICES_UDP:-DENABLE_HOST_SERVICES_TCP:-DENABLE_NODEPORT:-DENABLE_EXTERNAL_IP:-DENABLE_NODEPORT_ACCELERATION \
	-DENABLE_IPV4:-DENABLE_IPV6:-DENABLE_IPSEC:-DLB_L3:-DLB_L4:-DENABLE_HOST_SERVICES_UDP:-DENABLE_HOST_SERVICES_TCP:-DENABLE_NODEPORT:-DENABLE_EXTERNAL_IP:-DENABLE_NODEPORT_ACCELERATION:-DENABLE_SESSION_AFFINITY \

# These options are intended to max out the BPF program complexity. it is load
# tested as well.
MAX_LB_OPTIONS = -DENABLE_IPV4 -DENABLE_IPV6 -DLB_L3 -DLB_L4 \
	-DENABLE_HOST_SERVICES_TCP -DENABLE_HOST_SERVICES_UDP \
	-DENABLE_IPSEC

bpf_sock.ll: bpf_sock.c $(LIB)
	$(QUIET) set -e; \
	if [ $(BUILD_PERMUTATIONS) != "" ]; then \
		$(foreach OPTS,$(LB_OPTIONS), \
			$(ECHO_CC) " [$(subst :,$(space),$(OPTS))]"; \
			${CLANG} $(subst :,$(space),$(OPTS)) ${CLANG_FLAGS} -c $< -o $@; \
			${LLC} ${LLC_FLAGS} -o /dev/null $@; ) \
	fi
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${MAX_LB_OPTIONS} ${CLANG_FLAGS} -c $< -o $@

bpf_sock.o: bpf_sock.ll
	@$(ECHO_CC)
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

# The following option combinations are compile tested
OVERLAY_OPTIONS = \
	 -DENABLE_IPV4 \
	 -DENABLE_IPV6

# These options are intended to max out the BPF program complexity. it is load
# tested as well.
MAX_OVERLAY_OPTIONS = -DENABLE_IPV4 -DENABLE_IPV6 -DENABLE_IPSEC

bpf_overlay.ll: bpf_overlay.c $(LIB)
	$(QUIET) set -e; \
	if [ $(BUILD_PERMUTATIONS) != "" ]; then \
		$(foreach OPTS,$(OVERLAY_OPTIONS), \
			$(ECHO_CC) " [$(subst :,$(space),$(OPTS))]"; \
			${CLANG} $(subst :,$(space),$(OPTS)) ${CLANG_FLAGS} -c $< -o $@; \
			${LLC} ${LLC_FLAGS} -o /dev/null $@; ) \
	fi
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${MAX_OVERLAY_OPTIONS} ${CLANG_FLAGS} -c $< -o $@

bpf_overlay.o: bpf_overlay.ll
	@$(ECHO_CC)
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

NETDEV_OPTIONS = $(LB_OPTIONS) \
	-DENABLE_IPV4:-DENABLE_IPV6:-DLB_L3:-DLB_L4:-DENABLE_HOST_SERVICES_UDP:-DENABLE_HOST_SERVICES_TCP:-DENABLE_EXTERNAL_IP:-DENABLE_DSR:-DFROM_HOST \
	-DENABLE_IPV4:-DENABLE_IPV6:-DLB_L3:-DLB_L4:-DENABLE_IPSEC:-DENABLE_HOST_SERVICES_UDP:-DENABLE_HOST_SERVICES_TCP:-DENABLE_EXTERNAL_IP:-DENABLE_DSR:-DFROM_HOST \
	-DENABLE_IPV4:-DENABLE_IPV6:-DLB_L3:-DLB_L4:-DENABLE_HOST_SERVICES_UDP:-DENABLE_HOST_SERVICES_TCP:-DENABLE_NODEPORT:-DENABLE_EXTERNAL_IP:-DENABLE_HOSTPORT \
	-DENABLE_IPV4:-DENABLE_IPV6:-DLB_L3:-DLB_L4:-DENABLE_HOST_SERVICES_UDP:-DENABLE_HOST_SERVICES_TCP:-DENABLE_NODEPORT:-DENABLE_EXTERNAL_IP:-DENABLE_MASQUERADE \
	-DENABLE_IPV4:-DENABLE_IPV6:-DLB_L3:-DLB_L4:-DENABLE_IPSEC:-DENABLE_HOST_SERVICES_UDP:-DENABLE_HOST_SERVICES_TCP:-DENABLE_NODEPORT:-DENABLE_EXTERNAL_IP:-DENABLE_MASQUERADE \
	-DENABLE_IPV4:-DENABLE_IPV6:-DLB_L3:-DLB_L4:-DENABLE_HOST_SERVICES_UDP:-DENABLE_HOST_SERVICES_TCP:-DENABLE_NODEPORT:-DENABLE_EXTERNAL_IP:-DENABLE_DSR \
	-DENABLE_IPV4:-DENABLE_IPV6:-DLB_L3:-DLB_L4:-DENABLE_HOST_SERVICES_UDP:-DENABLE_HOST_SERVICES_TCP:-DENABLE_NODEPORT:-DENABLE_EXTERNAL_IP:-DENABLE_DSR:-DENABLE_DSR_HYBRID \
	-DENABLE_IPV4:-DENABLE_IPV6:-DLB_L3:-DLB_L4:-DENABLE_HOST_SERVICES_UDP:-DENABLE_HOST_SERVICES_TCP:-DENABLE_NODEPORT:-DENABLE_NODEPORT_ACCELERATION:-DENABLE_EXTERNAL_IP:-DENABLE_DSR:-DENABLE_DSR_HYBRID:-DENABLE_PREFILTER \
	-DENABLE_IPV4:-DENABLE_IPV6:-DLB_L3:-DLB_L4:-DENABLE_HOST_SERVICES_UDP:-DENABLE_HOST_SERVICES_TCP:-DENABLE_NODEPORT:-DENABLE_NODEPORT_ACCELERATION:-DENABLE_EXTERNAL_IP:-DENABLE_DSR:-DENABLE_DSR_HYBRID:-DENABLE_PREFILTER:-DENABLE_SESSION_AFFINITY \

MAX_NETDEV_OPTIONS = $(MAX_LB_OPTIONS)

bpf_netdev.ll: bpf_netdev.c $(LIB)
	$(QUIET) set -e; \
	if [ $(BUILD_PERMUTATIONS) != "" ]; then \
		$(foreach OPTS,$(NETDEV_OPTIONS), \
			$(ECHO_CC) " [$(subst :,$(space),$(OPTS))]"; \
			${CLANG} $(subst :,$(space),$(OPTS)) ${CLANG_FLAGS} -c $< -o $@; \
			${LLC} ${LLC_FLAGS} -o /dev/null $@; ) \
	fi
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${MAX_NETDEV_OPTIONS} ${CLANG_FLAGS} -c $< -o $@

bpf_netdev.o: bpf_netdev.ll
	@$(ECHO_CC)
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

bpf_xdp.ll: bpf_xdp.c $(LIB)
	$(QUIET) set -e; \
	if [ $(BUILD_PERMUTATIONS) != "" ]; then \
		$(foreach OPTS,$(NETDEV_OPTIONS), \
			$(ECHO_CC) " [$(subst :,$(space),$(OPTS))]"; \
			${CLANG} $(subst :,$(space),$(OPTS)) ${CLANG_FLAGS} -c $< -o $@; \
			${LLC} ${LLC_FLAGS} -o /dev/null $@; ) \
	fi
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${MAX_NETDEV_OPTIONS} ${CLANG_FLAGS} -c $< -o $@

bpf_xdp.o: bpf_xdp.ll
	@$(ECHO_CC)
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

# The following option combinations are compile tested
LXC_OPTIONS = \
	 -DALLOW_ICMP_FRAG_NEEDED \
	 -DSKIP_DEBUG \
	 -DHAVE_LPM_TRIE_MAP_TYPE \
	 -DHAVE_LRU_HASH_MAP_TYPE \
	 -DENABLE_IPV4 \
	 -DENABLE_IPV4:-DENABLE_IPSEC \
	 -DENABLE_IPV4:-DHAVE_LPM_TRIE_MAP_TYPE \
	 -DENABLE_IPV4:-DHAVE_LPM_TRIE_MAP_TYPE:-DHAVE_LRU_HASH_MAP_TYPE \
	 -DENABLE_IPV4:-DENABLE_IPV4_FRAGMENTS \
	 -DENABLE_IPV6 \
	 -DENABLE_IPV6:-DENABLE_IPSEC \
	 -DENABLE_IPV6:-DHAVE_LPM_TRIE_MAP_TYPE \
	 -DENABLE_IPV6:-DHAVE_LPM_TRIE_MAP_TYPE:-DHAVE_LRU_HASH_MAP_TYPE \
	 -DENABLE_IPV6:-DENABLE_IPV4 \
	 -DENABLE_IPV6:-DENABLE_IPV4:-DENABLE_ROUTING \
	 -DENABLE_IPV6:-DENABLE_IPV4:-DENABLE_IPSEC:-DENABLE_ENCAP_HOST_REMAP \
	 -DENABLE_IPV4:-DENABLE_IPV6:-DHAVE_LPM_TRIE_MAP_TYPE:-DHAVE_LRU_HASH_MAP_TYPE \
	 -DENABLE_HOST_REDIRECT:-DENABLE_IPV4:-DENABLE_IPV6 \
	 -DENABLE_HOST_REDIRECT:-DENABLE_IPV4:-DENABLE_IPV6:-DENABLE_NAT46 \
	 -DENABLE_NODEPORT:-DENABLE_IPV4:-DENABLE_IPV6 \
	 -DENABLE_NODEPORT:-DENABLE_DSR:-DENABLE_IPV4:-DENABLE_IPV6

# These options are intended to max out the BPF program complexity. it is load
# tested as well.
MAX_LXC_OPTIONS = -DENABLE_IPV4 -DENABLE_IPV6 -DENABLE_HOST_REDIRECT -DENABLE_NAT46 \
	-DENABLE_ROUTING -DENABLE_IPSEC

bpf_lxc.ll: bpf_lxc.c $(LIB)
	$(QUIET) set -e; \
	if [ $(BUILD_PERMUTATIONS) != "" ]; then \
		$(foreach OPTS,$(LXC_OPTIONS), \
			$(ECHO_CC) " [$(subst :,$(space),$(OPTS))]"; \
			${CLANG} $(subst :,$(space),$(OPTS)) ${CLANG_FLAGS} -c $< -o $@; \
			${LLC} ${LLC_FLAGS} -o /dev/null $@; ) \
	fi
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${MAX_LXC_OPTIONS} ${CLANG_FLAGS} -c $< -o $@

bpf_lxc.o: bpf_lxc.ll
	@$(ECHO_CC)
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

subdirs: $(SUBDIRS)
	$(QUIET) $(foreach TARGET,$(SUBDIRS), \
		$(MAKE) $(SUBMAKEOPTS) -C $(TARGET))

else
all: $(TARGET)
endif

$(TARGET): $(TARGET).c
	@$(ECHO_CC)
	@# Due to gcc bug, -lelf needs to be at the end.
	$(QUIET) ${HOSTCC} -Wall -O2 -Wno-format-truncation -I include/ $@.c -lelf -o $@

install:
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

clean:
	@$(ECHO_CLEAN)
	$(QUIET) $(foreach TARGET,$(SUBDIRS), \
		$(MAKE) $(SUBMAKEOPTS) -C $(TARGET) clean)
	$(QUIET)rm -fr *.o *.ll *.i *.s
	$(QUIET)rm -f $(TARGET)
