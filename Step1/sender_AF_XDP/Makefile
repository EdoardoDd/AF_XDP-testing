CC := gcc
CLANG := clang
LLC := llc
COMMON_DIR := ../../common
CFLAGS := -g -Wall -O2 -I$(COMMON_DIR)
LDFLAGS := -lbpf -lelf -lxdp -lz -pthread -lm

# File sorgenti comuni
COMMON_SOURCES := $(COMMON_DIR)/common_params.c \
                  $(COMMON_DIR)/common_user_bpf_xdp.c \
                  $(COMMON_DIR)/common_stats.c \
                  $(COMMON_DIR)/common_packet.c

XDP_TARGETS := sender_kern.o
USER_TARGETS := sender_user

all: $(USER_TARGETS) $(XDP_TARGETS)

clean:
	rm -f $(USER_TARGETS) $(XDP_TARGETS)
	rm -f *.ll

$(USER_TARGETS): %: %.c $(COMMON_SOURCES)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

$(XDP_TARGETS): %.o: %.c
	$(CLANG) -S -target bpf -D__BPF_TRACING__ $(CFLAGS) \
		-Wall -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types -Werror \
		-emit-llvm -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

.PHONY: clean