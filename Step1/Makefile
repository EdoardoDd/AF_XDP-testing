CC := gcc
CLANG := clang
CFLAGS := -g -Wall -O2
KERNEL_CFLAGS := -O2 -g -Wall -Werror -target bpf -D__BPF_TRACING__ -I/usr/include/$(shell uname -m)-linux-gnu
LDFLAGS := -lxdp -lbpf -lpthread -lm

USER_TARGETS := xdpsock
KERNEL_TARGETS := xdp_prog_kern.o

all: $(USER_TARGETS) $(KERNEL_TARGETS)

clean:
	rm -f $(USER_TARGETS) $(KERNEL_TARGETS)

$(USER_TARGETS): %: %.c
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)

xdp_prog_kern.o: xdp_prog_kern.c
	$(CLANG) $(KERNEL_CFLAGS) -c $< -o $@

.PHONY: all clean