CLANG ?= clang
BPFTOOL ?= bpftool
BTF ?= /sys/kernel/btf/vmlinux
CFLAGS ?= -O2 -g

.PHONY: all clean
all: theia_flow_events.bpf.o

vmlinux.h:
	$(BPFTOOL) btf dump file $(BTF) format c > $@.tmp
	mv $@.tmp $@

theia_flow_events.bpf.o: theia_flow_events.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) -target bpf -c $< -o $@

clean:
	rm -f vmlinux.h vmlinux.h.tmp theia_flow_events.bpf.o
