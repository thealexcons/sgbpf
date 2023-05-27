########### SETUP ############
LIBSGBPF_DIR := ../../sgbpf/
##############################

LIBSGBPF_HEADERS := $(LIBSGBPF_DIR)/include/
LIBSGBPF_LIB_DIR := $(LIBSGBPF_DIR)/lib/

# Path to libbpf within sgbpf
LIBBPF_HEADERS := $(LIBSGBPF_DIR)/dep/libbpf/src/root/usr/include/
LIBBPF_LIB_DIR  := $(LIBSGBPF_DIR)/dep/libbpf/src/
LIBBPF_HEADERS_DESTDIR := root

LOADER := loader
BPF_PROG := xdp_ringbuf.bpf.o

all: $(LOADER) $(BPF_PROG)

export DESTDIR := $(LIBBPF_HEADERS_DESTDIR)
install:
	make --directory=$(LIBBPF_LIB_DIR) all
	make --directory=$(LIBBPF_LIB_DIR) install_headers
	make --directory=$(LIBSGBPF_DIR) all


deinstall:
	make --directory=$(LIBBPF_LIB_DIR) clean
	rm -rf $(LIBBPF_LIB_DIR)/$(LIBBPF_HEADERS_DESTDIR)
	make --directory=$(LIBSGBPF_DIR) clean


$(LOADER): loader.cpp
	g++ -std=c++17 -I$(LIBSGBPF_HEADERS) -I$(LIBBPF_HEADERS) -L$(LIBSGBPF_LIB_DIR) -L$(LIBBPF_LIB_DIR) -g -Wall $^ -o $@ -lbpf -lsgbpf -lelf -luring


$(BPF_PROG): xdp_ringbuf.bpf.c
	clang -target bpf -D __BPF_TRACING__ -I$(LIBBPF_HEADERS) -g -Wall -Werror -O2 -c $^ -o $@


clean:
	rm -f *.o *.s
	rm -f $(LOADER)