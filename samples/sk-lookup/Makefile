LIBBPF_HEADERS := ../../libbpf/src/root/usr/include/
LIBBPF_HEADERS_DESTDIR := root
LIBBPF_LIB_DIR  := ../../libbpf/src/

LIBSGBPF_DIR := ../../sgbpf/
LIBSGBPF_HEADERS := ../../sgbpf/include/
LIBSGBPF_LIB_DIR := ../../sgbpf/lib/

LOADER_UDP := loader_udp
LOADER_TCP := loader_tcp
BPF_PROG := sk_lookup.bpf.o

all: $(LOADER_UDP) $(LOADER_TCP) $(BPF_PROG)

export DESTDIR := $(LIBBPF_HEADERS_DESTDIR)
install:
	make --directory=$(LIBBPF_LIB_DIR) all
	make --directory=$(LIBBPF_LIB_DIR) install_headers
	make --directory=$(LIBSGBPF_DIR) all


deinstall:
	make --directory=$(LIBBPF_LIB_DIR) clean
	rm -rf $(LIBBPF_LIB_DIR)/$(LIBBPF_HEADERS_DESTDIR)


$(LOADER_UDP): loader_udp.cpp
	g++ -std=c++17 -I$(LIBSGBPF_HEADERS) -I$(LIBBPF_HEADERS) -L$(LIBSGBPF_LIB_DIR) -L$(LIBBPF_LIB_DIR) -g -Wall $^ -o $@ -lbpf -lsgbpf

$(LOADER_TCP): loader_tcp.cpp
	g++ -std=c++17 -I$(LIBSGBPF_HEADERS) -I$(LIBBPF_HEADERS) -L$(LIBSGBPF_LIB_DIR) -L$(LIBBPF_LIB_DIR) -g -Wall $^ -o $@ -lbpf -lsgbpf


$(BPF_PROG): sk_lookup.bpf.c
	clang -target bpf -D __BPF_TRACING__ -g -Wall -Werror -O2 -c $^ -o $@


clean:
	rm -f *.o *.s
	rm -f $(LOADER)