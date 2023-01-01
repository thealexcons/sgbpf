LIBBPF_HEADERS := ../../libbpf/src/root/usr/include/
LIBBPF_HEADERS_DESTDIR := root
LIBBPF_LIB_DIR  := ../../libbpf/src/

LIBEBPFPP_DIR := ../../ebpfpp/
LIBEBPFPP_HEADERS := ../../ebpfpp/include/
LIBEBPFPP_LIB_DIR := ../../ebpfpp/lib/

LOADER := loader
BPF_PROG := tc_filter.bpf.o

all: $(LOADER) $(BPF_PROG)

export DESTDIR := $(LIBBPF_HEADERS_DESTDIR)
install:
	make --directory=$(LIBBPF_LIB_DIR) all
	make --directory=$(LIBBPF_LIB_DIR) install_headers
	make --directory=$(LIBEBPFPP_DIR) all


deinstall:
	make --directory=$(LIBBPF_LIB_DIR) clean
	rm -rf $(LIBBPF_LIB_DIR)/$(LIBBPF_HEADERS_DESTDIR)


$(LOADER): loader.cpp
	g++ -std=c++17 -I$(LIBEBPFPP_HEADERS) -I$(LIBBPF_HEADERS) -L$(LIBEBPFPP_LIB_DIR) -L$(LIBBPF_LIB_DIR) -g -Wall $^ -o $@ -lbpf -lebpfpp


$(BPF_PROG): tc_filter.bpf.c
	clang -target bpf -D __BPF_TRACING__ -I$(LIBBPF_HEADERS) -g -Wall -Werror -O2 -c $^ -o $@


clean:
	rm -f *.o *.s
	rm -f $(LOADER)