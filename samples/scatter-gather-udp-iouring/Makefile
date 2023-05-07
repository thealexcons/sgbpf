LIBBPF_HEADERS := ../../libbpf/src/root/usr/include/
LIBBPF_HEADERS_DESTDIR := root
LIBBPF_LIB_DIR  := ../../libbpf/src/

LIBEBPFPP_DIR := ../../ebpfpp/
LIBEBPFPP_HEADERS := ../../ebpfpp/include/
LIBEBPFPP_LIB_DIR := ../../ebpfpp/lib/

LOADER := loader
SG_LOADER := sg_loader
BPF_PROG := scatter_gather.bpf.o
BPF_AGGREGATION_PROG := aggregation.bpf.o

all: $(LOADER) $(SG_LOADER) $(BPF_PROG) $(BPF_AGGREGATION_PROG)

export DESTDIR := $(LIBBPF_HEADERS_DESTDIR)
install:
	make --directory=$(LIBBPF_LIB_DIR) all
	make --directory=$(LIBBPF_LIB_DIR) install_headers
	make --directory=$(LIBEBPFPP_DIR) all


deinstall:
	make --directory=$(LIBBPF_LIB_DIR) clean
	rm -rf $(LIBBPF_LIB_DIR)/$(LIBBPF_HEADERS_DESTDIR)


$(LOADER): loader.cpp
	g++ -std=c++17 -fsanitize=address -I$(LIBEBPFPP_HEADERS) -I$(LIBBPF_HEADERS) -L$(LIBEBPFPP_LIB_DIR) -L$(LIBBPF_LIB_DIR) -g -Wall $^ -o $@ -lbpf -lebpfpp -luring -lpthread


$(SG_LOADER): sg_loader.cpp
	g++ -std=c++17  -fsanitize=address -I$(LIBEBPFPP_HEADERS) -I$(LIBBPF_HEADERS) -L$(LIBEBPFPP_LIB_DIR) -L$(LIBBPF_LIB_DIR) -g -Wall $^ -o $@ -lbpf -lebpfpp -luring -lpthread


$(BPF_PROG): scatter_gather.bpf.c
	clang-12 -target bpf -D __BPF_TRACING__ -D BPF_DEBUG_PRINT -I$(LIBBPF_HEADERS) -g -Wall -O2 -c $^ -o $@
# clang-12 -target bpf -emit-llvm -S -D __BPF_TRACING__ -I$(LIBBPF_HEADERS) -g -Wall -O2 -c $^ -o $@.ll
# llc-12 -march=bpf -filetype=obj -o $@ $@.ll


$(BPF_AGGREGATION_PROG): aggregation.bpf.c
	clang-12 -target bpf -D __BPF_TRACING__ -D BPF_DEBUG_PRINT -I$(LIBBPF_HEADERS) -g -Wall -O2 -c $^ -o $@

clean:
	rm -f *.o *.s
	rm -f $(LOADER) $(SG_LOADER)

reset_maps:
	sudo rm /sys/fs/bpf/map_workers_resp_count
	sudo rm /sys/fs/bpf/map_aggregated_response
	sudo rm /sys/fs/bpf/map_req_completion_policy