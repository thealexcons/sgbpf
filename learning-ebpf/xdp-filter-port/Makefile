
LIBBPF_HEADERS := ../../libbpf/src/root/usr/include/
LIBBPF_SOURCE  := ../../libbpf/src/ 

LOADER := loader
BPF_PROG := xdp_filter_port.bpf.o

all: $(LOADER) $(BPF_PROG) 


$(LOADER): loader.cpp
	g++ -std=c++17  -I$(LIBBPF_HEADERS) -L$(LIBBPF_SOURCE) -g -Wall $^ -o $@ -lbpf -lelf


$(BPF_PROG): xdp_filter_port.bpf.c
	clang-10 -target bpf -D __BPF_TRACING__ -I$(LIBBPF_HEADERS) -g -Wall -Werror -O2 -c $^ -o $@


clean:
	rm -f *.o *.s
	rm -f $(LOADER)