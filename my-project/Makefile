# Setup path to your libbpf installation
LIBBPF_HEADERS := ../libbpf/src/root/usr/include/
LIBBPF_HEADERS_DESTDIR := root
LIBBPF_LIB_DIR  := ../libbpf/src/

# Setup path to your sgbpf directory
LIBSGBPF_DIR := ../sgbpf/
LIBSGBPF_HEADERS := ../sgbpf/include/
LIBSGBPF_LIB_DIR := ../sgbpf/lib/

SG_PROGRAM := sg_program

all: $(SG_PROGRAM)

export DESTDIR := $(LIBBPF_HEADERS_DESTDIR)
install:
	make --directory=$(LIBBPF_LIB_DIR) all
	make --directory=$(LIBBPF_LIB_DIR) install_headers
	make --directory=$(LIBSGBPF_DIR) all


deinstall:
	make --directory=$(LIBBPF_LIB_DIR) clean
	rm -rf $(LIBBPF_LIB_DIR)/$(LIBBPF_HEADERS_DESTDIR)


$(SG_PROGRAM): main.cpp
	g++ -std=c++17  -fsanitize=address -I$(LIBSGBPF_HEADERS) -I$(LIBBPF_HEADERS) -L$(LIBSGBPF_LIB_DIR) -L$(LIBBPF_LIB_DIR) -g -Wall $^ -o $@ -lbpf -lsgbpf -luring -lpthread

clean:
	rm -f *.o *.s
	rm -f $(SG_PROGRAM)

reset_maps:
	sudo rm /sys/fs/bpf/map_req_state
	sudo rm /sys/fs/bpf/map_aggregated_response
