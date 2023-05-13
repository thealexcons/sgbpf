########### SETUP ############
LIBSGBPF_DIR := ../sgbpf/
##############################

LIBSGBPF_HEADERS := $(LIBSGBPF_DIR)/include/
LIBSGBPF_LIB_DIR := $(LIBSGBPF_DIR)/lib/

# Path to libbpf within sgbpf
LIBBPF_HEADERS := $(LIBSGBPF_DIR)/dep/libbpf/src/root/usr/include/
LIBBPF_LIB_DIR  := $(LIBSGBPF_DIR)/dep/libbpf/src/
LIBBPF_HEADERS_DESTDIR := root

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
	make --directory=$(LIBSGBPF_DIR) clean


CC := g++
CFLAGS := -std=c++17 -O2 -g -Wall
# Note: must be in this order, otherwise it fails (and must be at the end of command)
LDFLAGS := -L$(LIBSGBPF_LIB_DIR) -L$(LIBBPF_LIB_DIR) -lsgbpf -lbpf -luring
INC := -I$(LIBSGBPF_HEADERS) -I$(LIBBPF_HEADERS)
$(SG_PROGRAM): main.cpp
	$(CC) $(CFLAGS) $(INC) $^ -o $@ $(LDFLAGS)

clean:
	rm -f *.o *.s
	rm -f $(SG_PROGRAM)

reset_maps:
	sudo rm /sys/fs/bpf/map_req_state
	sudo rm /sys/fs/bpf/map_aggregated_response
