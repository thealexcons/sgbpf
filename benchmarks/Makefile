
CC = g++
CFLAGS = -std=c++17 -g -O2 -Wall

all: sgbpf naive naive_one_sk event async async_busy_wait

###################### BASELINE BENCHMARKS ####################

naive: naive_sg.cpp
	$(CC) $(CFLAGS) $^ -o $@

naive_one_sk: naive_one_sk_sg.cpp
	$(CC) $(CFLAGS) $^ -o $@

event: event_sg.cpp
	$(CC) $(CFLAGS) $^ -o $@

async: async_sg.cpp
	$(CC) $(CFLAGS) $^ -o $@ -luring

async_busy_wait: async_sg.cpp
	$(CC) $(CFLAGS) $^ -o $@ -luring -D BUSY_WAITING_MODE


###################### SGBPF BENCHMARK ####################

########## SETUP ############
LIBSGBPF_DIR := ../sgbpf/
##############################

LIBSGBPF_HEADERS := $(LIBSGBPF_DIR)/include/
LIBSGBPF_LIB_DIR := $(LIBSGBPF_DIR)/lib/

# Path to libbpf within sgbpf
LIBBPF_HEADERS := $(LIBSGBPF_DIR)/dep/libbpf/src/root/usr/include/
LIBBPF_LIB_DIR  := $(LIBSGBPF_DIR)/dep/libbpf/src/
LIBBPF_HEADERS_DESTDIR := root


export DESTDIR := $(LIBBPF_HEADERS_DESTDIR)
install:
	make --directory=$(LIBBPF_LIB_DIR) all
	make --directory=$(LIBBPF_LIB_DIR) install_headers
	make --directory=$(LIBSGBPF_DIR) all

deinstall:
	make --directory=$(LIBBPF_LIB_DIR) clean
	rm -rf $(LIBBPF_LIB_DIR)/$(LIBBPF_HEADERS_DESTDIR)
	make --directory=$(LIBSGBPF_DIR) clean

# Note: must be in this order, otherwise it fails (and must be at the end of command)
LDFLAGS := -L$(LIBSGBPF_LIB_DIR) -L$(LIBBPF_LIB_DIR) -lsgbpf -lbpf -lelf -luring
INC := -I$(LIBSGBPF_HEADERS) -I$(LIBBPF_HEADERS)
sgbpf: sgbpf.cpp
	$(CC) $(CFLAGS) $(INC) $^ -o $@ $(LDFLAGS) -D IO_URING_CTRL_SK

reset_maps:
	sudo rm /sys/fs/bpf/map_req_state
	sudo rm /sys/fs/bpf/map_aggregated_response

clean:
	rm -f naive naive_one_sk event async async_busy_wait sgbpf
	rm -f *.o *.s
	rm -f $(SG_PROGRAM)