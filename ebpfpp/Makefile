CLEANEXTS   = o a

CC := g++
OUTPUTFILE := libebpfpp.a

INC_DIR := ./include/ebpfpp
LIBBPF_INC := ../libbpf/src/root/usr/include/
LIBBPF_SRC := ../libbpf/src/
CFLAGS= -std=c++17 -O2 -g -Wall -I$(INC_DIR) -I$(LIBBPF_INC) -L$(LIBBPF_SRC)


SRC_DIR := ./src
OBJ_DIR := ./obj
OUT_DIR := ./lib

SOURCES := $(wildcard $(SRC_DIR)/*.cpp)


.PHONY: all
all: $(OUTPUTFILE)

$(OUTPUTFILE): $(SOURCES)
	mkdir -p $(OUT_DIR) $(OBJ_DIR)
	for file in $(SOURCES); do $(CC) $(CFLAGS) -c $$file -O -lbpf; done
	mv *.o $(OBJ_DIR)
	ar rcs $(OUT_DIR)/$@ $(wildcard $(OBJ_DIR)/*.o)


.PHONY: clean 
clean:
	rm -rf $(OBJ_DIR)
	rm -rf $(OUT_DIR)
