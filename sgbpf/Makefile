
INC_DIR := ./include/sgbpf
LIBBPF_INC := ./dep/libbpf/src/root/usr/include/
LIBBPF_LIB_DIR := ./dep/libbpf/src/

########### USER LIB ###########
CC_ULIB := g++
CFLAGS_ULIB= -std=c++17 -O2 -g -Wall -I$(INC_DIR) -I$(LIBBPF_INC) -L$(LIBBPF_LIB_DIR) -luring -D DEBUG_PRINT

OUT_FILE_ULIB := libsgbpf.a
OBJ_DIR_ULIB := ./obj
OUT_DIR_ULIB := ./lib

SOURCES_ULIB := $(wildcard src/*.cpp)

# this assumes that libbpf and liburing has been built and installed

$(OUT_FILE_ULIB): $(SOURCES_ULIB)
	mkdir -p $(OUT_DIR_ULIB) $(OBJ_DIR_ULIB)
	for file in $(SOURCES_ULIB); do $(CC_ULIB) $(CFLAGS_ULIB) -c $$file -O; done
	mv *.o $(OBJ_DIR_ULIB)
	ar rcs $(OUT_DIR_ULIB)/$@ $(wildcard $(OBJ_DIR_ULIB)/*.o)	


############ BPF ##############
CC_BPF := clang-12
CFLAGS_BPF= -target bpf -emit-llvm -S -g -O2 -I$(INC_DIR) -D __BPF_TRACING__
LLC_BPF := llc-12
LLCFLAGS_BPF := -march=bpf -filetype=obj

BPF_PROG := scatter_gather.bpf.o
AGGREGATION_BPF_PROG := aggregation.bpf.o

BPF_OBJ_DIR := ./bpfobj

# Helper functions to check for environment variables
check_defined_err = \
    $(strip $(foreach 1,$1, \
        $(call __check_defined_err,$1,$(strip $(value 2)))))
__check_defined_err = \
    $(if $(value $1),, \
      $(error Undefined $1$(if $2, ($2))))

check_defined_set_default = \
    $(strip $(foreach 1,$1, \
        $(call __check_defined_set_default,$1,$(strip $(value 2)))))
__check_defined_set_default = \
    $(if $(value $1),, \
      $(info Undefined $1$(if $2, ($2)), setting to default $(BPF_OBJ_DIR) path) \
	  $(eval export OUTPUT_BPF_OBJ_DIR := $(BPF_OBJ_DIR)))

.SILENT: bpf bpf_func

.ONESHELL:
bpf: src/bpf/scatter_gather.bpf.c
	$(call check_defined_err, CUSTOM_AGGREGATION_BPF_PROG)
	$(call check_defined_set_default, OUTPUT_BPF_OBJ_DIR)

	mkdir -p $(BPF_OBJ_DIR)
	mkdir -p ${OUTPUT_BPF_OBJ_DIR}

	# Build main BPF object file
	echo "[1/2] Building main eBPF object file..."
	$(CC_BPF) $(CFLAGS_BPF) -c $^ -o $(BPF_PROG).ll || exit
	$(LLC_BPF) $(LLCFLAGS_BPF) -o $(BPF_PROG) $(BPF_PROG).ll
	rm -f $(BPF_PROG).ll
	mv $(BPF_PROG) ${OUTPUT_BPF_OBJ_DIR}
	echo "[1/2] Built eBPF object file and placed under ${OUTPUT_BPF_OBJ_DIR}\n"

	# Build custom aggregation BPF object file
	echo "[2/2] Building custom aggregation eBPF program..."
	$(CC_BPF) $(CFLAGS_BPF) -c ${CUSTOM_AGGREGATION_BPF_PROG} -o $(AGGREGATION_BPF_PROG).ll || exit
	$(LLC_BPF) $(LLCFLAGS_BPF) -o $(AGGREGATION_BPF_PROG) $(AGGREGATION_BPF_PROG).ll
	rm -f $(AGGREGATION_BPF_PROG).ll
	mv $(AGGREGATION_BPF_PROG) ${OUTPUT_BPF_OBJ_DIR}
	echo "[2/2] Built custom aggregation eBPF program and placed under ${OUTPUT_BPF_OBJ_DIR}\n"
	echo "BPF OBJECT FILES BUILT"

.PHONY: all
all: $(OUTPUTFILE)

.PHONY: clean 
clean:
	rm -rf $(OBJ_DIR_ULIB)
	rm -rf $(BPF_OBJ_DIR)
	rm -rf $(OUT_DIR_ULIB)