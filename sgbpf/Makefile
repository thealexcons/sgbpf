
########### USER LIB ###########
CC := g++
OUTPUTFILE := libsgbpf.a

# TODO can we somehow decouple LIBBPF from SGBPF directory structure??
# MAYBE force the user to set an environment variable to their libbpf path
# Since libbpf is required HERE and in the user program Makefile

INC_DIR := ./include/sgbpf
LIBBPF_INC := ../libbpf/src/root/usr/include/
LIBBPF_SRC := ../libbpf/src/
CFLAGS= -std=c++17 -O2 -g -Wall -I$(INC_DIR) -I$(LIBBPF_INC) -L$(LIBBPF_SRC) -D DEBUG_PRINT

SRC_DIR := ./src
OBJ_DIR := ./obj
OUT_DIR := ./lib

SOURCES := $(wildcard $(SRC_DIR)/*.cpp)

$(OUTPUTFILE): $(SOURCES)
	mkdir -p $(OUT_DIR) $(OBJ_DIR)
	for file in $(SOURCES); do $(CC) $(CFLAGS) -c $$file -O -lbpf -luring; done
	mv *.o $(OBJ_DIR)
	ar rcs $(OUT_DIR)/$@ $(wildcard $(OBJ_DIR)/*.o)	


############ BPF ##############

BPF_PROG := scatter_gather.bpf.o
AGGREGATION_BPF_PROG := aggregation.bpf.o

BPF_OBJ_DIR := ./bpfobj

# The aggregation object should be compiled on the demand by the user
# They can do something like:
# make --directory=<path/to/sgbpf> aggregation

#note if using the custom function instead of program, we need add it to the -I of the compilation
# and enable the -D CUSTOM_AGGREGATION flag
# hence the bpf target should be called on demand, and not on installation

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
bpf: $(SRC_DIR)/bpf/scatter_gather.bpf.c
	$(call check_defined_err, CUSTOM_AGGREGATION_BPF_PROG)
	$(call check_defined_set_default, OUTPUT_BPF_OBJ_DIR)

	mkdir -p $(BPF_OBJ_DIR)
	mkdir -p ${OUTPUT_BPF_OBJ_DIR}

	# Build main BPF object file
	echo "[1/2] Building main eBPF object file..."
	clang-12 -target bpf -I$(INC_DIR) -D __BPF_TRACING__ -D BPF_DEBUG_PRINT -g -O2 -c $^ -o $(BPF_PROG) || exit
	mv $(BPF_PROG) ${OUTPUT_BPF_OBJ_DIR}
	echo "[1/2] Built eBPF object file and placed under ${OUTPUT_BPF_OBJ_DIR}\n"

	# Build custom aggregation BPF object file
	echo "[2/2] Building custom aggregation eBPF program..."
	clang-12 -target bpf -I$(INC_DIR) -D __BPF_TRACING__ -g -O2 -c ${CUSTOM_AGGREGATION_BPF_PROG} -o $(AGGREGATION_BPF_PROG) || exit
	mv $(AGGREGATION_BPF_PROG) ${OUTPUT_BPF_OBJ_DIR}
	echo "[2/2] Built custom aggregation eBPF program and placed under ${OUTPUT_BPF_OBJ_DIR}\n"
	echo "BPF OBJECT FILES BUILT"

.ONESHELL:
bpf_func: $(SRC_DIR)/bpf/scatter_gather.bpf.c
	$(call check_defined_err, CUSTOM_AGGREGATION_FUNCTION)
	$(call check_defined_set_default, OUTPUT_BPF_OBJ_DIR)

	mkdir -p $(BPF_OBJ_DIR)
	mkdir -p ${OUTPUT_BPF_OBJ_DIR}

	# Build main BPF object file with the custom aggregation function in supplied header file
	echo "Building main eBPF object file with custom function..."
	cp ${CUSTOM_AGGREGATION_FUNCTION} ${INC_DIR}/bpf_h/custom_aggregation_function.bpf.h
	clang-12 -target bpf -I$(INC_DIR) -D __BPF_TRACING__ -D BPF_DEBUG_PRINT -D CUSTOM_AGGREGATION_FUNC -g -O2 -c $^ -o $(BPF_PROG) || exit
	mv $(BPF_PROG) ${OUTPUT_BPF_OBJ_DIR}
	echo "Built eBPF object file and placed under ${OUTPUT_BPF_OBJ_DIR}\n"


.PHONY: all
all: $(OUTPUTFILE)

.PHONY: clean 
clean:
	rm -rf $(OBJ_DIR)
	rm -rf $(BPF_OBJ_DIR)
	rm -rf $(OUT_DIR)
	rm -f $(INC_DIR)/bpf_h/custom_aggregation_function.bpf.h
