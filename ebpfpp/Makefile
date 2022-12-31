CLEANEXTS   = o a 

OUTPUTFILE  = libebpfpp.a
INSTALLDIR  = ../lib

SRC_DIR := src
OBJ_DIR := obj
BIN_DIR := bin # or . if you want it in the current directory

SOURCES := $(wildcard src/*.cpp)
HEADERS := $(wildcard include/*.h)

.PHONY: all
all: $(OUTPUTFILE)

$(OUTPUTFILE): Map.o Object.o Program.o Util.o Ebpfpp.o
	ar ru $@ $^
	ranlib $@

.PHONY: install
install:
	mkdir -p $(INSTALLDIR)
	cp -p $(OUTPUTFILE) $(INSTALLDIR)

.PHONY: clean 
clean:
	for file in $(CLEANEXTS); do rm -f *.$$file; done

# Indicate dependencies of .cpp files on .h files
Map.o: Map.h
Object.o: Object.h
Program.o: Program.h
Util.o: Util.h
Ebpfpp.o: Map.h Object.h Program.h Util.h
