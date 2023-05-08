# MEng Project - Accelerating network communication patterns using eBPF


## Wiki

[Link to project wiki](https://gitlab.doc.ic.ac.uk/ac3419/meng-project/-/wikis/home)

## Environment setup

See appendix 1 in report, but in summary:

1. The following dependencies are needed (note `clang+llvm-12` is required):
   
    ```$ sudo apt-get update```

    ```$ sudo apt install -y build-essential git make gcc clang-12 llvm-12 libelf-devgcc-multilib```

2. Download the latest copy (or the release of choice) of `libbpf`:
   
    ```$ git clone --depth 1 --single-branch --branch master https://github.com/libbpf/libbpf libbpf```

3. Build libbpf and install the headers locally:
   
    ```$ make --directory = libbpf/src all```

    ```$ DESTDIR=root make --directory = libbpf/src install_headers```

    ```$ make --directory = libbpf/src install_uapi_headers```

Note: When running the loader program, if you get a message about a missing shared library, you can copy
the missed shared object to `lib/x86_64-linux-gnu` or updated the `LD_LIBRARY_PATH` path ([example](https://stackoverflow.com/questions/70696552/cannot-open-shared-object-file-no-such-file-or-directory-including-libbpf-wit)).

1. Install `liburing` headers on the system:
   
    ```$ git clone https://github.com/axboe/liburing```

    ```$ cd liburing```

    ```$ ./configure && make```

    ```$ sudo make install```
    

## Starting a new project

0. This assumes you have followed the steps above and installed all the required dependencies.
   
1. Create a new directory. For this example, it will be called `my-project`.
   
2. Add a Makefile pointing to the correct `libbpf` and `sgbpf` locations (see `my-project/Makefile`).
   
3. Write your program using the `sgbpf` library (see `my-project/main.cpp` for an example).
   
4. Run `make install` to build `libbpf` and `sgbpf` libraries.
   
5. Run `make` to build your program.
   1. If you get a linker error (eg: undefined references), try re-running `make install` and then `make`.
   
6. Now, you need to build the BPF object files that contain the programs that will be loaded into the kernel:
   1. You may optionally set the `OUTPUT_BPF_OBJ_DIR` environment variable to a (full) directory in which the built object files will be placed. If ommitted, the object files will be placed under `bpfobj/` in the sgbpf directory.
   
   2. You are required to set the `CUSTOM_AGGREGATION_BPF_PROG` environment variable which should be the FULL path to your source file written in C containing the custom aggregation logic in a XDP program (which must be named `aggregation_prog`). See the example in `my-project/custom_aggregation.bpf.c`. Example (from inside `my-project`): `export CUSTOM_AGGREGATION_BPF_PROG=$(pwd)/custom_aggregation.bpf.c`
   
   3. Now, run `make --directory=<path/to/sgbpf> bpf` to build all required BPF object files.

7. Create a line-separated config file containing a list of worker endpoints, in the format: IPv4_Address:Port (see the example in `my-project`). 

8. Run your program: `sudo ./sg_program <path/to/scatter_gather.bpf.o> <path/to/aggregation.bpf.o> lo`  (remember that to load BPF programs, you need admin privileges).