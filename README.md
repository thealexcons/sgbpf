# sgbpf: an eBPF-accelerated scatter-gather network primitive for UDP

## About
MEng Project - Accelerating network communication patterns using eBPF


## Environment setup

1. The following dependencies are needed (note `clang+llvm-12` is required):

  ```$ sudo apt-get update```

  ```$ sudo apt install -y build-essential pkgconf git make gcc clang-12 llvm-12 libelf-dev gcc-multilib```

1. Ensure you have installed `liburing` and its headers on your system:

    ```$ git clone https://github.com/axboe/liburing```

    ```$ cd liburing```

    ```$ ./configure && make```

    ```$ sudo make install```

2. Clone this project (**and all the submodules**) using:

  ```$ git clone --recurse-submodules https://gitlab.doc.ic.ac.uk/ac3419/meng-project.git```

4. Build and install `libbpf` on your system (included as a submodule inside `sgbpf`):

    ```$ cd meng-project/sgbpf/dep/libbpf/src ```

    ```$ make all```

    ```$ sudo DESTDIR=root make install```

    ```$ sudo make install_headers```

    ```$ sudo make install_uapi_headers```


## Starting a new project

0. This assumes you have followed the steps above and installed all the required dependencies.
   
1. Create a new directory. For this example, it will be called `my-project`.
   
2. Add a Makefile pointing to the correct `libbpf` and `sgbpf` locations (see `my-project/Makefile`).
   
3. Write your program using the `sgbpf` library (see `my-project/main.cpp` for an example).
   
4. Run `make install` to build `libbpf` and `sgbpf` libraries.
   
5. Run `make` to build your program.
   1. If you get a linker error (eg: undefined references), try re-running `make install` and then `make`.
   
6. Now, you need to build the BPF object files that contain the programs that will be loaded into the kernel:
   1. You may optionally set the `OUTPUT_BPF_OBJ_DIR` environment variable to a (full) directory in which the built object files will be placed. If ommitted, the object files will be placed under `bpfobj/` in the sgbpf directory by default.
   
   2. You are required to set the `CUSTOM_AGGREGATION_BPF_PROG` environment variable which should be the FULL path to your source file written in C containing the custom aggregation logic in a XDP program (which must be named `aggregation_prog`). See the example in `my-project/custom_aggregation.bpf.c`. Example (from inside `my-project`): `export CUSTOM_AGGREGATION_BPF_PROG=$(pwd)/custom_aggregation.bpf.c`

   4. Now, run `make --directory=<path/to/sgbpf> bpf` to build all required BPF object files.

7. Create a line-separated config file containing a list of worker endpoints, in the format: IPv4_Address:Port (see the example in `my-project`). 

8. Run your program: `sudo ./sg_program <path/to/bpfobjs> lo`  (remember that to load BPF programs, you need admin privileges).

Note: When running the loader program, if you get a message about the missing shared library `libbpf.so.1`, you can copy the missing shared object to `lib/x86_64-linux-gnu` from the build inside `libbpf/src` using: `sudo cp sgbpf/dep/libbpf/src/libbpf.so.1 /lib/x86_64-linux-gnu/`
