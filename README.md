# MEng Project - Accelerating network communication patterns using eBPF


## Wiki

[Link to project wiki](https://gitlab.doc.ic.ac.uk/ac3419/meng-project/-/wikis/home)

## Environment setup

See appendix 1 in report, but in summary:

1. The following dependencies are needed:
    ```$ sudo apt-get update```
    ```$ sudo apt install -y build-essential git make gcc clang llvm libelf-devgcc-multilib```

2. Download the latest copy (or the release of choice) of libbpf :
    ```$ git clone --depth 1 --single-branch --branch master https://github.com/libbpf/libbpf libbpf```

3. Build libbpf and install the headers locally:
    ```$ make --directory = libbpf/src all```
    ```$ DESTDIR = root make --directory = libbpf/src install_headers```

