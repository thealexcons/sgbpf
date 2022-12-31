#ifndef _EBPFPP_PROGRAM_H
#define _EBPFPP_PROGRAM_H

#include <string>

#include "bpf/bpf.h"
#include "bpf/libbpf.h"

namespace ebpf {

class Program {
public:
    // CONSTRUCTORS
    explicit Program(bpf_program* program)
        : d_program{program}
        , d_fd{bpf_program__fd(program)}
        , d_name{bpf_program__name(program)}
    {}

    // Program(const Program&) = delete;
    // Program& operator=(const Program&) = delete;


    // GETTERS
    bpf_program* get() { return d_program; }
    
    bpf_program* const get() const { return d_program; }

    int fd() const { return d_fd; }

    const std::string& name() const { return d_name; }

private:
    // DATA
    bpf_program*    d_program;
    int             d_fd;
    std::string     d_name;
};


} // close namespace ebpf

#endif // !_EBPFPP_PROGRAM_H