#ifndef _EBPFPP_OBJECT_H
#define _EBPFPP_OBJECT_H

#include <string>
#include <vector>
#include <optional>

#include "Map.h"
#include "Program.h"

#include "bpf/bpf.h"
#include "bpf/libbpf.h"

namespace ebpf {

class Object {
public:
    // CONSTRUCTORS
    explicit Object(const std::string& path);

    // Object(const Object&) = delete;
    // Object& operator=(const Object&) = delete;


    // DESTRUCTOR
    ~Object();

    // GETTERS
    bpf_object* get() { return d_object; }
    
    bpf_object* const get() const { return d_object; }

    const std::string& name() const { return d_name; }

    // METHODS
    std::vector<Map> maps() const;

    std::vector<Program> programs() const;

    std::optional<Map> findMapByName(const std::string& name) const;

    std::optional<Program> findProgramByName(const std::string& funcName) const;

private:
    // DATA
    bpf_object*     d_object;
    std::string     d_name;
};


} // close namespace ebpf

#endif // !_EBPFPP_OBJECT_H