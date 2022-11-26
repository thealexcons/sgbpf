#include "Object.h"

#include <sstream>
#include <array>


namespace ebpf {

namespace {

    std::string libBPFErrMsg(int err) {
        std::array<char, 128> buf{};
        libbpf_strerror(err, buf.data(), buf.size());
        return std::string(buf.begin(), buf.end());
    }

}

// CONSTRUCTORS
Object::Object(const std::string& path) {
    d_object = bpf_object__open(path.c_str());
    const auto err = libbpf_get_error(d_object);
    if (err) {
        std::ostringstream oss;
        oss << "Error while opening bpf object: " << path << ", error: " 
            << libBPFErrMsg(err);
        throw std::runtime_error{oss.str()};
    }
    d_name = bpf_object__name(d_object);

    // Load the object into the kernel
    if (bpf_object__load(d_object)) {
        std::ostringstream oss; 
        oss << "error while trying to load bpf object: " << d_name;
        throw std::runtime_error{oss.str()};
    }
}


// DESTRUCTOR
Object::~Object() {
    bpf_object__close(d_object);
}


// METHODS
std::vector<Map> Object::maps() const {
    bpf_map* map;
    std::vector<Map> maps;
    bpf_object__for_each_map(map, d_object) {
        maps.emplace_back(map);
    }
    return maps;
}

std::vector<Program> Object::programs() const {
    bpf_program* program;
    std::vector<Program> programs;
    bpf_object__for_each_program(program, d_object) {
        programs.emplace_back(program);
    }
    return programs;
}

std::optional<Map> Object::findMapByName(const std::string& name) const {
    if (auto mapPtr = bpf_object__find_map_by_name(d_object, name.c_str())) {
        return Map{mapPtr};
    }
    return {};
}

std::optional<Program> Object::findProgramBySectionTitle(const std::string& title) const {
    if (auto progPtr = bpf_object__find_program_by_title(d_object, title.c_str())) {
        return Program{progPtr};
    }
    return {};
}

std::optional<Program> Object::findProgramByFunctionName(const std::string& funcName) const {
    if (auto progPtr = bpf_object__find_program_by_name(d_object, funcName.c_str())) {
        return Program{progPtr};
    }
    return {};
}

} // close namespace ebpf
