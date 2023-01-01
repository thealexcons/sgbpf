#ifndef _EBPFPP_MAP_H
#define _EBPFPP_MAP_H

#include <string>

#include "bpf/bpf.h"
#include "bpf/libbpf.h"

namespace ebpf {

class Map {
public:
    // CONSTRUCTORS
    explicit Map(bpf_map* map)
        : d_map{map}
        , d_fd{bpf_map__fd(map)}
        , d_name{bpf_map__name(map)}
    {}

    // Map(const Map&) = delete;
    // Map& operator=(const Map&) = delete;


    // GETTERS
    bpf_map* get() { return d_map; }
    
    bpf_map* const get() const { return d_map; }

    int fd() const { return d_fd; }

    const std::string& name() const { return d_name; }

    // METHODS
    template <typename KEY, typename VALUE>
    VALUE* find(const KEY* key, VALUE* value) {
        if (bpf_map_lookup_elem(d_fd, key, value))
            return nullptr;
        return value;
    }

    template <typename KEY, typename VALUE>
    int update(const KEY* key, const VALUE* value, uint64_t flags = BPF_ANY) {
        return bpf_map_update_elem(
                d_fd, 
                key, 
                value, 
                flags
            );
    }

    template <typename KEY, typename VALUE>
    int erase(const KEY* key) {
        return bpf_map_delete_elem(d_fd, key);
    }

private:
    // DATA
    bpf_map*        d_map;
    int             d_fd;
    std::string     d_name;
};


} // close namespace ebpf

#endif // !_EBPFPP_MAP_H