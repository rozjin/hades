#include <cstddef>
#include <driver/dtable.hpp>
#include <util/misc.hpp>

bool match_values(int *dtable_data, int *match_data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (dtable_data[i] == dtable::MATCH_ANY) continue;
        if (dtable_data[i] != match_data[i]) return false;
    }

    return true;
}

vfs::devfs::matcher *dtable::lookup_by_data(int *match_data, size_t len) {
    for (size_t i = 0; i < util::lengthof(entries); i++) {
        auto entry = entries[i];
        if (match_values(entry.match_data, match_data, len)) return entries[i].matcher;
    }

    return nullptr;
}

vfs::devfs::matcher *dtable::lookup_by_major(ssize_t major) {
    for (size_t i = 0; i < util::lengthof(entries); i++) {
        auto entry = entries[i];
        if (entry.major == major) return entries[i].matcher;
    }

    return nullptr;
}