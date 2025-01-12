#ifndef ROOTFS_HPP
#define ROOTFS_HPP

#include "util/types.hpp"
#include <cstddef>
#include <frg/hash.hpp>
#include <frg/hash_map.hpp>
#include <mm/mm.hpp>
#include <fs/vfs.hpp>

namespace vfs {
    class rootfs : public vfs::filesystem {
        private:
            struct storage {
                void *buf;
                size_t length;
            };

        public:
            rootfs() {}

            node *lookup(node *parent, frg::string_view name) override;
            
            ssize_t read(node *file, void *buf, size_t len, off_t offset) override;
            ssize_t write(node *file, void *buf, size_t len, off_t offset) override;
            ssize_t create(node *dst, path name, int64_t type, int64_t flags, mode_t mode,
                uid_t uid, gid_t gid) override;
            ssize_t mkdir(node *dst, frg::string_view name, int64_t flags, mode_t mode,
                uid_t uid, gid_t gid) override;
            ssize_t remove(node *dest) override;
    };
};

#endif