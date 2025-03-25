#include "fs/vfs.hpp"
#include "mm/mm.hpp"
#include "smarter/smarter.hpp"
#include "util/log/log.hpp"
#include <algorithm>
#include <cstddef>
#include <util/types.hpp>
#include <cstdint>
#include <fs/ext2.hpp>

static log::subsystem logger = log::make_subsystem("EXT2");

bool vfs::ext2fs::load() {
    this->superblock = (ext2fs::super *) kmalloc(sizeof(ext2fs::super));
    if (this->device.expired()) {
        return false;
    }

    auto source = this->device.lock();
    if (source->fs.expired()) {
        return false;
    }

    auto devfs = source->fs.lock();
    if (devfs->read(source, superblock, sizeof(ext2fs::super), 1024) < 0) {
        kmsg(logger, "superblock: read error");
        kfree(superblock);
        return false;
    }

    if (superblock->signature != EXT2_SIGNATURE) {
        kfree(superblock);
        return false;
    }

    block_size = 1024 << superblock->block_size;
    frag_size = 1024 << superblock->frag_size;
    bgd_count = util::ceil(superblock->block_count, superblock->blocks_per_group);

    kmsg(logger,
        "ext2fs: inode count: %u, block count: %u, blocks per group: %u, block size: %u, bgd count: %u",

            superblock->inode_count,
            superblock->block_count,
            superblock->blocks_per_group,
            block_size,
            bgd_count);

    ext2fs::inode inode;
    if (read_inode_entry(&inode, 2) == -1) {
        kmsg(logger, "error reading root inode");
        kfree(superblock);
        return false;
    }

    root->inum = 2;
    root->meta->st_ino = 2;

    root->meta->st_uid = inode.uid;
    root->meta->st_gid = inode.gid;
    root->meta->st_size = read_inode_size(&inode);
    root->meta->st_mode = S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
    root->meta->st_blksize = block_size;
    root->meta->st_blkcnt = util::ceil(root->meta->st_size, root->meta->st_blksize);
    root->meta->st_ino = 2;
    root->meta->st_nlink = 1;

    read_dirents(&inode, (ext2fs::ext2_private **) (&root->private_data));

    return true;;
}

weak_ptr<vfs::node> vfs::ext2fs::lookup(shared_ptr<node> parent, frg::string_view name) {
    ext2fs::inode dir_inode;
    if (read_inode_entry(&dir_inode, parent->inum) == -1) {
        return {};
    }

    auto private_data = (ext2fs::ext2_private *) parent->private_data;
    if (!private_data) {
        if (read_dirents(&dir_inode, &private_data) == -1) {
            return {};
        }
    }

    ext2_private *files = private_data;
    ext2_private *file = files;
    while (file) {
        ext2fs::inode inode;
        if (read_inode_entry(&inode, file->dent->inode_index) == -1) {
            return {};
        }

        if (strncmp(file->name, name.data(), std::max((size_t) file->dent->name_length, name.size()))!= 0) {
            file = file->next;
            continue;
        }

        int node_type;
        mode_t node_mode = inode.permissions & 0xFFF;
        switch (file->dent->dir_type) {
            case 1:
                node_type = node::type::FILE;
                node_mode |= S_IFREG;
                break;
            case 2:
                node_type = node::type::DIRECTORY;
                node_mode |= S_IFDIR;
                break;
            case 3:
                node_type = node::type::CHARDEV;
                node_mode |= S_IFCHR;
                break;
            case 4:
                node_type = node::type::BLOCKDEV;
                node_mode |= S_IFBLK;
                break;
            case 5:
                kmsg(logger, "FIFOs are unimplemented");

                node_type = node::type::FILE;
                node_mode |= S_IFREG;
                break;
            case 6:
                node_type = node::type::SOCKET;
                node_mode |= S_IFSOCK;
                break;
            case 7:
                node_type = node::type::SYMLINK;
                node_mode |= S_IFLNK;
                break;
            default:
                kmsg(logger, log::level::WARN, "unknown dirent type %d on %s", file->dent->dir_type, file->name);
                node_type = node::type::FILE;
                node_mode |= S_IFREG;

                break;
        }

        auto inode_index = file->dent->inode_index;
        auto node = smarter::allocate_shared<vfs::node>(memory::mm::heap, selfPtr, name, parent, 0, node_type, inode_index);
        auto meta = smarter::allocate_shared<vfs::node::statinfo>(memory::mm::heap);

        node->meta = meta;
        node->private_data = nullptr;

        meta->st_uid = inode.uid;
        meta->st_gid = inode.gid;
        meta->st_size = read_inode_size(&inode);
        meta->st_mode = node_mode;
        meta->st_blksize = block_size;
        meta->st_blkcnt = util::ceil(meta->st_size, meta->st_blksize);
        meta->st_ino = file->dent->inode_index;
        meta->st_nlink = 1;

        parent->children.push_back(node);

        /*
        if (node->type == node::type::SYMLINK) {
            if (read_symlink(&inode, (char **) (&node)))
        }
        */

       return node;
    }

    return {};
}

ssize_t vfs::ext2fs::readdir(shared_ptr<node> dir) {
    ext2fs::inode dir_inode;
    if (read_inode_entry(&dir_inode, dir->inum) == -1) {
        return -1;
    }

    auto private_data = (ext2fs::ext2_private *) dir->private_data;
    if (!private_data) {
        if (read_dirents(&dir_inode, &private_data) == -1) {
            return -1;
        }
    }

    ext2_private *files = private_data;
    ext2_private *file = files;
    while (file) {
        ext2fs::inode inode;
        if (read_inode_entry(&inode, file->dent->inode_index) == -1) {
            return -1;
        }

        int node_type;
        mode_t node_mode = inode.permissions & 0xFFF;
        switch (file->dent->dir_type) {
            case 1:
                node_type = node::type::FILE;
                node_mode |= S_IFREG;
                break;
            case 2:
                node_type = node::type::DIRECTORY;
                node_mode |= S_IFDIR;
                break;
            case 3:
                node_type = node::type::CHARDEV;
                node_mode |= S_IFCHR;
                break;
            case 4:
                node_type = node::type::BLOCKDEV;
                node_mode |= S_IFBLK;
                break;
            case 5:
                kmsg(logger, "FIFOs are unimplemented");

                node_type = node::type::FILE;
                node_mode |= S_IFREG;
                break;
            case 6:
                node_type = node::type::SOCKET;
                node_mode |= S_IFSOCK;
                break;
            case 7:
                node_type = node::type::SYMLINK;
                node_mode |= S_IFLNK;
                break;
            default:
                kmsg(logger, log::level::WARN, "unknown dirent type %d on %s", file->dent->dir_type, file->name);
                node_type = node::type::FILE;
                node_mode |= S_IFREG;

                break;
        }

        // filesystem *fs, path name, node *parent, ssize_t flags, ssize_t type, ssize_t inum = -1

        auto inode_index = file->dent->inode_index;
        auto node = smarter::allocate_shared<vfs::node>(memory::mm::heap, selfPtr, file->name, dir, 0, node_type, inode_index);
        auto meta = smarter::allocate_shared<vfs::node::statinfo>(memory::mm::heap);

        node->meta = meta;
        node->private_data = (void *) file;

        meta->st_uid = inode.uid;
        meta->st_gid = inode.gid;
        meta->st_mode = node_mode;
        meta->st_size = read_inode_size(&inode);
        meta->st_blksize = block_size;
        meta->st_blkcnt = util::ceil(meta->st_size, meta->st_blksize);
        meta->st_ino = file->dent->inode_index;
        meta->st_nlink = 1;

        dir->children.push_back(node);

        /*
        if (node->type == node::type::SYMLINK) {
            if (read_symlink(&inode, (char **) (&node)))
        }
        */

       file = file->next;
    }

    return 0;
}

ssize_t vfs::ext2fs::read(shared_ptr<node> file, void *buf, size_t len, off_t offset) {
    ext2fs::inode inode;
    if (read_inode_entry(&inode, file->inum) == -1) {
        return -1;
    }

    void *read_buffer = kmalloc(len);
    ssize_t bytes_read = read_inode(&inode, read_buffer, len, offset);
    ssize_t bytes_copied = arch::copy_to_user(buf, read_buffer, len);

    kfree(read_buffer);

    return (bytes_copied < bytes_read) ? bytes_copied : bytes_read;
}

ssize_t vfs::ext2fs::write(shared_ptr<node> file, void *buf, size_t len, off_t offset) {
    ext2fs::inode inode;
    if (read_inode_entry(&inode, file->inum) == -1) {
        return -1;
    }

    void *write_buffer = kmalloc(len);
    ssize_t bytes_written = arch::copy_from_user(write_buffer, buf, len);
    write_inode(&inode, file->inum, write_buffer, bytes_written, offset);

    return bytes_written;
}

ssize_t vfs::ext2fs::truncate(shared_ptr<node> file, off_t offset) {
    if (file->meta->st_size == offset) {
        return 0;
    }

    ext2fs::inode inode;
    if (read_inode_entry(&inode, file->inum) == -1) {
        return -1;
    }

    if (file->meta->st_size > offset) {
        for (uint32_t iblock = offset / block_size; iblock < file->meta->st_size / block_size; iblock++) {
            uint32_t block;
            if (inode_get_block(&inode, iblock, &block) == -1) {
                return -1;
            }

            if (free_block(block) == -1) {
                return -1;
            }
        }
    } else {
        for (uint32_t iblock = file->meta->st_size / block_size; iblock < offset / block_size; iblock++) {
            int block = allocate_block();
            if (block == -1) {
                return -1;
            }

            if (inode_set_block(&inode, file->inum, iblock, block) == -1) {
                return -1;
            }
        }
    }

    return 0;
}

ssize_t vfs::ext2fs::create(shared_ptr<node> dst, path name, int64_t type, int64_t flags, mode_t mode,
    uid_t uid, gid_t gid) {
    ext2fs::inode parent_inode;
    if (read_inode_entry(&parent_inode, dst->inum) == -1) {
        return -1;
    }

    int inum = allocate_inode();
    int dir_type;
    int inode_type;
    switch (type) {
        case node::type::FILE:
            dir_type = 1;
            inode_type = S_IFREG;
            break;
        case node::type::DIRECTORY:
            dir_type = 2;
            inode_type = S_IFDIR;
            break;
        case node::type::BLOCKDEV:
            dir_type = 4;
            inode_type = S_IFBLK;
            break;
        case node::type::CHARDEV:
            dir_type = 3;
            inode_type = S_IFCHR;
            break;
        case node::type::SOCKET:
            dir_type = 6;
            inode_type = S_IFSOCK;
            break;
        case node::type::SYMLINK:
            dir_type = 7;
            inode_type = S_IFLNK;
            break;
        default:
            dir_type = 0;
            break;
    }

    if (write_dirent(&parent_inode, dst->inum, name.data(), inum, dir_type) == -1) {
        return -1;
    }

    ext2fs::inode inode;

    inode.permissions = inode_type | mode;
    inode.uid = uid;
    inode.gid = gid;

    if (write_inode_entry(&inode, inum) == -1) {
        return -1;
    }

    auto node = smarter::allocate_shared<vfs::node>(memory::mm::heap, selfPtr, name, dst, flags, type, inum);
    auto meta = smarter::allocate_shared<vfs::node::statinfo>(memory::mm::heap);

    meta->st_ino = inum;
    meta->st_uid = parent_inode.uid;
    meta->st_gid = parent_inode.gid;
    meta->st_mode = inode_type | mode;
    meta->st_size = 0;
    meta->st_blkcnt = 0;
    meta->st_blksize = block_size;

    node->meta = meta;

    dst->children.push_back(node);

    return 0;
}

ssize_t vfs::ext2fs::mkdir(shared_ptr<node> dst, frg::string_view name, int64_t flags, mode_t mode,
    uid_t uid, gid_t gid) {
    ext2fs::inode parent_inode;
    if (read_inode_entry(&parent_inode, dst->inum) == -1) {
        return -1;
    }

    int inum = allocate_inode();
    int dir_type = 2;
    int inode_type = S_IFDIR;

    if (write_dirent(&parent_inode, dst->inum, name.data(), inum, dir_type) == -1) {
        return -1;
    }

    ext2fs::inode inode;

    inode.permissions = inode_type | mode;
    inode.uid = uid;
    inode.gid = gid;

    if (write_inode_entry(&inode, inum) == -1) {
        return -1;
    }

    auto node = smarter::allocate_shared<vfs::node>(memory::mm::heap, selfPtr, name, dst, flags, node::type::DIRECTORY, inum);
    auto meta = smarter::allocate_shared<vfs::node::statinfo>(memory::mm::heap);

    meta->st_ino = inum;
    meta->st_uid = parent_inode.uid;
    meta->st_gid = parent_inode.gid;
    meta->st_mode = S_IFDIR | mode;
    meta->st_size = 0;
    meta->st_blkcnt = 0;
    meta->st_blksize = block_size;

    node->meta = meta;

    dst->children.push_back(node);

    return 0;
}

ssize_t vfs::ext2fs::unlink(shared_ptr<node> dst) {
    auto private_data = (ext2fs::ext2_private *) dst->private_data;
    return free_inode(private_data->dent->inode_index);
}

int vfs::ext2fs::write_dirent(inode *dir, int dir_inode, const char *name, int inode, int type) {
    void *buffer = kmalloc(read_inode_size(dir) + block_size);
    if (read_inode(dir, buffer, read_inode_size(dir), 0) == -1) {
        kfree(buffer);
        return -1;
    }

    for (size_t headway = 0; headway < read_inode_size(dir);) {
        ext2fs::dirent *dirent = (ext2fs::dirent *) ((char *) buffer + headway);

        int expected_size = util::align(sizeof(ext2fs::dirent) + dirent->name_length, 4);
        headway += expected_size;

        if (dirent->entry_size == expected_size)
            continue;

        dirent->inode_index = inode;
        dirent->entry_size = expected_size;
        dirent->name_length = strlen(name);
        dirent->dir_type = type;

        memcpy((char *) dirent + sizeof(ext2fs::dirent), name, dirent->name_length);

        dirent = (ext2fs::dirent *) ((char *) dirent + expected_size);

        dirent->inode_index = 0;
        dirent->entry_size = read_inode_size(dir) - headway;
        dirent->name_length = 0;
        dirent->dir_type = 0;

        if (write_inode(dir, dir_inode, buffer, read_inode_size(dir), 0) == -1) {
            kfree(buffer);
            return -1;
        }

        break;
    }

    kfree(buffer);
    return 0;
}

inline size_t max_path_length = 8192;
int vfs::ext2fs::read_symlink(inode *inode, char **path) {
    *path = (char *) kmalloc(max_path_length);

    if (read_inode_size(inode) < 60) {
        memcpy(*path, inode->blocks, 60);
    } else if (read_inode(inode, *path, read_inode_size(inode), 0) == -1) {
        kfree(*path);
        return -1;
    }

    return 0;
}

int vfs::ext2fs::read_dirents(inode *inode, ext2_private **files) {
    void *buffer = kmalloc(read_inode_size(inode));

    if (read_inode(inode, buffer, read_inode_size(inode), 0) == -1) {
        kfree(buffer);
        return -1;
    }

    for (size_t headway = 0; headway < read_inode_size(inode);) {
        ext2fs::dirent *dirent = (ext2fs::dirent *) ((char *) buffer + headway);
        ext2fs::ext2_private *file = frg::construct<ext2fs::ext2_private>(memory::mm::heap);

        char *name = (char *) kmalloc(dirent->name_length + 1);
        memcpy(name, (char *) dirent + sizeof(ext2fs::dirent), dirent->name_length);

        file->dent = dirent;
        file->name = name;
        file->next = *files;

        *files = file;

        int expected_size = util::align(sizeof(ext2fs::dirent) + dirent->name_length, 4);
        if (dirent->entry_size != expected_size || dirent->name_length == 0) {
            break;
        }

        headway += dirent->entry_size;
    }

    return 0;
}

int vfs::ext2fs::write_inode(inode *inode, int index, void *buf, size_t count, off_t off) {
    uint64_t inode_size = read_inode_size(inode);

    for (uint64_t headway = 0; headway < count;) {
        uint32_t iblock = (off + headway) / block_size;
        uint32_t block;

        size_t length = count - headway;
        size_t block_offset = (off + headway) % block_size;

        if (length > (block_size - off)) {
            length = block_size - off;
        }

        if (inode_get_block(inode, iblock, &block) == -1) {
            return -1;
        }

        if (block == 0) {
            block = allocate_block();
            if (block == -1) {
                return -1;
            }

            if (inode_set_block(inode, index, iblock, block) == -1) {
                return -1;
            }

            inode_size += length;
        }

        if (device.expired()) {
            kmsg(logger, "write error");
            return -1;            
        }

        auto source = device.lock();
        if (source->fs.expired()) {
            kmsg(logger, "write error");
            return -1;
        }

        auto devfs = source->fs.lock();
        if (devfs->write(source, (char *) buf + headway, length, block * block_size + block_offset) < 0) {
            kmsg(logger, "write error");
            return -1;
        }

        headway += length;
    }

    if (write_inode_size(inode, index, inode_size) == -1) {
        return -1;
    }

    return count;
}

int vfs::ext2fs::read_inode(inode *inode, void *buf, size_t count, off_t off) {
    if (off > read_inode_size(inode)) {
        return 0;
    }

    if ((off + count) > read_inode_size(inode)) {
        count = read_inode_size(inode) - off;
    }

    for (uint64_t headway = 0; headway < count;) {
        uint32_t iblock = (off + headway) / block_size;
        uint32_t block;

        if (inode_get_block(inode, iblock, &block) == -1) {
            return -1;
        }

        size_t length = count - headway;
        size_t block_offset = (off + headway) % block_size;

        if (length > (block_size - off)) {
            length = block_size - off;
        }


        if (device.expired()) {
            kmsg(logger, "write error");
            return -1;            
        }

        auto source = device.lock();
        if (source->fs.expired()) {
            kmsg(logger, "write error");
            return -1;
        }

        auto devfs = source->fs.lock();
        if (devfs->read(source, (char *) buf + headway, length, block * block_size + block_offset) < 0) {
            kmsg(logger, "read error");
            return -1;
        }

        headway += length;
    }

    return count;
}

int vfs::ext2fs::inode_set_block(inode *inode, int index, uint32_t iblock, uint32_t block) {
    if (device.expired()) {
        return -1;            
    }

    auto source = device.lock();
    if (source->fs.expired()) {
        return -1;
    }

    auto devfs = source->fs.lock();
    
    uint32_t blocks_per_level = block_size / 4;
    if (iblock < 12) {
        inode->blocks[iblock] = block;
        return 0;
    }

    if (iblock >= blocks_per_level) {
        iblock -= blocks_per_level;

        uint32_t indirect_block_index = iblock / blocks_per_level;
        uint32_t indirect_block_offset = iblock / blocks_per_level;
        uint32_t indirect_block = 0;

        if (indirect_block_index >= blocks_per_level) {
            iblock -= blocks_per_level * blocks_per_level;

            uint32_t double_indirect_block_index = iblock / blocks_per_level;
            uint32_t double_indirect_block_offset = iblock % blocks_per_level;
            uint32_t double_indirect_block = 0;

            if (!inode->blocks[14]) {
                if ((inode->blocks[14] = allocate_block()) == -1) {
                    return -1;
                }

                if (write_inode_entry(inode, index) == -1) {
                    return -1;
                }
            }

            if (devfs->read(source, &double_indirect_block, sizeof(double_indirect_block),
                inode->blocks[14] * block_size + double_indirect_block_index * 4) < 0) {
                kmsg(logger, "read error");
            }

            if (!double_indirect_block) {
                if ((double_indirect_block = allocate_block()) == -1) {
                    return -1;
                }

                if (devfs->write(source, &double_indirect_block, sizeof(double_indirect_block),
                    inode->blocks[14] * block_size + double_indirect_block_index * 4) < 0) {
                    kmsg(logger, "write error");
                }
            }

            if (devfs->read(source, &indirect_block, sizeof(indirect_block),
                double_indirect_block_index * block_size + double_indirect_block * 4) < 0) {
                kmsg(logger, "read error");
            }

            if (!indirect_block) {
                if ((indirect_block = allocate_block()) == -1) {
                    return -1;
                }

                if (devfs->write(source, &indirect_block, sizeof(indirect_block),
                    double_indirect_block_index * block_size + double_indirect_block * 4) < 0) {
                    kmsg(logger, "read error");
                    return -1;
                }
            }

            if (devfs->write(source, &block, sizeof(block),
                indirect_block * block_size + double_indirect_block_offset * 4) < 0) {
                kmsg(logger, "write error");
            }

            return 0;
        }

        if (!inode->blocks[13]) {
            if ((inode->blocks[13] = allocate_block()) == -1) {
                return -1;
            }

            if (write_inode_entry(inode, index) == -1) {
                return -1;
            }
        }

        if (devfs->read(source, &indirect_block, sizeof(indirect_block),
            inode->blocks[13] * block_size + indirect_block_index * 4) < 0) {
            kmsg(logger, "read error");
            return -1;
        }

        if (!indirect_block) {
            if ((indirect_block = allocate_block()) == -1) {
                return -1;
            }

            if (devfs->write(source, &indirect_block, sizeof(indirect_block),
                inode->blocks[13] * block_size + indirect_block_index * 4) < 0) {
                kmsg(logger, "write error");
                return -1;
            }
        }

        if (devfs->write(source, &block, sizeof(block),
            indirect_block * block_size + indirect_block_offset * 4) < 0) {
            kmsg(logger, "write error");
            return -1;
        }

        return 0;
    }

    if (!inode->blocks[12]) {
        if ((inode->blocks[12] = allocate_block()) == -1) {
            return -1;
        }

        if (write_inode_entry(inode, index) == -1) {
            return -1;
        }

        if (devfs->write(source, &block, sizeof(block),
            inode->blocks[12] * blocks_per_level + iblock * 4) < 0) {
            kmsg(logger, "write error");
            return -1;
        }
    }

    return 0;
}

int vfs::ext2fs::inode_get_block(inode *inode, uint32_t iblock, uint32_t *res) {
    if (device.expired()) {
        return -1;            
    }

    auto source = device.lock();
    if (source->fs.expired()) {
        return -1;
    }

    auto devfs = source->fs.lock();

    uint32_t blocks_per_level = block_size / 4;
    uint32_t block = 0;

    if (iblock < 12) {
        *res = inode->blocks[iblock];
        return 0;
    }

    iblock -= 12;
    if (iblock >= blocks_per_level) {
        iblock -= blocks_per_level;

        uint32_t indirect_block_index = iblock / blocks_per_level;
        uint32_t indirect_block_offset = iblock / blocks_per_level;
        uint32_t indirect_block = 0;

        if (indirect_block_index >= blocks_per_level) {
            iblock -= blocks_per_level * blocks_per_level;

            uint32_t double_indirect_block_index = iblock / blocks_per_level;
            uint32_t double_indirect_block_offset = iblock % blocks_per_level;
            uint32_t double_indirect_block = 0;

            if (devfs->read(source, &double_indirect_block, sizeof(double_indirect_block),
                inode->blocks[14] * block_size + double_indirect_block_index * 4) < 0) {
                kmsg(logger, "read error");
            }

            if (!double_indirect_block) return -1;

            if (devfs->read(source, &indirect_block, sizeof(indirect_block),
                double_indirect_block_index * block_size + double_indirect_block * 4) < 0) {
                kmsg(logger, "read error");
                return -1;
            }

            if (!indirect_block) return -2;

            if (devfs->read(source, &block, sizeof(block),
                indirect_block * block_size + double_indirect_block_offset * 4) < 0) {
                kmsg(logger, "read error");
            }

            *res = block;
            return (!block) ? -2 : 0;
        }

        if (devfs->read(source, &indirect_block, sizeof(indirect_block),
            inode->blocks[13] * block_size + indirect_block_index * 4) < 0) {
            kmsg(logger, "read error");
            return -1;
        }

        if (!indirect_block) return -2;

        if (devfs->read(source, &block, sizeof(block),
            indirect_block * block_size + indirect_block_offset * 4) < 0) {
            kmsg(logger, "read error");
            return -1;
        }

        *res = block;
        return (!block) ? -2 : 0;
    }

    if (devfs->read(source, &block, sizeof(block),
        inode->blocks[12] * block_size + iblock * 4) < 0) {
        kmsg(logger, "read error");
        return -1;
    }

    *res = block;
    return 0;
}

int vfs::ext2fs::free_block(uint32_t block) {
    if (device.expired()) {
        return -1;            
    }

    auto source = device.lock();
    if (source->fs.expired()) {
        return -1;
    }

    auto devfs = source->fs.lock();

    uint32_t bgd_index = block / superblock->blocks_per_group;
    uint32_t bitmap_index = block - bgd_index * superblock->blocks_per_group;

    ext2fs::bgd bgd;
    if (read_bgd(&bgd, bgd_index) == -1) {
        return -1;
    }

    uint8_t *bitmap = (uint8_t *) kmalloc(block_size);
    if (devfs->read(source, bitmap, block_size, bgd.block_addr_bitmap * block_size) < 0) {
        kmsg(logger, "read error");

        kfree(bitmap);
        return -1;
    }

    if (!util::bit_test(bitmap, bitmap_index)) {
        kfree(bitmap);
        return 0;
    }

    util::bit_clear(bitmap, bitmap_index);
    if (devfs->write(source, bitmap, block_size, bgd.block_addr_bitmap * block_size) < 0) {
        kmsg(logger, "write error");

        kfree(bitmap);
        return -1;
    }

    bgd.unallocated_inodes--;
    if (write_bgd(&bgd, bgd_index) == -1) {
        kfree(bitmap);
        return -1;
    }

    kfree(bitmap);
    return 0;
}

int vfs::ext2fs::free_inode(uint32_t inode) {
    if (device.expired()) {
        return -1;            
    }

    auto source = device.lock();
    if (source->fs.expired()) {
        return -1;
    }

    auto devfs = source->fs.lock();

    uint32_t bgd_index = inode / superblock->inodes_per_group;
    uint32_t bitmap_index = inode - bgd_index * superblock->inodes_per_group;

    ext2fs::bgd bgd;
    if (read_bgd(&bgd, bgd_index) == -1) {
        return -1;
    }

    uint8_t *bitmap = (uint8_t *) kmalloc(block_size);
    if (devfs->read(source, bitmap, block_size, bgd.block_addr_inode * block_size) < 0) {
        kmsg(logger, "read error");

        kfree(bitmap);
        return -1;
    }

    if (!util::bit_test(bitmap, bitmap_index)) {
        kfree(bitmap);
        return 0;
    }

    util::bit_clear(bitmap, bitmap_index);
    if (devfs->write(source, bitmap, block_size, bgd.block_addr_inode * block_size) < 0) {
        kmsg(logger, "write error");

        kfree(bitmap);
        return -1;
    }

    bgd.unallocated_inodes--;
    if (write_bgd(&bgd, bgd_index) == -1) {
        kfree(bitmap);
        return -1;
    }

    kfree(bitmap);
    return 0;
}

int vfs::ext2fs::allocate_block() {
    ext2fs::bgd bgd;

    for (size_t i = 0; i < bgd_count; i++) {
        if (read_bgd(&bgd, i) == -1) {
            return -1;
        }

        int block_index = bgd_allocate_block(&bgd, i);
        if (block_index == -1) {
            continue;
        }

        return block_index + i * superblock->blocks_per_group;
    }

    return -1;
}

int vfs::ext2fs::allocate_inode() {
    ext2fs::bgd bgd;

    for (size_t i = 0; i < bgd_count; i++) {
        if (read_bgd(&bgd, i) == -1) {
            return -1;
        }

        int inode_index = bgd_allocate_inode(&bgd, i);
        if (inode_index == -1) {
            continue;
        }

        return inode_index + i * superblock->inodes_per_group;
    }

    return -1;
}

int vfs::ext2fs::bgd_allocate_inode(bgd *bgd, int bgd_index) {
    if (device.expired()) {
        return -1;            
    }

    auto source = device.lock();
    if (source->fs.expired()) {
        return -1;
    }

    auto devfs = source->fs.lock();

    if (bgd->unallocated_inodes == 0) {
        return -1;
    }

    uint8_t *bitmap = (uint8_t *) kmalloc(block_size);
    if (devfs->read(source, bitmap, block_size, bgd->block_addr_inode * block_size) < 0) {
        kmsg(logger, "read error");
        kfree(bitmap);
        return -1;
    }

    for (size_t i = 0; i < block_size; i++) {
        if (!util::bit_test(bitmap, i)) {
            util::bit_set(bitmap, i);

            if (devfs->write(source, bitmap, block_size, bgd->block_addr_inode * block_size) < 0) {
                kmsg(logger, "write error");
                kfree(bitmap);
                return -1;
            }

            bgd->unallocated_inodes--;
            if (write_bgd(bgd, bgd_index) == -1) {
                kfree(bitmap);
                return -1;
            }

            if (devfs->write(source, bitmap, block_size, bgd->block_addr_inode * block_size) < 0) {
                kmsg(logger, "write error");
                kfree(bitmap);
                return -1;
            }

            kfree(bitmap);
            return i;
        }
    }

    kfree(bitmap);
    return 0;
}

int vfs::ext2fs::bgd_allocate_block(bgd *bgd, int bgd_index) {
    if (device.expired()) {
        return -1;            
    }

    auto source = device.lock();
    if (source->fs.expired()) {
        return -1;
    }

    auto devfs = source->fs.lock();

    if (bgd->unallocated_blocks == 0) {
        return -1;
    }

    uint8_t *bitmap = (uint8_t *) kmalloc(block_size);
    if (devfs->read(source, bitmap, block_size, bgd->block_addr_bitmap * block_size) < 0) {
        kmsg(logger, "read error");
        kfree(bitmap);
        return -1;
    }

    for (size_t i = 0; i < block_size; i++) {
        if (!util::bit_test(bitmap, i)) {
            util::bit_set(bitmap, i);

            if (devfs->write(source, bitmap, block_size, bgd->block_addr_bitmap * block_size) < 0) {
                kmsg(logger, "write error");
                kfree(bitmap);
                return -1;
            }

            bgd->unallocated_blocks--;
            if (write_bgd(bgd, bgd_index) == -1) {
                kfree(bitmap);
                return -1;
            }

            if (devfs->write(source, bitmap, block_size, bgd->block_addr_bitmap * block_size) < 0) {
                kmsg(logger, "write error");
                kfree(bitmap);
                return -1;
            }

            kfree(bitmap);
            return i;
        }
    }

    kfree(bitmap);
    return 0;
}

int vfs::ext2fs::read_inode_entry(inode *inode, int index) {
    if (device.expired()) {
        return -1;            
    }

    auto source = device.lock();
    if (source->fs.expired()) {
        return -1;
    }

    auto devfs = source->fs.lock();

    int table_index = (index - 1) % superblock->inodes_per_group;
    int bgd_index = (index - 1) / superblock->inodes_per_group;

    ext2fs::bgd bgd;
    if (read_bgd(&bgd, bgd_index) == -1) {
        return -1;
    }

    if (devfs->read(source, inode, sizeof(ext2fs::inode),
        bgd.inode_table_block * block_size + superblock->inode_size * table_index) == -1) {
        kmsg(logger, "read error");
        return -1;
    }

    return 0;
}

int vfs::ext2fs::write_inode_entry(inode *inode, int index) {
    if (device.expired()) {
        return -1;            
    }

    auto source = device.lock();
    if (source->fs.expired()) {
        return -1;
    }

    auto devfs = source->fs.lock();

    int table_index = (index - 1) % superblock->inodes_per_group;
    int bgd_index = (index - 1) / superblock->inodes_per_group;

    ext2fs::bgd bgd;
    if (read_bgd(&bgd, bgd_index) == -1) {
        return -1;
    }

    if (devfs->write(source, inode, sizeof(ext2fs::inode),
        bgd.inode_table_block * block_size + superblock->inode_size * table_index) == -1) {
        kmsg(logger, "read error");
        return -1;
    }

    return 0;
}

int vfs::ext2fs::read_bgd(bgd *bgd, int index) {
    if (device.expired()) {
        return -1;            
    }

    auto source = device.lock();
    if (source->fs.expired()) {
        return -1;
    }

    auto devfs = source->fs.lock();

    uint64_t bgd_offset = (block_size >= 2048) ? block_size : block_size * 2;
    if (devfs->read(source, bgd, sizeof(ext2fs::bgd), bgd_offset + index * sizeof(ext2fs::bgd)) == -1) {
        return -1;
    }

    return 0;
}

int vfs::ext2fs::write_bgd(bgd *bgd, int index) {
    if (device.expired()) {
        return -1;            
    }

    auto source = device.lock();
    if (source->fs.expired()) {
        return -1;
    }

    auto devfs = source->fs.lock();

    uint64_t bgd_offset = (block_size >= 2048) ? block_size : block_size * 2;
    if (devfs->write(source, bgd, sizeof(ext2fs::bgd), bgd_offset + index * sizeof(ext2fs::bgd)) == -1) {
        return -1;
    }

    return 0;
}

