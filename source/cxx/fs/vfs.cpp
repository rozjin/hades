#include "fs/ext2.hpp"
#include "mm/common.hpp"
#include <sys/sched/sched.hpp>
#include "util/lock.hpp"
#include "util/types.hpp"
#include <cstdint>
#include <frg/allocation.hpp>
#include <mm/mm.hpp>
#include <cstddef>
#include <frg/string.hpp>
#include <fs/dev.hpp>
#include <fs/rootfs.hpp>
#include <fs/vfs.hpp>
#include <mm/mm.hpp>
#include <util/log/log.hpp>
#include <util/string.hpp>

vfs::node *vfs::tree_root = nullptr;
frg::hash_map<frg::string_view, vfs::filesystem *, vfs::path_hasher, memory::mm::heap_allocator> mounts{vfs::path_hasher()};

vfs::filesystem *stored_devfs = nullptr;
static log::subsystem logger = log::make_subsystem("VFS");
void vfs::init() {
    mount("/", "/", fslist::ROOTFS, mflags::NOSRC);
    kmsg(logger, "Initialized");
}

static frg::string_view strip_leading(frg::string_view path) {
    if (path[0] == '/' && path != '/') {
        return path.sub_string(1);
    }

    return path;
}

vfs::filesystem *vfs::resolve_fs(frg::string_view path, node *base, size_t& symlinks_traversed) {
    if (path == '/') {
        return tree_root->fs;
    }

    if (path == '.') {
        if (base != nullptr) return base->fs;
        return nullptr;
    }

    if (path == "..") {
        if (base->parent != nullptr) return base->parent->fs;
        return nullptr;
    }


    auto name = find_name(path);
    auto adjusted_path = strip_leading(path);
    node *current;
    if (path[0] == '/' || base == nullptr) {
        current = tree_root;
    } else {
        current = base;
    }

    char *symlink_buf = (char *) kmalloc(8192);

    auto view = adjusted_path;
    ssize_t next_slash;
    while ((next_slash = view.find_first('/')) != -1) {
        auto pos = next_slash == -1 ? view.size() : next_slash;

        if (auto c = view.sub_string(0, pos); c.size()) {
            if (c == "..") {
                if (current->parent == nullptr) {
                    return nullptr;
                }

                current = current->parent;
            } else if (c == '/') {
                pos++;
            } else if (c != '.') {
                node *next = nullptr;
                if ((next = current->find_child(c)) == nullptr) {
                    next = current->fs->lookup(current, c);
                }

                if (next == nullptr || next->resolveable == false) {
                    return current->fs;
                }

                switch (next->type) {
                    case node::type::DIRECTORY:
                        current = next;
                        break;
                    case node::type::SYMLINK: {
                        if (!next->meta || next->meta->st_size == 0) {
                            return nullptr;
                        }

                        if (symlinks_traversed + 1 > 40) {
                            return nullptr;
                        }

                        memset(symlink_buf, 0, 8192);
                        next->fs->read(next, symlink_buf, next->meta->st_size, 0);
                        next = resolve_at(symlink_buf, current, symlinks_traversed);
                        if (next == nullptr) {
                            return current->fs;
                        }

                        symlinks_traversed++;
                        break;
                    }

                    default:
                        return next->fs;
                }
            }
        }

        view = view.sub_string(pos + 1);
    }

    node *next = nullptr;
    if (name == "..") {
        if (current->parent == nullptr) {
            return nullptr;
        }

        next = current->parent;
    } else if (name == '/') {
        next = current;
    } else {
        if ((next = current->find_child(name)) == nullptr) {
            next = current->fs->lookup(current, name);
        }

        if (next == nullptr || next->resolveable == false) {
            return nullptr;
        }
    }
    
    switch (next->type) {
        case node::type::SYMLINK: {
            if (!next->meta || next->meta->st_size == 0) {
                return nullptr;
            }

            if (symlinks_traversed + 1 > 40) {
                return nullptr;
            }

            memset(symlink_buf, 0, 8192);
            next->fs->read(next, symlink_buf, next->meta->st_size, 0);
            next = resolve_at(symlink_buf, current, symlinks_traversed);
            if (next == nullptr) {
                return nullptr;
            }

            return next->fs;
        }

        default:
            return next->fs;
    }
}

vfs::node *vfs::resolve_at(frg::string_view path, node *base, bool follow_symlink, size_t& symlinks_traversed) {
    if (path == '/') {
        return tree_root;
    }

    if (path == '.') {
        return base;
    }

    if (path == "..") {
        return base->parent;
    }

    auto name = find_name(path);
    auto adjusted_path = strip_leading(path);
    node *current;
    if (path[0] == '/' || base == nullptr) {
        current = tree_root;
    } else {
        current = base;
    }

    char *symlink_buf = (char *) kmalloc(8192);

    auto view = adjusted_path;
    ssize_t next_slash;
    while ((next_slash = view.find_first('/')) != -1) {
        auto pos = next_slash == -1 ? view.size() : next_slash;

        if (auto c = view.sub_string(0, pos); c.size()) {
            if (c == "..") {
                if (current->parent == nullptr) {
                    return nullptr;
                }

                current = current->parent;
            } else if (c == '/') {
                pos++;
            } else if (c != '.') {
                node *next = nullptr;
                if ((next = current->find_child(c)) == nullptr) {
                    next = current->fs->lookup(current, c);
                }

                if (next == nullptr || next->resolveable == false) {
                    return nullptr;
                }

                switch (next->type) {
                    case node::type::DIRECTORY:
                        current = next;
                        break;
                    case node::type::SYMLINK: {
                        if (!next->meta || next->meta->st_size == 0) {
                            return nullptr;
                        }

                        if (symlinks_traversed + 1 > 40) {
                            return nullptr;
                        }

                        memset(symlink_buf, 0, 8192);
                        next->fs->read(next, symlink_buf, next->meta->st_size, 0);
                        next = resolve_at(symlink_buf, current, symlinks_traversed);
                        if (next == nullptr) {
                            return nullptr;
                        }

                        symlinks_traversed++;
                        break;
                    }

                    default:
                        return nullptr;
                }
            }
        }

        view = view.sub_string(pos + 1);
    }

    node *next = nullptr;
    if (name == "..") {
        if (current->parent == nullptr) {
            return nullptr;
        }

        next = current->parent;
    } else if (name == '/') {
        next = current;
    } else {
        if ((next = current->find_child(name)) == nullptr) {
            next = current->fs->lookup(current, name);
        }

        if (next == nullptr || next->resolveable == false) {
            return nullptr;
        }
    }
    
    switch (next->type) {
        case node::type::DIRECTORY:
            return next;
        case node::type::SYMLINK: {
            if (!follow_symlink) {
                return next;
            }

            if (!next->meta || next->meta->st_size == 0) {
                return nullptr;
            }

            if (symlinks_traversed + 1 > 40) {
                return nullptr;
            }

            memset(symlink_buf, 0, 8192);
            next->fs->read(next, symlink_buf, next->meta->st_size, 0);
            next = resolve_at(symlink_buf, current, symlinks_traversed);
            if (next == nullptr) {
                return nullptr;
            }

            return next;
        }

        default:
            return next;
    }
}

ssize_t vfs::lseek(vfs::fd *fd, off_t off, size_t whence) {
    auto desc = fd->desc;
    if (!desc->node) return -ENOTSUP;
    if (desc->node->get_type() == node::type::DIRECTORY) {
        return -EISDIR;
    }

    if (desc->node->get_type() == node::type::SOCKET) {
        return -EPIPE;
    }

    switch (whence) {
        case SEEK_CUR:
            desc->pos = desc->pos + off;
            return desc->pos;;
        case SEEK_SET:
            desc->pos = off;
            return desc->pos;
        case SEEK_END:
            desc->pos = desc->node->meta->st_size;
            return desc->pos;
        default:
            return -EINVAL;
    }

    return 0;
}

ssize_t vfs::read(vfs::fd *fd, void *buf, size_t len) {
    if (len == 0) return 0;

    auto desc = fd->desc;
    if (!desc->node) {
        if ((size_t) desc->pos > desc->info->st_size) {
            while (__atomic_load_n(&desc->pipe->data_written, __ATOMIC_RELAXED) == 0);
            __atomic_clear(&desc->pipe->data_written, __ATOMIC_RELAXED);
        }

        if ((size_t) desc->pos + len > desc->info->st_size) {
            len = desc->info->st_size - desc->pos;
        }

        memcpy(buf, (char *) desc->pipe->buf + desc->pos, len);
        desc->pos += len;
        return len;
    }

    if (desc->node->get_type() == node::type::DIRECTORY) {
        return -EISDIR;
    }

    auto res = desc->node->get_fs()->read(desc->node, buf, len, desc->pos);
    if (res >= 0) desc->pos += res;
    return res;
}

ssize_t vfs::write(vfs::fd *fd, void *buf, size_t len) {
    if (len == 0) return 0;

    auto desc = fd->desc;
    if (!desc->node) {
        if ((size_t) desc->pos >= memory::page_size) {
            return -EINVAL;
        }

        if ((size_t) (desc->pos + len) > memory::page_size) {
            len = desc->info->st_size - desc->pos;
        }

        if ((size_t) (desc->pos + len) > desc->info->st_size) {
            desc->info->st_size = desc->pos + len - desc->info->st_size;
        }

        memcpy((char *) desc->pipe->buf + desc->pos, buf, len);
        desc->pos += len;

        if ((size_t) desc->pos > desc->info->st_size) {
            desc->pipe->data_written = true;
        }

        return len;
    }

    if (desc->node->get_type() == node::type::DIRECTORY) {
        return -EISDIR;
    }

    auto res = desc->node->get_fs()->write(desc->node, buf, len, desc->pos);
    if (res >= 0) desc->pos += res;
    return res;
}

ssize_t vfs::ioctl(vfs::fd *fd, size_t req, void *buf) {
    auto desc = fd->desc;
    return desc->node->get_fs()->ioctl(desc->node, req, buf);
}

vfs::path* vfs::get_absolute(node *node) {
    vfs::node *current = node;
    pathlist paths;
    while (current != nullptr) {
        paths.push_back(current->name);
        current = current->parent;
    }

    vfs::path* path = frg::construct<vfs::path>(memory::mm::heap, "/");
    for (size_t i = 0; i < paths.size(); i++) {
        path->operator+('/');
        path->operator+(paths[i]);
    }

    paths.clear();
    return path;
}

vfs::node *vfs::get_parent(node *base, frg::string_view filepath) {
    if (filepath[0] == '/' && filepath.count('/') == 1) {
        return tree_root;
    }

    auto parent_path = filepath;
    if (parent_path.find_last('/') != size_t(-1))
        parent_path = parent_path.sub_string(0, parent_path.find_last('/'));

    auto parent = resolve_at(parent_path, base);
    if (!parent) {
        return nullptr;
    }

    return parent;
}

ssize_t vfs::create(node *base, frg::string_view filepath, fd_table *table, int64_t type, int64_t flags, mode_t mode,
    uid_t uid, gid_t gid) {
    auto parent = get_parent(base, filepath);
    if (!parent) {
        return -ENOENT;
    }

    if (parent->get_type() != node::type::DIRECTORY) {
        return -EINVAL;
    }

    auto name = find_name(filepath);
    auto fs = parent->get_fs();

    size_t err = 0;
    switch (type) {
        case node::type::DIRECTORY: {
            if ((err = fs->mkdir(parent, name, flags, mode, uid, gid)) != 0) {
                return err;
            }

            break;
        }

        case node::type::FILE: {
            if ((err = fs->create(parent, name, type, flags, mode, uid, gid)) != 0) {
                return err;
            }

            break;
        }
    }

    return 0;
}

vfs::fd_table *vfs::make_table() {
    auto table = frg::construct<fd_table>(memory::mm::heap);
    table->lock = util::lock{};
    table->last_fd = 0;

    return table;
}

vfs::fd_table *vfs::copy_table(fd_table *table) {
    auto new_table = make_table();
    new_table->last_fd = table->last_fd;

    for (auto [fd_number, fd]: table->fd_list) {
        auto desc = fd->desc;

        auto new_desc = frg::construct<vfs::descriptor>(memory::mm::heap);
        auto new_fd = frg::construct<vfs::fd>(memory::mm::heap);

        new_desc->node = desc->node;
        new_desc->pipe = desc->pipe;

        new_desc->ref = 1;
        new_desc->pos = desc->pos;
        new_desc->info = desc->info;

        new_desc->current_ent = 0;
        new_desc->dirent_list = frg::vector<dirent *, memory::mm::heap_allocator>();
        new_desc->event_trigger = frg::construct<ipc::trigger>(memory::mm::heap);
        new_desc->status = 0;

        new_fd->lock = util::lock();
        new_fd->desc = new_desc;
        new_fd->table = new_table;
        new_fd->fd_number = fd_number;
        new_fd->flags = fd->flags;
        new_fd->mode = fd->mode;

        new_table->fd_list[fd->fd_number] = new_fd;
    }

    return new_table;
}

void vfs::delete_table(fd_table *table) {
    for (auto [fd_number, fd]: table->fd_list) {
        if (fd == nullptr) continue;

        auto desc = fd->desc;
        if (desc->node) desc->node->ref_count--;
        frg::destruct(memory::mm::heap, desc);
        frg::destruct(memory::mm::heap, fd);
    }

    frg::destruct(memory::mm::heap, table);
}

mode_t vfs::type2mode(int64_t type) {
    int mode_type;
    switch (type) {
        case node::type::FILE:
            mode_type = S_IFREG;
            break;
        case node::type::DIRECTORY:
            mode_type = S_IFDIR;
            break;
        case node::type::BLOCKDEV:
            mode_type = S_IFBLK;
            break;
        case node::type::CHARDEV:
            mode_type = S_IFCHR;
            break;
        case node::type::SOCKET:
            mode_type = S_IFSOCK;
            break;
        case node::type::SYMLINK:
            mode_type = S_IFLNK;
            break;
        default:
            mode_type = 0;
            break;
    }

    return mode_type;
}

vfs::node* vfs::make_recursive(node *base, frg::string_view path, int64_t type, mode_t mode) {
    frg::string_view view = path;
    ssize_t next_slash;

    node *current_node = base;
    while ((next_slash = view.find_first('/')) != -1) {
        auto pos = next_slash == -1 ? view.size() : next_slash;

        if (auto c = view.sub_string(0, pos); c.size()) {
            if (auto child = current_node->find_child(c.data())) {
                if (child->type != node::type::DIRECTORY) return nullptr;
                current_node = child;

            } else {
                node *next = frg::construct<node>(memory::mm::heap, base->fs, c.data(), current_node, 0, node::type::DIRECTORY);

                next->meta->st_uid = current_node->meta->st_uid;
                next->meta->st_gid = current_node->meta->st_gid;
                next->meta->st_mode = current_node->meta->st_mode;
                
                current_node->children.push_back(next);
                current_node = next;
            }
        }

        view = view.sub_string(pos + 1);
    }

    node *next = frg::construct<node>(memory::mm::heap, base->fs, view.data() + view.find_last('/') + 1, current_node, 0, type);
    next->meta->st_uid = current_node->meta->st_uid;
    next->meta->st_gid = current_node->meta->st_gid;
    next->meta->st_mode = (current_node->meta->st_mode & (~S_IFDIR)) | type2mode(type);

    current_node->children.push_back(next);

    return next;
}

vfs::filesystem *vfs::device_fs() {
    return stored_devfs;
}

vfs::fd *vfs::make_fd(vfs::node *node, fd_table *table, int64_t flags, mode_t mode) {
    auto desc = frg::construct<vfs::descriptor>(memory::mm::heap);
    auto fd = frg::construct<vfs::fd>(memory::mm::heap);

    desc->node = node;
    desc->pipe = nullptr;

    desc->ref = 1;
    desc->pos= 0;

    desc->info = nullptr;

    desc->current_ent = 0;
    desc->dirent_list = frg::vector<dirent *, memory::mm::heap_allocator>();
    desc->event_trigger = frg::construct<ipc::trigger>(memory::mm::heap);
    desc->status = 0;

    fd->lock = util::lock();
    fd->desc = desc;
    fd->table = table;
    fd->fd_number = table->last_fd++;
    fd->flags = flags;
    fd->mode = mode;

    if (node) {
        auto open_val = node->get_fs()->on_open(fd, flags);
        if (open_val != -ENOTSUP && open_val < 0) {
            frg::destruct(memory::mm::heap, desc);
            frg::destruct(memory::mm::heap, fd);

            return nullptr;
        }
    }

    table->lock.irq_acquire();
    table->fd_list[fd->fd_number] = fd;
    table->lock.irq_release();

    return fd;
}

vfs::fd *vfs::open(node *base, frg::string_view filepath, fd_table *table, int64_t flags, mode_t mode,
    uid_t uid, gid_t gid) {
    if (!table) {
        return nullptr;
    }

    auto node = resolve_at(filepath, base);
    if (!node) {
        if (flags & O_CREAT && table) {
            auto err = create(base, filepath, table, vfs::node::type::FILE, flags, mode, uid, gid);
            if (err <= 0) {
                return nullptr;
            }
        } else {
            return nullptr;
        }
    }

    return make_fd(node, table, flags, mode);
}

vfs::fd_pair vfs::open_pipe(fd_table *table, ssize_t flags) {
    auto read = make_fd(nullptr, table, flags, O_RDONLY);
    auto write = make_fd(nullptr, table, flags, O_WRONLY);

    auto pipe = frg::construct<vfs::pipe>(memory::mm::heap);
    pipe->read = read->desc;
    pipe->write = write->desc;
    pipe->len = memory::page_size;
    pipe->buf = kmalloc(memory::page_size);
    pipe->data_written = false;

    auto stat = frg::construct<node::statinfo>(memory::mm::heap);
    stat->st_size = 0;
    stat->st_mode = S_IFIFO | S_IWUSR | S_IRUSR;

    write->desc->pipe = pipe;
    write->desc->info = stat;
    write->flags = O_WRONLY;

    read->desc->pipe = pipe;
    read->desc->info = stat;
    read->flags = O_RDONLY;

    return {read, write};
}

vfs::fd *vfs::dup(vfs::fd *fd, bool cloexec, ssize_t new_num) {
    if (fd == nullptr) {
        return nullptr;
    }

   if (fd->fd_number == new_num) {
        return fd;
    }

    fd->desc->ref++;
    auto new_fd = fd->table->fd_list[new_num];
    if (new_num >= 0 && new_fd) {
        close(new_fd);
    }

    new_fd = frg::construct<vfs::fd>(memory::mm::heap);
    new_fd->lock = util::lock();
    new_fd->desc = fd->desc;
    new_fd->table = fd->table;
    if (new_num >= 0) {
        new_fd->fd_number = new_num;
    } else {
        new_fd->fd_number = fd->table->last_fd++;
    }

    new_fd->flags = cloexec ? fd->flags | O_CLOEXEC : fd->flags & ~O_CLOEXEC;
    new_fd->mode = fd->mode;

    fd->table->lock.irq_acquire();
    fd->table->fd_list[new_fd->fd_number] = new_fd;
    fd->table->lock.irq_release();

    return new_fd;
}

ssize_t vfs::stat(node *dir, frg::string_view filepath, node::statinfo *buf, int64_t flags) {
    auto node = resolve_at(filepath, dir, !(flags & AT_SYMLINK_NOFOLLOW));
    if (!node) {
        return -ENOENT;
    }

    memcpy(buf, node->meta, sizeof(node::statinfo));
    return 0;
}

ssize_t vfs::close(vfs::fd *fd) {
    auto desc = fd->desc;
    desc->ref--;

    if (desc->node) {
        desc->node->ref_count--;
        desc->node->get_fs()->on_close(fd, fd->flags);

        if (desc->node->ref_count == 0 && desc->node->delete_on_close) {
            desc->node->fs->remove(desc->node);
        }
    }

    fd->table->fd_list.remove(fd->fd_number);
    if (fd->fd_number <= fd->table->last_fd) {
        fd->table->last_fd = fd->fd_number;
    }

    frg::destruct(memory::mm::heap, fd);
    if (desc->ref <= 0) {
        if (desc->info) frg::destruct(memory::mm::heap, desc->info);
        for (auto dirent: desc->dirent_list) {
            if (dirent == nullptr) continue;
            frg::destruct(memory::mm::heap, dirent);
        }

        frg::destruct(memory::mm::heap, desc->event_trigger);
        frg::destruct(memory::mm::heap, desc);
    }

    return 0;
}

ssize_t vfs::mkdir(node *base, frg::string_view dirpath, int64_t flags, mode_t mode,
    uid_t uid, gid_t gid) {
    auto dst = resolve_at(dirpath, base);
    if (dst) {
        switch (base->get_type()) {
            case node::type::DIRECTORY:
                return -EISDIR;
            default:
                return -EEXIST;
        }
    }

    auto parent = get_parent(base, dirpath);
    if (!parent) {
        return -ENOTDIR;
    }

    return parent->fs->mkdir(parent, find_name(dirpath), flags, mode, uid, gid);
}

ssize_t vfs::rename(node *old_base, frg::string_view oldpath, node *new_base, frg::string_view newpath, int64_t flags) {
    auto oldview = frg::string_view(oldpath);
    auto newview = frg::string_view(newpath);
    auto name = find_name(newpath);

    if (newview.size() > oldview.size() && newview.sub_string(0, oldview.size()) == oldview) {
        return -EINVAL;
    }

    auto src = resolve_at(oldpath, old_base);
    if (!src) {
        return -EINVAL;
    }

    auto dst = resolve_at(newpath, new_base);
    if (dst) {
        if (dst->get_fs() != src->get_fs()) {
            return -EXDEV;
        }

        if (dst->ref_count || src->ref_count) {
            return -EBUSY;
        }

        switch (dst->get_type()) {
            case node::type::SOCKET:
            case node::type::BLOCKDEV:
            case node::type::CHARDEV:
                return -EINVAL;
            default:
                break;
        }

        if (dst->get_type() == node::type::DIRECTORY && src->get_type() == node::type::DIRECTORY) {
            if (dst->get_ccount()) {
                return -ENOTEMPTY;
            }
        }

        if (dst->get_type() != src->get_type()) {
                return -EINVAL;
        }
    } else if (resolve_fs(newpath, new_base) != src->get_fs()) {
        return -EXDEV;
    }

    src->fs->rename(src, dst, name, flags);

    return 0;
}

// TODO: adding a symlink
ssize_t vfs::link(node *from_base, frg::string_view from, node *to_base, frg::string_view to, bool is_symlink) {
    if (from == to) {
        return -EINVAL;
    }

    auto src = resolve_at(from, from_base);

    auto dst = resolve_at(to, to_base);
    auto dst_name = find_name(to);
    auto dst_parent = get_parent(to_base, to);

    if (dst) {
        return -EINVAL;
    }

    auto dst_fs = resolve_fs(to, to_base);
    if (dst_fs != src->fs) {
        return -EINVAL;
    }

    auto link_dst = frg::construct<node>(memory::mm::heap, src->fs, dst_name, dst_parent, 0, src->type, src->inum);
    auto err = dst_fs->link(src, link_dst, dst_name, false);
    if (err < 0) {
        frg::destruct(memory::mm::heap, link_dst);
        return err;
    }

    dst_parent->children.push_back(link_dst);
    return 0;
}

ssize_t vfs::unlink(node *base, frg::string_view filepath) {
    auto node = resolve_at(filepath, base);
    if (node == nullptr || node->type == node::type::DIRECTORY) {
        return -EINVAL;
    }

    auto err = node->fs->unlink(node);
    if (err < 0) {
        return err;
    }

    node->resolveable = false;
    node->delete_on_close = true;
    if (node->ref_count == 0) {
        for (size_t i = 0; i < node->parent->children.size(); i++) {
            auto child = node->parent->children[i];
            if (child == nullptr) continue;
            if (child->name == node->name) {
                node->parent->children[i] = nullptr;
                break;
            }
        }

        node->fs->remove(node);
    }

    return 0;
}

ssize_t vfs::rmdir(node *base, frg::string_view dirpath) {
    auto dst = resolve_at(dirpath, base);
    if (dst == nullptr || dst->type != node::type::DIRECTORY || dst->children.size() > 0) {
        return -EINVAL;
    }

    auto err = dst->fs->remove(dst);
    if (err < 0) {
        return err;
    }

    return 0;
}

vfs::pathlist vfs::readdir(node *base, frg::string_view dirpath) {
    auto dst = resolve_at(dirpath, base);
    if (dst == nullptr || dst->type != node::type::DIRECTORY) {
        return {};
    }

    auto err = dst->fs->readdir(dst);
    if (err < 0) {
        return {};
    }

    auto paths = pathlist();
    for (auto child: dst->children) {
        if (child == nullptr) continue;
        paths.push(child->name);
    }

    return paths;
}

ssize_t vfs::mount(frg::string_view srcpath, frg::string_view dstpath, ssize_t fstype, int64_t flags) {
    auto *src = resolve_at(srcpath, nullptr);
    auto *dst = resolve_at(dstpath, nullptr);

    switch (flags) {
        case (mflags::NOSRC | mflags::NODST):
        case mflags::NODST:
        case mflags::NOSRC: {
            switch (fstype) {
                case fslist::ROOTFS: {
                    if (tree_root) {
                        return -ENOTEMPTY;
                    }

                    auto *fs = frg::construct<rootfs>(memory::mm::heap);
                    auto *root = frg::construct<node>(memory::mm::heap, fs, "/", nullptr, 0, node::type::DIRECTORY);
                    fs->init_as_root(root);
                    tree_root = root;
                    mounts["/"] = fs;
                    break;
                }

                case fslist::DEVFS: {
                    if (!dst) {
                        return -EINVAL;
                    }

                    if (dst->get_type() != node::type::DIRECTORY) {
                        return -EINVAL;
                    }

                    if (dst->get_ccount() > 0) {
                        return -EINVAL;
                    }

                    auto fs = frg::construct<devfs>(memory::mm::heap);
                    fs->init_fs(dst, nullptr);
                    dst->set_fs(fs);
                    mounts[strip_leading(dstpath)] = fs;
                    stored_devfs = fs;
                    break;
                }

                default:
                    return -EINVAL;
            }
            break;
        }

        default: {
            switch (fstype) {
                case fslist::EXT: {
                    if (!dst || !src) {
                        kmsg(logger, "invalid src or dst");

                        return -EINVAL;
                    }

                    if (dst->get_type() != node::type::DIRECTORY || src->get_type() != node::type::BLOCKDEV) {
                        kmsg(logger, "invalid source device or dest; dst: %ld, src: %ld", dst->get_type(), src->get_type());

                        return -EINVAL;
                    }

                    auto fs = frg::construct<ext2fs>(memory::mm::heap);
                    fs->init_fs(dst, src);
                    dst->set_fs(fs);
                    mounts[strip_leading(dstpath)] = fs;
                }

                default:
                    return -EINVAL;
            }

            break;
        }

    }

    return 0;
}

// TODO: fix umount
ssize_t vfs::umount(node *dst) {
    auto *fs = dst->get_fs();
    if (!dst) {
        return -EINVAL;
    }

    if (!fs) {
        return -EINVAL;
    }

    if (dst->ref_count) {
        return -EBUSY;
    }

    frg::destruct(memory::mm::heap, fs);
    return 0;
}