#include "arch/types.hpp"
#include "fs/ext2.hpp"
#include "mm/common.hpp"
#include <sys/sched/sched.hpp>
#include "smarter/smarter.hpp"
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

shared_ptr<vfs::node> vfs::tree_root{};
frg::hash_map<
    frg::string_view, 
    shared_ptr<vfs::filesystem>, 
    vfs::path_hasher, 
    memory::mm::heap_allocator
> mounts{vfs::path_hasher()};

shared_ptr<vfs::filesystem> stored_devfs{};
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

weak_ptr<vfs::filesystem> vfs::resolve_fs(frg::string_view path, shared_ptr<node> base, size_t& symlinks_traversed) {
    if (path == '/') {
        return tree_root->fs;
    }

    if (path == '.') {
        if (base) return base->fs;
        return {};
    }

    if (path == "..") {
        if (!base->parent.expired()) {
            auto parent = base->parent.lock();
            auto fs = parent->fs.lock();
            if (fs) {
                return fs;
            }
        }
        return {};
    }


    auto name = find_name(path);
    auto adjusted_path = strip_leading(path);
    shared_ptr<node> current;
    if (path[0] == '/' || base) {
        current = tree_root;
    } else {
        current = base;
    }

    char *symlink_buf = nullptr;

    auto view = adjusted_path;
    ssize_t next_slash;
    while ((next_slash = view.find_first('/')) != -1) {
        auto pos = next_slash == -1 ? view.size() : next_slash;

        if (auto c = view.sub_string(0, pos); c.size()) {
            if (c == "..") {
                if (current->parent.expired()) {
                    kfree(symlink_buf);
                    return {};
                }

                current = current->parent.lock();
            } else if (c == '/') {
                pos++;
            } else if (c != '.') {
                shared_ptr<node> next = current->find_child(c);
                if (!next) {
                    auto fs = current->fs.lock();
                    if (fs) {
                        auto res = fs->lookup(current, c);
                        if (!res.expired()) {
                            next = res.lock();
                        }
                    }
                }

                if (!next || next->resolveable == false) {
                    kfree(symlink_buf);
                    return current->fs;
                }

                switch (next->type) {
                    case node::type::DIRECTORY:
                        current = next;
                        break;
                    case node::type::SYMLINK: {
                        if (!next->meta || next->meta->st_size == 0) {
                            kfree(symlink_buf);
                            return {};
                        }

                        if (symlinks_traversed + 1 > 40) {
                            kfree(symlink_buf);
                            return {};
                        }

                        if (symlink_buf == nullptr) symlink_buf = (char *) kmalloc(8192);
                        
                        auto fs = next->fs.lock();

                        if (fs) {
                            memset(symlink_buf, 0, 8192);
                            fs->read(next, symlink_buf, next->meta->st_size, 0);
                            next = resolve_at(symlink_buf, current, symlinks_traversed);
                            if (!next) {
                                kfree(symlink_buf);
                                return current->fs;
                            }
                        }

                        symlinks_traversed++;
                        break;                        
                    }

                    default:
                        kfree(symlink_buf);
                        return next->fs;
                }
            }
        }

        view = view.sub_string(pos + 1);
    }

    shared_ptr<node> next{};
    if (name == "..") {
        if (current->parent.expired()) {
            kfree(symlink_buf);
            return {};
        }

        next = current->parent.lock();
    } else if (name == '/') {
        next = current;
    } else {
        shared_ptr<node> next = current->find_child(name);
        if (!next) {
            auto fs = current->fs.lock();
            if (fs) {
                auto res = fs->lookup(current, name);
                if (!res.expired()) {
                    next = res.lock();
                }
            }
        }

        if (!next || next->resolveable == false) {
            kfree(symlink_buf);
            return {};
        }
    }
    
    switch (next->type) {
        case node::type::SYMLINK: {
            if (!next->meta || next->meta->st_size == 0) {
                kfree(symlink_buf);
                return {};
            }

            if (symlinks_traversed + 1 > 40) {
                kfree(symlink_buf);
                return {};
            }

            auto fs = next->fs.lock();

            if (fs) {
                memset(symlink_buf, 0, 8192);
                fs->read(next, symlink_buf, next->meta->st_size, 0);
                next = resolve_at(symlink_buf, current, symlinks_traversed);
                if (!next) {
                    kfree(symlink_buf);
                    return current->fs;
                }
            }

            if (!next) {
                kfree(symlink_buf);
                return {};
            }

            kfree(symlink_buf);
            return next->fs;
        }

        default:
            kfree(symlink_buf);
            return next->fs;
    }
}

shared_ptr<vfs::node> vfs::resolve_at(frg::string_view path, shared_ptr<vfs::node> base, bool follow_symlink, size_t& symlinks_traversed) {
    if (path == '/') {
        return tree_root;
    }

    if (path == '.') {
        return base;
    }

    if (path == "..") {
        return base->parent.lock();
    }

    auto name = find_name(path);
    auto adjusted_path = strip_leading(path);
    shared_ptr<node> current;
    if (path[0] == '/' || !base) {
        current = tree_root;
    } else {
        current = base;
    }

    char *symlink_buf = nullptr;

    auto view = adjusted_path;
    ssize_t next_slash;
    while ((next_slash = view.find_first('/')) != -1) {
        auto pos = next_slash == -1 ? view.size() : next_slash;

        if (auto c = view.sub_string(0, pos); c.size()) {
            if (c == "..") {
                if (current->parent.expired()) {
                    kfree(symlink_buf);
                    return {};
                }

                current = current->parent.lock();
            } else if (c == '/') {
                pos++;
            } else if (c != '.') {
                shared_ptr<node> next = current->find_child(c);
                if (!next) {
                    auto fs = current->fs.lock();
                    if (fs) {
                        auto res = fs->lookup(current, c);
                        if (!res.expired()) {
                            next = res.lock();
                        }
                    }
                }

                if (!next || next->resolveable == false) {
                    kfree(symlink_buf);
                    return {};
                }

                switch (next->type) {
                    case node::type::DIRECTORY:
                        current = next;
                        break;
                    case node::type::SYMLINK: {
                        if (!next->meta || next->meta->st_size == 0) {
                            kfree(symlink_buf);
                            return {};
                        }

                        if (symlinks_traversed + 1 > 40) {
                            kfree(symlink_buf);
                            return {};
                        }

                        if (symlink_buf == nullptr) symlink_buf = (char *) kmalloc(8192);

                        auto fs = next->fs.lock();

                        if (fs) {
                            memset(symlink_buf, 0, 8192);
                            fs->read(next, symlink_buf, next->meta->st_size, 0);
                            next = resolve_at(symlink_buf, current, symlinks_traversed);
                            if (!next) {
                                kfree(symlink_buf);
                                return {};
                            }
                        }

                        symlinks_traversed++;
                        break;
                    }

                    default:
                        kfree(symlink_buf);
                        return {};
                }
            }
        }

        view = view.sub_string(pos + 1);
    }

    shared_ptr<node> next{};
    if (name == "..") {
        if (current->parent.expired()) {
            kfree(symlink_buf);
            return {};
        }

        next = current->parent.lock();
    } else if (name == '/') {
        next = current;
    } else {
        next = current->find_child(name);
        if (!next) {
            auto fs = current->fs.lock();
            if (fs) {
                auto res = fs->lookup(current, name);
                if (!res.expired()) {
                    next = res.lock();
                }
            }
        }

        if (!next || next->resolveable == false) {
            kfree(symlink_buf);
            return {};
        }
    }
    
    switch (next->type) {
        case node::type::DIRECTORY:
            kfree(symlink_buf);
            return next;
        case node::type::SYMLINK: {
            if (!follow_symlink) {
                return next;
            }

            if (!next->meta || next->meta->st_size == 0) {
                return {};
            }

            if (symlinks_traversed + 1 > 40) {
                return {};
            }

            if (symlink_buf == nullptr) symlink_buf = (char *) kmalloc(8192);

            auto fs = next->fs.lock();

            if (fs) {
                memset(symlink_buf, 0, 8192);
                fs->read(next, symlink_buf, next->meta->st_size, 0);
                next = resolve_at(symlink_buf, current, symlinks_traversed);
                if (!next) {
                    kfree(symlink_buf);
                    return {};
                }
            }

            kfree(symlink_buf);
            return next;
        }

        default:
            kfree(symlink_buf);
            return next;
    }
}

ssize_t vfs::lseek(shared_ptr<fd> fd, off_t off, size_t whence) {
    auto desc = fd->desc;
    if (!desc->node) return -ENOTSUP;
    if (desc->node->type == node::type::DIRECTORY) {
        return -EISDIR;
    }

    if (desc->node->type == node::type::SOCKET) {
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

ssize_t vfs::read(shared_ptr<fd> fd, void *buf, size_t len) {
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

    if (desc->node->type == node::type::DIRECTORY) {
        return -EISDIR;
    }

    auto fs = desc->node->fs.lock();
    if (fs) {
        auto res = fs->read(desc->node, buf, len, desc->pos);
        if (res >= 0) desc->pos += res;
        return res;    
    }

    return -EBADF;
}

ssize_t vfs::write(shared_ptr<fd> fd, void *buf, size_t len) {
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

    if (desc->node->type == node::type::DIRECTORY) {
        return -EISDIR;
    }

    auto fs = desc->node->fs.lock();
    if (fs) {
        auto res = fs->write(desc->node, buf, len, desc->pos);
        if (res >= 0) desc->pos += res;
        return res;    
    }

    return -EBADF;
}

ssize_t vfs::ioctl(shared_ptr<fd> fd, size_t req, void *buf) {
    auto desc = fd->desc;
    auto fs = desc->node->fs.lock();
    if (fs) {
        return fs->ioctl(desc->node, req, buf);
    }

    return -EBADF;
}

ssize_t vfs::poll(pollfd *fds, nfds_t nfds, shared_ptr<fd_table> table, sched::timespec *timespec) {
    frg::vector<shared_ptr<descriptor>, memory::mm::heap_allocator> desc_list{};
    for (size_t i = 0; i < nfds; i++) {
        auto pollfd = &fds[i];
        auto fd = table->fd_list[pollfd->fd];

        if (!fd) {
            arch::set_errno(EBADF);
            return - 1;
        }

        auto desc = fd->desc;
        desc_list.push(desc);
    }

    while (true) {
        for (size_t i = 0; i < desc_list.size(); i++) {
            auto desc = desc_list[i];

            shared_ptr<pipe> pipe{};
            shared_ptr<node> file{};

            ssize_t status = 0;
            if (!desc->node) {
                pipe = desc->pipe;
                if (desc == pipe->write && pipe->read) {
                    fds[i].revents = POLLERR & fds[i].revents;
                    continue;
                } else if (desc == pipe->read && pipe->write) {
                    fds[i].revents = POLLHUP & fds[i].revents;
                    continue;
                }

                // TODO: find a more efficient way to do this0
                while (__atomic_load_n(&pipe->data_written, __ATOMIC_RELAXED) == 0);

                fds[i].revents = (POLLIN | POLLOUT) & fds[i].revents;
                return 1;
            } else {
                file = desc->node;

                switch (file->type) {
                    case node::type::CHARDEV: break;
                    case node::type::SOCKET: break;
                    case node::type::FIFO: break;
                    default: {
                        fds[i].revents = (POLLIN | POLLOUT) & fds[i].revents;
                        return 1;
                    }
                }
                
                if (!desc->node->fs.expired()) {
                    auto fs = desc->node->fs.lock();
                    status = fs->poll(file, arch::get_thread());
                }
            }

            if (status < 0) {
                return -1;
            }
            
            if (status & fds[i].events) {
                fds[i].revents = status & fds[i].events;
                return 1;
            }
        }
    }

    return 0;    
}

vfs::path vfs::get_abspath(shared_ptr<node> node) {
    shared_ptr<vfs::node> current = node;
    vfs::path path{};
    while (current) {
        path += '/';
        path += current->name;

        current = current->parent.lock();
    }

    return path;
}

weak_ptr<vfs::node> vfs::get_parent(shared_ptr<node> base, frg::string_view filepath) {
    if (filepath[0] == '/' && filepath.count('/') == 1) {
        return tree_root;
    }

    auto parent_path = filepath;
    if (parent_path.find_last('/') != size_t(-1))
        parent_path = parent_path.sub_string(0, parent_path.find_last('/'));

    auto parent = resolve_at(parent_path, base);
    if (!parent) {
        return {};
    }

    return parent;
}

ssize_t vfs::create(shared_ptr<node> base, frg::string_view filepath, shared_ptr<fd_table> table, int64_t type, int64_t flags, mode_t mode,
    uid_t uid, gid_t gid) {
    auto res = get_parent(base, filepath);
    if (res.expired()) {
        return -ENOENT;
    }

    auto parent = res.lock();
    if (parent->type != node::type::DIRECTORY) {
        return -EINVAL;
    }

    auto name = find_name(filepath);
    if (!parent->fs.expired()) {
        auto fs = parent->fs.lock();
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

        return err;
    }

    return -EBADF;
}

shared_ptr<vfs::fd_table> vfs::make_table() {
    auto table = smarter::allocate_shared<fd_table>(memory::mm::heap);
    table->last_fd = 0;

    return table;
}

shared_ptr<vfs::fd_table> vfs::copy_table(shared_ptr<fd_table> table) {
    auto new_table = make_table();
    new_table->last_fd = table->last_fd;

    for (auto [fd_number, fd]: table->fd_list) {
        if (!fd) continue;
        auto desc = fd->desc;

        auto new_desc = smarter::allocate_shared<descriptor>(memory::mm::heap);
        auto new_fd = smarter::allocate_shared<vfs::fd>(memory::mm::heap);

        new_desc->node = desc->node;
        new_desc->pipe = desc->pipe;

        new_desc->ref = 1;
        new_desc->pos = desc->pos;
        new_desc->info = desc->info;

        new_desc->current_ent = 0;
        new_desc->dirent_list = frg::vector<dirent *, memory::mm::heap_allocator>();

        new_fd->desc = new_desc;
        new_fd->table = new_table;
        new_fd->fd_number = fd_number;
        new_fd->flags = fd->flags;
        new_fd->mode = fd->mode;

        new_table->fd_list[fd->fd_number] = new_fd;
    }

    return new_table;
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

shared_ptr<vfs::node>  vfs::make_recursive(shared_ptr<node> base, frg::string_view path, int64_t type, mode_t mode) {
    frg::string_view view = path;
    ssize_t next_slash;

    shared_ptr<node> current_node = base;
    while ((next_slash = view.find_first('/')) != -1) {
        auto pos = next_slash == -1 ? view.size() : next_slash;

        if (auto c = view.sub_string(0, pos); c.size()) {
            if (auto child = current_node->find_child(c.data())) {
                if (child->type != node::type::DIRECTORY) return nullptr;
                current_node = child;
            } else {
                shared_ptr<node> next = smarter::allocate_shared<node>(memory::mm::heap, base->fs, c.data(), current_node, 0, node::type::DIRECTORY);

                next->meta->st_uid = current_node->meta->st_uid;
                next->meta->st_gid = current_node->meta->st_gid;
                next->meta->st_mode = current_node->meta->st_mode;
                
                current_node->children.push_back(next);
                current_node = next;
            }
        }

        view = view.sub_string(pos + 1);
    }

    shared_ptr<node> next = smarter::allocate_shared<node>(memory::mm::heap, base->fs, view.data() + view.find_last('/') + 1, current_node, 0, type);
    next->meta->st_uid = current_node->meta->st_uid;
    next->meta->st_gid = current_node->meta->st_gid;
    next->meta->st_mode = (current_node->meta->st_mode & (~S_IFDIR)) | type2mode(type);

    current_node->children.push_back(next);

    return next;
}

shared_ptr<vfs::filesystem> vfs::device_fs() {
    return stored_devfs;
}

shared_ptr<vfs::fd> vfs::make_fd(shared_ptr<vfs::node> node, shared_ptr<vfs::fd_table> table, int64_t flags, mode_t mode) {
    auto desc = smarter::allocate_shared<vfs::descriptor>(memory::mm::heap);
    auto fd = smarter::allocate_shared<vfs::fd>(memory::mm::heap);

    desc->node = node;
    desc->pipe = nullptr;

    desc->ref = 1;
    desc->pos= 0;

    desc->info = nullptr;

    desc->current_ent = 0;
    desc->dirent_list = frg::vector<dirent *, memory::mm::heap_allocator>();

    fd->desc = desc;
    fd->table = table;
    fd->fd_number = table->last_fd++;
    fd->flags = flags;
    fd->mode = mode;

    if (node && !node->fs.expired()) {
        auto fs = node->fs.lock();
        auto open_val = fs->on_open(fd, flags);
        if (open_val != -ENOTSUP && open_val < 0) {
            return {};
        }
    }

    util::lock_guard table_guard{table->lock};
    table->fd_list[fd->fd_number] = fd;

    return fd;
}

shared_ptr<vfs::fd> vfs::open(shared_ptr<node> base, frg::string_view filepath, shared_ptr<fd_table> table, int64_t flags, mode_t mode,
    uid_t uid, gid_t gid) {
    if (!table) {
        return {};
    }

    auto node = resolve_at(filepath, base);
    if (!node) {
        if (flags & O_CREAT && table) {
            auto err = create(base, filepath, table, vfs::node::type::FILE, flags, mode, uid, gid);
            if (err <= 0) {
                return {};
            }
        } else {
            return {};
        }
    }

    return make_fd(node, table, flags, mode);
}

vfs::fd_pair vfs::open_pipe(shared_ptr<fd_table> table, ssize_t flags) {
    auto read = make_fd(nullptr, table, flags, O_RDONLY);
    auto write = make_fd(nullptr, table, flags, O_WRONLY);

    auto pipe = smarter::allocate_shared<vfs::pipe>(memory::mm::heap);
    pipe->read = read->desc;
    pipe->write = write->desc;
    pipe->len = memory::page_size;
    pipe->buf = kmalloc(memory::page_size);
    pipe->data_written = false;

    auto stat = smarter::allocate_shared<node::statinfo>(memory::mm::heap);
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

shared_ptr<vfs::fd> vfs::dup(shared_ptr<vfs::fd> fd, bool cloexec, ssize_t new_num) {
    if (!fd) {
        return {};
    }

   if (fd->fd_number == new_num) {
        return fd;
    }

    fd->desc->ref++;

    if (!fd->table.expired()) {
        auto table = fd->table.lock();
        auto new_fd = table->fd_list[new_num];
        if (new_num >= 0 && new_fd) {
            close(new_fd);
        }
    
        new_fd = smarter::allocate_shared<vfs::fd>(memory::mm::heap);
        new_fd->desc = fd->desc;
        new_fd->table = fd->table;
        if (new_num >= 0) {
            new_fd->fd_number = new_num;
        } else {
            new_fd->fd_number = table->last_fd++;
        }
    
        new_fd->flags = cloexec ? fd->flags | O_CLOEXEC : fd->flags & ~O_CLOEXEC;
        new_fd->mode = fd->mode;

        util::lock_guard table_guard{table->lock};
        table->fd_list[new_fd->fd_number] = new_fd;
    
        return new_fd;
    }

    return {};
}

ssize_t vfs::stat(shared_ptr<node> dir, frg::string_view filepath, node::statinfo *buf, int64_t flags) {
    auto node = resolve_at(filepath, dir, !(flags & AT_SYMLINK_NOFOLLOW));
    if (!node) {
        return -ENOENT;
    }

    memcpy(buf, node->meta.get(), sizeof(node::statinfo));
    return 0;
}

ssize_t vfs::close(shared_ptr<fd> fd) {
    auto desc = fd->desc;
    desc->ref--;

    if (desc->node && !desc->node->fs.expired()) {
        auto fs = desc->node->fs.lock();
        fs->on_close(fd, fd->flags);

        if (desc->node.use_count() == 1 && desc->node->delete_on_close) {
            fs->remove(desc->node);
        }
    }

    if (!fd->table.expired()) {
        auto table = fd->table.lock();
        table->fd_list.remove(fd->fd_number);
        if (fd->fd_number <= table->last_fd) {
            table->last_fd = fd->fd_number;
        }
    
        if (desc->ref <= 0) {
            for (auto dirent: desc->dirent_list) {
                if (dirent == nullptr) continue;
                frg::destruct(memory::mm::heap, dirent);
            }
        }
    
        return 0;
    }

    return -EBADF;
}

ssize_t vfs::mkdir(shared_ptr<node> base, frg::string_view dirpath, int64_t flags, mode_t mode,
    uid_t uid, gid_t gid) {
    auto dst = resolve_at(dirpath, base);
    if (dst) {
        switch (base->type) {
            case node::type::DIRECTORY:
                return -EISDIR;
            default:
                return -EEXIST;
        }
    }

    auto res = get_parent(base, dirpath);
    if (res.expired()) {
        return -ENOTDIR;
    }

    auto parent = res.lock();
    if (!parent->fs.expired()) {
        auto fs = parent->fs.lock();
        return fs->mkdir(parent, find_name(dirpath), flags, mode, uid, gid);
    }

    return -EBADF;
}

ssize_t vfs::rename(shared_ptr<node> old_base, frg::string_view oldpath, shared_ptr<node> new_base, frg::string_view newpath, int64_t flags) {
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
        if (dst->fs.expired() || src->fs.expired()) {
            return -EBADF;
        }

        auto dst_fs = dst->fs.lock();
        auto src_fs = src->fs.lock();
        if (dst_fs != src_fs) {
            return -EXDEV;
        }

        switch (dst->type) {
            case node::type::SOCKET:
            case node::type::BLOCKDEV:
            case node::type::CHARDEV:
                return -EINVAL;
            default:
                break;
        }

        if (dst->type == node::type::DIRECTORY && src->type == node::type::DIRECTORY) {
            if (dst->children.size()) {
                return -ENOTEMPTY;
            }
        }

        if (dst->type != src->type) {
                return -EINVAL;
        }
    } else if (resolve_fs(newpath, new_base).lock() != src->fs.lock()) {
        return -EXDEV;
    }

    if (src->fs.expired()) {
        return -EBADF;
    }

    auto src_fs = src->fs.lock();
    src_fs->rename(src, dst, name, flags);
    return 0;
}

// TODO: adding a symlink
ssize_t vfs::link(shared_ptr<node> from_base, frg::string_view from, shared_ptr<node> to_base, frg::string_view to, bool is_symlink) {
    if (from == to) {
        return -EINVAL;
    }

    auto src = resolve_at(from, from_base);

    auto dst = resolve_at(to, to_base);
    auto dst_name = find_name(to);
    auto dst_parent = get_parent(to_base, to);
    
    auto dst_res = resolve_fs(to, to_base);
    if (dst || dst_res.expired()) {
        return -EINVAL;
    }

    if (src->fs.expired()) {
        return -EINVAL;
    }

    auto dst_fs = dst_res.lock();
    auto src_fs = src->fs.lock();
    if (dst_fs!= src_fs) {
        return -EINVAL;
    }

    auto link_dst = smarter::allocate_shared<node>(memory::mm::heap, src->fs, dst_name, dst_parent, 0, src->type, src->inum);
    auto err = dst_fs->link(src, link_dst, dst_name, false);
    if (err < 0) {
        return err;
    }

    auto parent = dst_parent.lock();
    parent->children.push_back(link_dst);
    return 0;
}

ssize_t vfs::unlink(shared_ptr<node> base, frg::string_view filepath) {
    auto node = resolve_at(filepath, base);
    if (!node || node->type == node::type::DIRECTORY) {
        return -EINVAL;
    }

    if (node->fs.expired()) {
        return -EBADF;
    }

    auto fs = node->fs.lock();
    auto err = fs->unlink(node);
    if (err < 0) {
        return err;
    }

    node->resolveable = false;
    node->delete_on_close = true;
    if (node.use_count() == 1) {
        if (node->parent.expired()) {
            return -EBADF;
        }

        auto parent = node->parent.lock();
        for (size_t i = 0; i < parent->children.size(); i++) {
            auto child = parent->children[i];
            if (!child) continue;
            if (child->name == node->name) {
                parent->children.erase(child);
                break;
            }
        }

        fs->remove(node);
    }

    return 0;
}

ssize_t vfs::rmdir(shared_ptr<node> base, frg::string_view dirpath) {
    auto dst = resolve_at(dirpath, base);
    if (!dst || dst->type != node::type::DIRECTORY || dst->children.size() > 0) {
        return -EINVAL;
    }

    if (dst->fs.expired()) {
        return -EBADF;
    }

    auto fs = dst->fs.lock();
    auto err = fs->remove(dst);
    if (err < 0) {
        return err;
    }

    return 0;
}

vfs::pathlist vfs::readdir(shared_ptr<node> base, frg::string_view dirpath) {
    auto dst = resolve_at(dirpath, base);
    if (!dst || dst->type != node::type::DIRECTORY) {
        return {};
    }

    if (dst->fs.expired()) {
        return {};
    }

    auto fs = dst->fs.lock();

    auto err = fs->readdir(dst);
    if (err < 0) {
        return {};
    }

    auto paths = pathlist();
    for (auto child: dst->children) {
        if (!child) continue;
        paths.push(child->name);
    }

    return paths;
}

ssize_t vfs::mount(frg::string_view srcpath, frg::string_view dstpath, ssize_t fstype, int64_t flags) {
    auto src = resolve_at(srcpath, nullptr);
    auto dst = resolve_at(dstpath, nullptr);

    switch (flags) {
        case (mflags::NOSRC | mflags::NODST):
        case mflags::NODST:
        case mflags::NOSRC: {
            switch (fstype) {
                case fslist::ROOTFS: {
                    if (tree_root) {
                        return -ENOTEMPTY;
                    }

                    // weak_ptr<filesystem> fs, path name, weak_ptr<node> parent, ssize_t flags, ssize_t type
                    auto root = smarter::allocate_shared<node>(memory::mm::heap, nullptr, "/", nullptr, 0, node::type::DIRECTORY);
                    auto fs = smarter::allocate_shared<rootfs>(memory::mm::heap, root);
                    
                    fs->selfPtr = fs;
                    root->fs = fs;
                    tree_root = root;
                    mounts["/"] = fs;
                    break;
                }

                case fslist::DEVFS: {
                    if (!dst) {
                        return -EINVAL;
                    }

                    if (dst->type != node::type::DIRECTORY) {
                        return -EINVAL;
                    }

                    if (dst->children.size() > 0) {
                        return -EINVAL;
                    }

                    auto fs = smarter::allocate_shared<devfs>(memory::mm::heap, dst);

                    fs->selfPtr = fs;
                    dst->fs = fs;

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

                    if (dst->type != node::type::DIRECTORY || src->type != node::type::BLOCKDEV) {
                        kmsg(logger, "invalid source device or dest; dst: %ld, src: %ld", dst->type, src->type);

                        return -EINVAL;
                    }

                    auto fs = smarter::allocate_shared<ext2fs>(memory::mm::heap, dst, src);
                    fs->selfPtr = fs;
                    if (!fs->load()) {
                        return -EINVAL;
                    }

                    dst->fs = fs;
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
ssize_t vfs::umount(shared_ptr<node> dst) {
    if (!dst || dst->fs.expired()) {
        return -EINVAL;
    }

    auto fs = dst->fs.lock();
    if (dst.use_count()) {
        return -EBUSY;
    }

    return 0;
}