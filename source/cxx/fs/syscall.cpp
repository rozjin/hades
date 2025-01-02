/*
    vfs::fd *open(frg::string_view filepath, fd_table *table, int64_t flags, int64_t mode);
    fd_pair open_pipe(fd_table *table, ssize_t flags);
    ssize_t lseek(vfs::fd *fd, size_t off, size_t whence);
    vfs::fd *dup(vfs::fd *fd, ssize_t flags, ssize_t new_num);
    ssize_t close(vfs::fd *fd);
    ssize_t read(vfs::fd *fd, void *buf, ssize_t len);
    ssize_t write(vfs::fd *fd, void *buf, ssize_t len);
    ssize_t ioctl(vfs::fd *fd, size_t req, void *buf);
    void *mmap(vfs::fd *fd, void *addr, ssize_t off, ssize_t len);
    ssize_t lstat(frg::string_view filepath, node::statinfo *buf);
    ssize_t create(frg::string_view filepath, fd_table *table, int64_t type, int64_t flags, int64_t mode);
    ssize_t mkdir(frg::string_view dirpath, int64_t flags, int64_t mode);
    ssize_t rename(frg::string_view oldpath, frg::string_view newpath, int64_t flags);
    ssize_t link(frg::string_view from, frg::string_view to, bool is_symlink);
    ssize_t unlink(frg::string_view filepath);
    ssize_t rmdir(frg::string_view dirpath);
    pathlist lsdir(frg::string_view dirpath);
 */

#include <frg/string.hpp>
#include <mm/mm.hpp>
#include <sys/sched/sched.hpp>
#include <cstddef>
#include <fs/vfs.hpp>
#include <arch/types.hpp>
#include <arch/x86/types.hpp>

vfs::node *resolve_dirfd(int dirfd, frg::string_view path, sched::process *process) {
    bool is_relative = path == '/';
    if (is_relative) {
        if (dirfd == AT_FDCWD) {
            return process->cwd;
        }

        auto fd = process->fds->fd_list[dirfd];
        if (fd == nullptr || !fd->desc->node || fd->desc->node->type != vfs::node::type::DIRECTORY) {
            arch::set_errno(EBADF);

            return nullptr;
        }
    }

    return vfs::tree_root;
}

void make_dirent(vfs::node *dir, vfs::node *child, dirent *entry) {
    strcpy(entry->d_name, child->name.data());

    entry->d_ino = child->inum;
    entry->d_off = 0;
    entry->d_reclen = sizeof(dirent);

    switch (child->type) {
        case vfs::node::type::FILE:
            entry->d_type = DT_REG;
            break;
        case vfs::node::type::DIRECTORY:
            entry->d_type = DT_DIR;
            break;
        case vfs::node::type::BLOCKDEV:
            entry->d_type = DT_BLK;
            break;
        case vfs::node::type::CHARDEV:
            entry->d_type = DT_CHR;
            break;
        case vfs::node::type::SOCKET:
            entry->d_type = DT_SOCK;
            break;
        case vfs::node::type::SYMLINK:
            entry->d_type = DT_LNK;
            break;
        default:
            entry->d_type = DT_UNKNOWN;
    }
}

void syscall_openat(arch::irq_regs *r) {
    int dirfd = r->rdi;
    const char *path = (const char *) r->rsi;
    int flags = r->rdx;
    int mode = r->r10;

    auto process = arch::get_process();
    auto dir = resolve_dirfd(dirfd, path, process);
    if (dir == nullptr) {
        r->rax = -1;
        return;
    }

    auto node = vfs::resolve_at(path, dir);
    if (flags & O_CREAT && node == nullptr) {
        auto res = vfs::create(dir, path, process->fds, vfs::node::type::FILE, flags, mode);
        if (res < 0) {
            arch::set_errno(-res);
            r->rax = -1;
            return;
        }
    } else if ((flags & O_CREAT) && (flags & O_EXCL)) {
        arch::set_errno(EEXIST);
        r->rax = -1;
        return;
    } else if (node == nullptr) {
        arch::set_errno(ENOENT);
        r->rax = -1;
        return;
    }

    if (!(flags & O_DIRECTORY) && node->type == vfs::node::type::DIRECTORY) {
        arch::set_errno(EISDIR);
        r->rax = -1;
        return;
    }

    if ((flags & O_TRUNC)) {
        auto res = node->fs->truncate(node, 0);
        if (res < 0) {
            arch::set_errno(-res);
            r->rax = -1;
            return;
        }
    }

    auto fd = vfs::open(dir, path, process->fds, flags, mode);
    if (fd == nullptr) {
        r->rax = -1;
        return;
    }

    r->rax = fd->fd_number;
}

void syscall_pipe(arch::irq_regs *r) {
    int *fd_nums = (int *) r->rdi;

    auto process = arch::get_process();
    process->fds->lock.irq_acquire();

    auto [fd_read, fd_write] = vfs::open_pipe(process->fds, 0);

    fd_nums[0] = fd_read->fd_number;
    fd_nums[1] = fd_write->fd_number;

    process->fds->lock.irq_release();
    r->rax = 0;   
}

void syscall_lseek(arch::irq_regs *r) {
    off_t offset = r->rsi;
    size_t whence = r->rdx;

    auto process = arch::get_process();

    process->fds->lock.irq_acquire();
    auto fd = process->fds->fd_list[r->rdi];
    if (fd == nullptr) {
        arch::set_errno(ESPIPE);
        process->fds->lock.irq_release();
        r->rax = -1;
        return;
    }

    fd->lock.irq_acquire();
    r->rax = vfs::lseek(fd, offset, whence);
    fd->lock.irq_release();
    process->fds->lock.irq_release();
}

void syscall_dup2(arch::irq_regs *r) {
    int oldfd_num = r->rdi;
    int newfd_num = r->rsi;

    auto process = arch::get_process();

    auto oldfd = process->fds->fd_list[oldfd_num];
    if (oldfd == nullptr) {
        arch::set_errno(EBADF);
        r->rax = -1;
        return;
    }

    oldfd->lock.irq_acquire();
    auto newfd = vfs::dup(oldfd, false, newfd_num);
    oldfd->lock.irq_release();

    r->rax = newfd->fd_number;
}

void syscall_close(arch::irq_regs *r) {
    int fd_number = r->rdi;
    auto process = arch::get_process();

    process->fds->lock.irq_acquire();
    auto fd = process->fds->fd_list[fd_number];
    if (fd == nullptr) {
        arch::set_errno(EBADF);
        process->fds->lock.irq_release();
        r->rax = -1;
        return;
    }

    vfs::close(fd);
    process->fds->lock.irq_release();
    r->rax = 0;
}

void syscall_read(arch::irq_regs *r) {
    int fd_number = r->rdi;
    void *buf = (void *) r->rsi;
    size_t count = r->rdx;

    auto process = arch::get_process();
    
    process->fds->lock.irq_acquire();
    auto fd = process->fds->fd_list[fd_number];
    if (fd == nullptr) {
        arch::set_errno(EBADF);
        process->fds->lock.irq_release();
        r->rax = -1;
        return;        
    }

    fd->lock.irq_acquire();
    if (fd->desc->node) {
        fd->desc->node->lock.irq_acquire();
    }

    r->rax = vfs::read(fd, buf, count);

    if (fd->desc->node) {
        fd->desc->node->lock.irq_release();
    }
    fd->lock.irq_release();
    process->fds->lock.irq_release();
}

void syscall_write(arch::irq_regs *r) {
    int fd_number = r->rdi;
    void *buf = (void *) r->rsi;
    size_t count = r->rdx;

    auto process = arch::get_process();
    
    process->fds->lock.irq_acquire();
    auto fd = process->fds->fd_list[fd_number];
    if (fd == nullptr) {
        arch::set_errno(EBADF);
        process->fds->lock.irq_release();
        r->rax = -1;
        return; 
    }

    fd->lock.irq_acquire();
    if (fd->desc->node) {
        fd->desc->node->lock.irq_acquire();
    }

    r->rax = vfs::write(fd, buf, count);

    if (fd->desc->node) {
        fd->desc->node->lock.irq_release();
    }
    fd->lock.irq_release();
    process->fds->lock.irq_release();
}

void syscall_ioctl(arch::irq_regs *r) {
    int fd_number = r->rdi;
    size_t req = r->rsi;
    void *arg = (void *) r->rdx;

    auto process = arch::get_process();
    
    process->fds->lock.irq_acquire();
    auto fd = process->fds->fd_list[fd_number];
    if (fd == nullptr) {
        arch::set_errno(EBADF);
        process->fds->lock.irq_release();
        r->rax = -1;
        return; 
    }

    fd->lock.irq_acquire();
    if (fd->desc->node) {
        fd->desc->node->lock.irq_acquire();
    }

    auto res = vfs::ioctl(fd, req, arg);
    if (res < 0) {
        arch::set_errno(-res);
        r->rax = -1;
    } else {
        r->rax = res;
    }

    if (fd->desc->node) {
        fd->desc->node->lock.irq_release();
    }
    fd->lock.irq_release();
    process->fds->lock.irq_release();
}

void syscall_statat(arch::irq_regs *r) {
    int dirfd = r->rdi;
    const char *path = (const char *) r->rsi;
    void *buf = (void *) r->rdx;
    int flags = r->r10;

    auto process = arch::get_process();
    auto dir = resolve_dirfd(dirfd, path, process);

    if (!strlen(path) && !(flags & AT_EMPTY_PATH)) {
        arch::set_errno(ENOENT);
        r->rax = -1;
        return;
    }

    vfs::node *node;
    if (flags & AT_EMPTY_PATH) {
        if (dir == nullptr) {
            arch::set_errno(EBADF);
            r->rax = -1;
            return;
        }

        node = dir;
    } else {
        node = vfs::resolve_at(path, dir);
        if (node == nullptr) {
            arch::set_errno(EBADF);
            r->rax = -1;
            return;;
        }
    }

    arch::copy_to_user(buf, node->meta, sizeof(vfs::node::statinfo));
    r->rax = 0;
}

void syscall_mkdirat(arch::irq_regs *r) {
    int dirfd = r->rdi;
    const char *path = (const char *) r->rsi;
    int mode = r->rdx;

    auto process = arch::get_process();
    auto dir = resolve_dirfd(dirfd, path, process);
    if (dir == nullptr) {
        r->rax = -1;
        return;
    }
    
    dir->lock.irq_acquire();
    auto res = vfs::mkdir(dir, path, 0, mode);
    dir->lock.irq_release();

    if (res < 0) {
        arch::set_errno(-res);
        r->rax = -1;
        return;
    }

    r->rax = 0;
}

void syscall_renameat(arch::irq_regs *r) {
    int old_dirfd_num = r->rdi;
    const char *old_path = (char *) r->rsi;
    int new_dirfd_num = r->rdx;
    const char *new_path = (char *) r->r10;
    
    auto process = arch::get_process();
    auto old_dir = resolve_dirfd(old_dirfd_num, old_path, process);
    if (old_dir == nullptr) {
        r->rax = -1;
        return;
    }

    auto new_dir = resolve_dirfd(new_dirfd_num, new_path, process);
    if (new_dir == nullptr) {
        r->rax = -1;
        return;
    }

    auto src = resolve_at(old_path, old_dir);
    if (!src) {
        arch::set_errno(EACCES);
        r->rax = -1;
        return;
    }

    auto dst = resolve_at(new_path, new_dir);

    old_dir->lock.irq_acquire();
    new_dir->lock.irq_acquire();

    src->lock.irq_acquire();
    if (dst) {
        dst->lock.irq_acquire();
    }

    auto res = vfs::rename(old_dir, old_path, new_dir, new_path, 0);

    old_dir->lock.irq_release();
    new_dir->lock.irq_release();
    if (dst) {
        dst->lock.irq_release();
    }
    src->lock.irq_release();
    
    if (res < 0) {
        arch::set_errno(-res);
        r->rax = -1;
        return;
    }

    r->rax = 0;
}

void syscall_linkat(arch::irq_regs *r) {
    int old_dirfd_num = r->rdi;
    const char *old_path = (char *) r->rsi;
    int new_dirfd_num = r->rdx;
    const char *new_path = (char *) r->r10;
    
    auto process = arch::get_process();
    auto old_dir = resolve_dirfd(old_dirfd_num, old_path, process);
    if (old_dir == nullptr) {
        r->rax = -1;
        return;
    }

    auto new_dir = resolve_dirfd(new_dirfd_num, new_path, process);
    if (new_dir == nullptr) {
        r->rax = -1;
        return;
    }

    auto src = resolve_at(old_path, old_dir);
    if (!src) {
        arch::set_errno(ENOENT);
        r->rax = -1;
        return;
    }

    auto dst = resolve_at(new_path, new_dir);
    if (dst) {
        arch::set_errno(EEXIST);
        r->rax = -1;
        return;
    }

    old_dir->lock.irq_acquire();
    new_dir->lock.irq_acquire();

    src->lock.irq_acquire();

    auto res = vfs::link(old_dir, old_path, new_dir, new_path, false);

    old_dir->lock.irq_release();
    new_dir->lock.irq_release();

    src->lock.irq_release();
    
    if (res < 0) {
        arch::set_errno(-res);
        r->rax = -1;
        return;
    }

    r->rax = 0;
}

void syscall_unlinkat(arch::irq_regs *r) {
    int dirfd_num = r->rdi;
    const char *path = (char *) r->rsi;

    auto process = arch::get_process();
    auto dir = resolve_dirfd(dirfd_num, path, process);
    if (dir == nullptr) {
        r->rax = -1;
        return;
    }

    auto node = vfs::resolve_at(path, dir);
    if (node == nullptr) {
        arch::set_errno(ENOENT);
        r->rax = -1;
        return;
    }

    dir->lock.irq_acquire();
    node->lock.irq_acquire();

    auto res = vfs::unlink(dir, path);

    node->lock.irq_release();
    dir->lock.irq_release();

    if (res < 0) {
        arch::set_errno(-res);
        r->rax = -1;
        return;
    }

    r->rax = 0;
}

void syscall_readdir(arch::irq_regs *r) {
    int fd_number = r->rdi;
    dirent *ents = (dirent *) r->rsi;

    auto process = arch::get_process();

    process->fds->lock.irq_acquire();
    auto fd = process->fds->fd_list[fd_number];
    if (fd == nullptr || fd->desc->node == nullptr || fd->desc->node->type != vfs::node::type::DIRECTORY) {
        arch::set_errno(EBADF);
        process->fds->lock.irq_release();
        r->rax = 1;
        return;
    }

    fd->lock.irq_acquire();
    auto node = fd->desc->node;
    node->lock.irq_acquire();

    if ((node->children.size() >= fd->desc->current_ent) && node->children.size() != fd->desc->dirent_list.size()) {
        for (auto dirent: fd->desc->dirent_list) {
            if (dirent == nullptr) continue;
            frg::destruct(memory::mm::heap, dirent);
        }

        fd->desc->dirent_list.clear();
        fd->desc->current_ent = 0;
    }

    if (!fd->desc->dirent_list.size()) {
        for (size_t i = 0; i < node->children.size(); i++) {
            auto child = node->children[i];
            if (child ==  nullptr) {
                node->lock.irq_release();
                fd->lock.irq_release();

                r->rax = -1;
                return;
            }

            auto entry = frg::construct<dirent>(memory::mm::heap);
            make_dirent(node, child, entry);
            fd->desc->dirent_list.push_back(entry);
        }
    }

    if (fd->desc->current_ent >= fd->desc->dirent_list.size()) {
        arch::set_errno(0);
        node->lock.irq_release();
        fd->lock.irq_release();

        r->rax = -1;
        return;
    }

    *ents = *fd->desc->dirent_list[fd->desc->current_ent];
    
    node->lock.irq_release();
    fd->lock.irq_release();

    r->rax = 0;
    return;
}

void syscall_fcntl(arch::irq_regs *r) {
    auto process = arch::get_process();
    auto fd = process->fds->fd_list[r->rdi];

    if (fd == nullptr) {
        arch::set_errno(EBADF);
        r->rax = -1;
        return;
    }

    switch(r->rsi) {
        case F_DUPFD: {
            auto new_fd = vfs::dup(fd, false, -1);
            r->rax = new_fd->fd_number;
            break;
        }

        case F_DUPFD_CLOEXEC: {
            auto new_fd = vfs::dup(fd, true, -1);
            r->rax = new_fd->fd_number;
            break;
        }

        case F_GETFD: {
            fd->lock.irq_acquire();
            r->rax = fd->flags;
            fd->lock.irq_release();
            break;
        }

        case F_SETFD: {
            fd->lock.irq_acquire();
            fd->flags = r->rdx;
            r->rax = 0;
            fd->lock.irq_release();
            break;
        }

        case F_GETFL: {
            if (!fd->desc->node) {
                arch::set_errno(EBADF);
                r->rax = -1;
                return;
            }

            fd->desc->node->lock.irq_acquire();
            r->rax = fd->desc->node->flags;
            fd->desc->node->lock.irq_release();
            break;
        }

        case F_SETFL: {
            if (!fd->desc->node) {
                arch::set_errno(EBADF);
                r->rax = -1;
                return;
            }

            fd->desc->node->lock.irq_acquire();

            fd->desc->node->flags = r->rdx;
            r->rax = 0;

            fd->desc->node->lock.irq_release();
            break;
        }

        default: {
            arch::set_errno(EINVAL);
            r->rax = -1;
        }
    }
}