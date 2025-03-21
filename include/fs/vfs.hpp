#ifndef VFS_HPP
#define VFS_HPP

#include <cstddef>
#include <cstdint>
#include <frg/allocation.hpp>
#include <frg/hash.hpp>
#include <frg/hash_map.hpp>
#include <frg/string.hpp>
#include <frg/vector.hpp>
#include <mm/mm.hpp>
#include <sys/sched/time.hpp>
#include <util/lock.hpp>
#include <util/log/log.hpp>
#include <util/types.hpp>
#include <util/errors.hpp>

namespace sched {
    class process;
    class thread;
}

namespace vfs {
    struct node;
    class filesystem;
    class manager;

    using path = frg::string<memory::mm::heap_allocator>;
    using pathlist = frg::vector<frg::string_view, memory::mm::heap_allocator>;
    using nodelist = frg::vector<node *, memory::mm::heap_allocator>;
    
    struct path_hasher {
        unsigned int operator() (frg::string_view path) {
            return frg::CStringHash{}(path.data());
        }
    };

    inline frg::string_view find_name(frg::string_view path) {
        auto pos = path.find_last('/');
        if (pos == size_t(-1)) {
            return path;
        }

        return path.sub_string(pos + 1);
    }

    struct mflags {
        enum {
            NOSRC = 0x8,
            NODST = 0x4,
        };
    };

    struct fslist {
        enum {
            ROOTFS = 1,
            SYSFS,
            PROCFS,
            DEVFS,
            TMPFS,
            INITRD,
            EXT
        };
    };

    struct fd;
    struct node {
        public:
            struct type {
                enum {
                    FILE = 1,
                    DIRECTORY,
                    BLOCKDEV,
                    CHARDEV,
                    SOCKET,
                    SYMLINK,
                    FIFO
                };
            };

            struct statinfo {
                dev_t st_dev;
                ino_t st_ino;
                mode_t st_mode;
                nlink_t st_nlink;
                uid_t st_uid;
                gid_t st_gid;
                dev_t st_rdev;
                off_t st_size;

                sched::timespec st_atim;
                sched::timespec st_mtim;
                sched::timespec st_ctim;

                blksize_t st_blksize;
                blkcnt_t st_blkcnt;
            };

            void set_fs(filesystem *fs) {
                this->fs = fs;
            } 

            filesystem *get_fs() {
                return fs;
            }

            ssize_t get_type() {
                return type;
            }

            node(filesystem *fs, path name, node *parent, ssize_t flags, ssize_t type, ssize_t inum = -1) : ref_count(), fs(fs), name(name),
            resolveable(true), delete_on_close(false), parent(parent), children(), flags(flags), type(type), lock() {
                if (inum > 0) {
                    this->inum = inum;
                } else {
                    this->inum = parent ? parent->inum++ : 0;
                }

                this->meta = frg::construct<statinfo>(memory::mm::heap);
            };

            vfs::node *find_child(frg::string_view name) {
                for (size_t i = 0; i < children.size(); i++) {
                    if (children[i] == nullptr) continue;
                    if (children[i]->name.eq(name)) return children[i];
                }

                return nullptr;
            }

            ssize_t get_ccount() {
                return children.size();
            }

            void set_parent(node *parent) {
                this->parent = parent;
            }

            node *get_parent() {
                return parent;
            }

            path get_name() {
                return name;
            }

            bool has_access(uid_t uid, gid_t gid, int mode) {
                if (uid == 0) {
                    return true;
                }

                mode_t mask_uid = 0, mask_gid = 0, mask_oth = 0;

                if(mode & R_OK) { mask_uid |= S_IRUSR; mask_gid |= S_IRGRP; mask_oth |= S_IROTH; }
                if(mode & W_OK) { mask_uid |= S_IWUSR; mask_gid |= S_IWGRP; mask_oth |= S_IWOTH; }
                if(mode & X_OK) { mask_uid |= S_IXUSR; mask_gid |= S_IXGRP; mask_oth |= S_IXOTH; }

                if(meta->st_uid == uid) {
                    if((meta->st_mode & mask_uid) == mask_uid) {
                        return true;
                    }

                    return false;
                } else if(meta->st_gid == gid) {
                    if((meta->st_mode & mask_gid) == mask_gid) {
                        return true;
                    }

                    return false;
                } else {
                    if((meta->st_mode & mask_oth) == mask_oth) {
                        return true;
                    }

                    return false;
                }                
            }

            size_t ref_count;
            filesystem *fs;
            statinfo *meta;
            path name;

            bool resolveable;
            bool delete_on_close;

            node *parent;
            void *private_data;
            nodelist children;

            ssize_t inum;
            ssize_t flags;
            ssize_t type;

            util::spinlock lock;
    };

    struct fd;
    struct fd_table;

    class filesystem {
        public:
            node *root;
            node *source;
            nodelist nodes;
            path relpath;

            frg::vector<fd *, memory::mm::heap_allocator> open_fds;

            filesystem() {}

            // TODO: destructor for umount

            void init_as_root(node *root) {
                this->root = root;
                this->source = nullptr;
            }

            virtual void init_fs(node *root, node *source) {
                this->root = root;
                this->source = source;
            }

            virtual node *lookup(node *parent, frg::string_view name) {
                return nullptr;
            }

            virtual ssize_t readdir(node *dir) {
                return -ENOTSUP;
            }

            virtual ssize_t on_open(vfs::fd *fd, ssize_t flags) {
                return -ENOTSUP;
            }

            virtual ssize_t on_close(vfs::fd *fd, ssize_t flags) {
                return -ENOTSUP;
            }

            virtual ssize_t read(node *file, void *buf, size_t len, off_t offset) {
                return -ENOTSUP;
            }

            virtual void *mmap(node *file, void *addr, size_t len, off_t offset) {
                return nullptr;
            }

            virtual ssize_t write(node *file, void *buf, size_t len, off_t offset) {
                return -ENOTSUP;
            }

            virtual ssize_t truncate(node *file, off_t offset) {
                return 0;
            }

            virtual ssize_t ioctl(node *file, size_t req, void *buf) {
                return -ENOTSUP;
            }

            virtual ssize_t poll(vfs::node *file, sched::thread *thread) {
                return -ENOTSUP;
            }

            virtual ssize_t create(node *dst, path name, int64_t type, int64_t flags, mode_t mode,
                uid_t uid, gid_t gid) {
                return -ENOTSUP;
            }

            virtual ssize_t mkdir(node *dst, frg::string_view name, int64_t flags, mode_t mode,
                uid_t uid, gid_t gid) {
                return -ENOTSUP;
            }

            virtual ssize_t rename(node *src, node *dst, frg::string_view name, int64_t flags) {
                return -ENOTSUP;
            }

            virtual ssize_t link(node *src, node *dst, frg::string_view name, bool is_symlink) {
                return -ENOTSUP;
            }

            virtual ssize_t unlink(node *dst) {
                return -ENOTSUP;
            }

            virtual ssize_t remove(node *dst) {
                return -ENOTSUP;
            }
    };

    // TODO: sockets
    struct pipe;
    struct descriptor {
        vfs::node *node;
        vfs::pipe *pipe;

        size_t ref;
        size_t pos;

        node::statinfo *info;

        int current_ent;
        frg::vector<dirent *, memory::mm::heap_allocator> dirent_list;
    };

    struct pipe {
        descriptor *read;
        descriptor *write;
        void *buf;
        size_t len;
        
        bool data_written;
    };

    using fd_pair = frg::tuple<vfs::fd *, vfs::fd *>;

    struct fd {
        util::spinlock lock;
        descriptor *desc;
        fd_table *table;
        int fd_number;
        ssize_t flags;
        ssize_t mode;

        fd(): lock() {};
    };
    
    struct fd_table {
        util::spinlock lock;
        frg::hash_map<int, fd *, frg::hash<int>, memory::mm::heap_allocator> fd_list;
        size_t last_fd;

        fd_table(): lock(), fd_list(frg::hash<int>()) {}
    };

    static size_t zero = 0;
    filesystem *resolve_fs(frg::string_view path, node *base, size_t& symlinks_traversed = zero);
    node *resolve_at(frg::string_view path, node *base, bool follow_symlink = true, size_t& symlinks_traversed = zero);
    path *get_absolute(node *node);
    node *get_parent(node *base, frg::string_view path);

    ssize_t mount(frg::string_view srcpath, frg::string_view dstpath, ssize_t fstype, int64_t flags);
    ssize_t umount(node *dst);

    vfs::fd *open(node *base, frg::string_view filepath, fd_table *table, int64_t flags, mode_t mode,
        uid_t uid, gid_t gid);
    fd_pair open_pipe(fd_table *table, ssize_t flags);

    ssize_t lseek(vfs::fd *fd, off_t off, size_t whence);
    vfs::fd *dup(vfs::fd *fd, bool cloexec, ssize_t new_num);
    ssize_t close(vfs::fd *fd);
    ssize_t read(vfs::fd *fd, void *buf, size_t len);
    ssize_t write(vfs::fd *fd, void *buf, size_t len);
    ssize_t ioctl(vfs::fd *fd, size_t req, void *buf);
    void *mmap(vfs::fd *fd, void *addr, off_t off, size_t len);

    ssize_t poll(pollfd *fds, nfds_t nfds, fd_table *table, sched::timespec *timespec);

    ssize_t stat(node *dir, frg::string_view filepath, node::statinfo *buf, int64_t flags);

    ssize_t create(node *base, frg::string_view filepath, fd_table *table, int64_t type, int64_t flags, mode_t mode,
        uid_t uid, gid_t gid);
    ssize_t mkdir(node *base, frg::string_view dirpath, int64_t flags, mode_t mode,
        uid_t uid, gid_t gid);
    
    ssize_t rename(node *old_base, frg::string_view oldpath, node *new_base, frg::string_view newpath, int64_t flags);
    ssize_t link(node *from_base, frg::string_view from, node *to_base, frg::string_view to, bool is_symlink);
    ssize_t unlink(node *base, frg::string_view filepath);
    ssize_t rmdir(node *base, frg::string_view dirpath);
    pathlist readdir(node *base, frg::string_view dirpath);

    // fs use only
    mode_t type2mode(int64_t type);

    vfs::fd *make_fd(vfs::node *node, fd_table *table, int64_t flags, mode_t mode);
    vfs::node *make_recursive(node *base, frg::string_view path, int64_t type, mode_t mode);
    filesystem *device_fs();

    // sched use
    fd_table *make_table();
    fd_table *copy_table(fd_table *table);
    void delete_table(fd_table *table);

    extern node *tree_root;
    void init();
};

#endif