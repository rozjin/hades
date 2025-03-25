#ifndef VFS_HPP
#define VFS_HPP

#include "smarter/smarter.hpp"
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
        private:
            void init(ssize_t inum) {
                if (inum > 0) {
                    this->inum = inum;
                } else {
                    if (!parent.expired()) {
                        auto new_parent = parent.lock();
                        this->inum = new_parent ? new_parent->inum++ : 0;
                    }
                }

                this->meta = smarter::allocate_shared<statinfo>(memory::mm::heap);                
            }

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

            node(weak_ptr<filesystem> fs, path name, weak_ptr<node> parent, ssize_t flags, ssize_t type, ssize_t inum = -1) : fs(fs), name(name),
                resolveable(true), delete_on_close(false), parent(parent), children(), flags(flags), type(type), lock() {
                init(inum);
            };

            node(std::nullptr_t, path name, std::nullptr_t, ssize_t flags, ssize_t type, ssize_t inum = -1):
                fs(), name(name), resolveable(true), delete_on_close(false), parent(), children(), flags(flags), type(type), lock() {
                init(inum);
            }

            shared_ptr<node> find_child(frg::string_view name) {
                for (size_t i = 0; i < children.size(); i++) {
                    if (children[i]) {
                        if (children[i]->name.eq(name)) return children[i];
                    }
                }

                return {nullptr};
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

            weak_ptr<filesystem> fs;
            shared_ptr<statinfo> meta;
            path name;

            bool resolveable;
            bool delete_on_close;

            weak_ptr<node> parent;
            frg::vector<shared_ptr<node>, memory::mm::heap_allocator> children;

            void *private_data;
            ssize_t inum;
            ssize_t flags;
            ssize_t type;

            util::spinlock lock;
    };

    struct fd;
    struct fd_table;

    class filesystem {
        public:
            shared_ptr<node> root;
            weak_ptr<node> device;

            shared_ptr<filesystem> selfPtr;
            path relpath;

            filesystem(shared_ptr<node> root, weak_ptr<node> device):
                root(root), device(device) {}

            virtual bool load() { return true; };

            virtual weak_ptr<node>lookup(shared_ptr<node> parent, frg::string_view name) {
                return {};
            }

            virtual ssize_t readdir(shared_ptr<node> dir) {
                return -ENOTSUP;
            }

            virtual ssize_t on_open(shared_ptr<fd> fd, ssize_t flags) {
                return -ENOTSUP;
            }

            virtual ssize_t on_close(shared_ptr<fd> fd, ssize_t flags) {
                return -ENOTSUP;
            }

            virtual ssize_t read(shared_ptr<node> file, void *buf, size_t len, off_t offset) {
                return -ENOTSUP;
            }

            virtual void *mmap(shared_ptr<node> file, void *addr, size_t len, off_t offset) {
                return nullptr;
            }

            virtual ssize_t write(shared_ptr<node> file, void *buf, size_t len, off_t offset) {
                return -ENOTSUP;
            }

            virtual ssize_t truncate(shared_ptr<node> file, off_t offset) {
                return 0;
            }

            virtual ssize_t ioctl(shared_ptr<node> file, size_t req, void *buf) {
                return -ENOTSUP;
            }

            virtual ssize_t poll(shared_ptr<node> file, sched::thread *thread) {
                return -ENOTSUP;
            }

            virtual ssize_t create(shared_ptr<node> dst, path name, int64_t type, int64_t flags, mode_t mode,
                uid_t uid, gid_t gid) {
                return -ENOTSUP;
            }

            virtual ssize_t mkdir(shared_ptr<node> dst, frg::string_view name, int64_t flags, mode_t mode,
                uid_t uid, gid_t gid) {
                return -ENOTSUP;
            }

            virtual ssize_t rename(shared_ptr<node> src, shared_ptr<node> dst, frg::string_view name, int64_t flags) {
                return -ENOTSUP;
            }

            virtual ssize_t link(shared_ptr<node> src, shared_ptr<node> dst, frg::string_view name, bool is_symlink) {
                return -ENOTSUP;
            }

            virtual ssize_t unlink(shared_ptr<node> dst) {
                return -ENOTSUP;
            }

            virtual ssize_t remove(shared_ptr<node> dst) {
                return -ENOTSUP;
            }
    };

    // TODO: sockets
    struct pipe;
    struct descriptor {
        shared_ptr<vfs::node> node;
        shared_ptr<vfs::pipe> pipe;

        size_t ref;
        size_t pos;

        shared_ptr<node::statinfo> info;

        int current_ent;
        frg::vector<dirent *, memory::mm::heap_allocator> dirent_list;
    };

    struct pipe {
        shared_ptr<descriptor> read;
        shared_ptr<descriptor> write;

        void *buf;
        size_t len;
        
        bool data_written;
    };

    using fd_pair = frg::tuple<shared_ptr<fd>, shared_ptr<fd>>;
    struct fd {
        util::spinlock lock;
        shared_ptr<descriptor> desc;
        weak_ptr<fd_table> table;
        int fd_number;
        ssize_t flags;
        ssize_t mode;

        fd(): lock() {};
    };
    
    struct fd_table {
        util::spinlock lock;
        frg::hash_map<
            int, shared_ptr<fd>, 
            frg::hash<int>, memory::mm::heap_allocator
        > fd_list;
        size_t last_fd;

        fd_table(): lock(), fd_list(frg::hash<int>()) {}
    };

    static size_t zero = 0;
    weak_ptr<filesystem> resolve_fs(frg::string_view path, shared_ptr<node> base, size_t& symlinks_traversed = zero);
    shared_ptr<node> resolve_at(frg::string_view path, shared_ptr<node> base, bool follow_symlink = true, size_t& symlinks_traversed = zero);
    path get_abspath(shared_ptr<node> node);
    weak_ptr<node> get_parent(shared_ptr<node> base, frg::string_view path);

    ssize_t mount(frg::string_view srcpath, frg::string_view dstpath, ssize_t fstype, int64_t flags);
    ssize_t umount(shared_ptr<node> dst);

    shared_ptr<fd> open(shared_ptr<node> base, frg::string_view filepath, shared_ptr<fd_table> table, int64_t flags, mode_t mode,
        uid_t uid, gid_t gid);
    fd_pair open_pipe(shared_ptr<fd_table> table, ssize_t flags);

    ssize_t lseek(shared_ptr<fd> fd, off_t off, size_t whence);
    shared_ptr<fd> dup(shared_ptr<fd> fd, bool cloexec, ssize_t new_num);
    ssize_t close(shared_ptr<fd> fd);
    ssize_t read(shared_ptr<fd> fd, void *buf, size_t len);
    ssize_t write(shared_ptr<fd> fd, void *buf, size_t len);
    ssize_t ioctl(shared_ptr<fd> fd, size_t req, void *buf);
    void *mmap(shared_ptr<fd> fd, void *addr, off_t off, size_t len);

    ssize_t poll(pollfd *fds, nfds_t nfds, shared_ptr<fd_table> table, sched::timespec *timespec);

    ssize_t stat(shared_ptr<node> dir, frg::string_view filepath, node::statinfo *buf, int64_t flags);

    ssize_t create(shared_ptr<node> base, frg::string_view filepath, shared_ptr<fd_table> table, int64_t type, int64_t flags, mode_t mode,
        uid_t uid, gid_t gid);
    ssize_t mkdir(shared_ptr<node> base, frg::string_view dirpath, int64_t flags, mode_t mode,
        uid_t uid, gid_t gid);
    
    ssize_t rename(shared_ptr<node> old_base, frg::string_view oldpath, shared_ptr<node> new_base, frg::string_view newpath, int64_t flags);
    ssize_t link(shared_ptr<node> from_base, frg::string_view from, shared_ptr<node> to_base, frg::string_view to, bool is_symlink);
    ssize_t unlink(shared_ptr<node> base, frg::string_view filepath);
    ssize_t rmdir(shared_ptr<node> base, frg::string_view dirpath);
    pathlist readdir(shared_ptr<node> base, frg::string_view dirpath);

    // fs use only
    mode_t type2mode(int64_t type);

    shared_ptr<fd> make_fd(shared_ptr<node> node, shared_ptr<fd_table> table, int64_t flags, mode_t mode);
    shared_ptr<node> make_recursive(shared_ptr<node> base, frg::string_view path, int64_t type, mode_t mode);
    shared_ptr<filesystem> device_fs();

    // sched use
    shared_ptr<fd_table>  make_table();
    shared_ptr<fd_table>  copy_table(shared_ptr<fd_table> table);

    extern shared_ptr<node> tree_root;
    void init();
};

#endif