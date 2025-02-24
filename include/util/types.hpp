#ifndef TYPES_HPP
#define TYPES_HPP

#include <cstddef>
#include <cstdint>
#include <frg/unique.hpp>
#include <mm/mm.hpp>

using pid_t = int;
using tid_t = int;
using uid_t = uint32_t;
using gid_t = int32_t;

using blksize_t = int64_t;
using blkcnt_t = int64_t;

using dev_t = uint64_t;
using ino_t = uint64_t;
using mode_t = int32_t;
using nlink_t = int32_t;
using clockid_t = uint64_t;
using time_t = long;

using sigset_t = uint64_t;
using ssize_t = int64_t;
using off_t = int64_t;

constexpr int S_IRWXU = 0700;
constexpr int S_IRUSR = 0400;
constexpr int S_IWUSR = 0200;
constexpr int S_IXUSR = 0100;
constexpr int S_IRWXG = 070;
constexpr int S_IRGRP = 040;
constexpr int S_IWGRP = 020;
constexpr int S_IXGRP = 010;
constexpr int S_IRWXO = 07;
constexpr int S_IROTH = 04;
constexpr int S_IWOTH = 02;
constexpr int S_IXOTH = 01;
constexpr int S_ISUID = 04000;
constexpr int S_ISGID = 02000;
constexpr int S_ISVTX = 01000;

constexpr int DEFAULT_MODE = S_IRWXU | S_IRWXG | S_IRWXO;

constexpr int O_CREAT = 0x000010;
constexpr int O_APPEND = 0x000008;
constexpr int O_CLOEXEC = 0x004000;
constexpr int O_EXCL = 0x000040;
constexpr int O_DIRECTORY = 0x000020;
constexpr int O_TRUNC = 0x000200;

constexpr int O_ACCMODE = 0x0007;
constexpr int O_EXEC = 1;
constexpr int O_RDONLY = 2;
constexpr int O_RDWR = 3;
constexpr int O_WRONLY = 5;

constexpr int S_IFMT     = 0x0f000;
constexpr int S_IFBLK   = 0x06000;
constexpr int S_IFCHR   = 0x02000;
constexpr int S_IFIFO   = 0x01000;
constexpr int S_IFREG   = 0x08000;
constexpr int S_IFDIR   = 0x04000;
constexpr int S_IFLNK   = 0x0a000;
constexpr int S_IFSOCK = 0x0c000;

constexpr int O_NOCTTY = 0x000080;

constexpr int AT_FDCWD = -100;
constexpr int AT_EMPTY_PATH = 1;

constexpr int AT_SYMLINK_FOLLOW = 2;
constexpr int AT_SYMLINK_NOFOLLOW = 4;

constexpr int SEEK_SET = 1;
constexpr int SEEK_CUR = 2;
constexpr int SEEK_END = 3;

constexpr int F_OK = 1;
constexpr int R_OK = 2;
constexpr int W_OK = 4;
constexpr int X_OK = 8;

constexpr int F_DUPFD = 1;
constexpr int F_DUPFD_CLOEXEC = 2;
constexpr int F_GETFD = 3;
constexpr int F_SETFD = 4;
constexpr int F_GETFL = 5;
constexpr int F_SETFL = 6;
constexpr int F_GETLK = 7;
constexpr int F_SETLK = 8;
constexpr int F_SETLKW = 9;
constexpr int F_GETOWN = 10;
constexpr int F_SETOWN = 11;

constexpr size_t DT_UNKNOWN = 0;
constexpr size_t DT_FIFO = 1;
constexpr size_t DT_CHR = 2;
constexpr size_t DT_DIR = 4;
constexpr size_t DT_BLK = 6;
constexpr size_t DT_REG = 8;
constexpr size_t DT_LNK = 10;
constexpr size_t DT_SOCK = 12;
constexpr size_t DT_WHT = 14;

struct dirent {
    ino_t d_ino;
    off_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[1024];
};

constexpr size_t POLLIN = 0x01;
constexpr size_t POLLOUT = 0x02;
constexpr size_t POLLPRI = 0x04;
constexpr size_t POLLHUP = 0x08;
constexpr size_t POLLERR = 0x10;
constexpr size_t POLLRDHUP = 0x20;
constexpr size_t POLLNVAL = 0x40;
constexpr size_t POLLWRNORM = 0x80;

using nfds_t = size_t;
struct pollfd {
    int fd;
    short events;
    short revents;
};

using bus_addr_t = size_t;
using bus_size_t = size_t;
using bus_handle_t = uintptr_t;

template<typename T>
using unique_ptr = frg::unique_ptr<T, memory::mm::heap_allocator>;

constexpr char alpha_lower[] = "abcdefghijklmnopqrstuvwxyz";

#endif