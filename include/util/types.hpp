#ifndef TYPES_HPP
#define TYPES_HPP

#include <cstddef>
#include <cstdint>

using pid_t = int;
using tid_t = int;
using uid_t = uint32_t;
using gid_t = int32_t;

using ino_t = uint64_t;
using mode_t = int32_t;
using clockid_t = uint64_t;
using time_t = long;

using sigset_t = uint64_t;
using ssize_t = int64_t;
using off_t = int64_t;

constexpr int O_CREAT = 0x000010;
constexpr int O_APPEND = 0x000008;
constexpr int O_CLOEXEC = 0x004000;
constexpr int O_EXCL = 0x000040;
constexpr int O_DIRECTORY = 0x000020;
constexpr int O_TRUNC = 0x000200;

constexpr int O_RDONLY = 2;
constexpr int O_WRONLY = 5;
constexpr int O_RDWR = 3;

constexpr int O_NOCTTY = 0x000080;

constexpr int AT_FDCWD = -100;
constexpr int AT_EMPTY_PATH = 1;

constexpr int AT_SYMLINK_FOLLOW = 2;
constexpr int AT_SYMLINK_NOFOLLOW = 4;

constexpr int SEEK_SET = 1;
constexpr int SEEK_CUR = 2;
constexpr int SEEK_END = 3;

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

struct [[gnu::packed]] dirent {
    ino_t d_ino;
    off_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[1024];
};

#endif