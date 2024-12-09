#ifndef ERRNO_HPP
#define ERRNO_HPP

#include <cstddef>

constexpr size_t EPERM = 1;
constexpr size_t ENOENT	= 2;
constexpr size_t ESRCH = 3;
constexpr size_t EINTR	= 4;
constexpr size_t EIO = 5; 
constexpr size_t ENXIO = 6;
constexpr size_t E2BIG = 7;
constexpr size_t ENOEXEC = 8;
constexpr size_t EBADF = 9;
constexpr size_t ECHILD	= 10;
constexpr size_t EDEADLK = 11;

constexpr size_t ENOMEM	= 12;
constexpr size_t EACCES	= 13;
constexpr size_t EFAULT	= 14;

constexpr size_t ENOTBLK = 15;
constexpr size_t EBUSY = 16;

constexpr size_t EEXIST	 = 17;
constexpr size_t EXDEV	 = 18;
constexpr size_t ENODEV	 = 19;
constexpr size_t ENOTDIR = 20;
constexpr size_t EISDIR	 = 21;
constexpr size_t EINVAL	 = 22;
constexpr size_t ENFILE	 = 23;
constexpr size_t EMFILE	 = 24;
constexpr size_t ENOTTY	 = 25;

constexpr size_t ETXTBSY = 26;

constexpr size_t EFBIG	= 27;
constexpr size_t ENOSPC	= 28;
constexpr size_t ESPIPE	= 29;
constexpr size_t EROFS	= 30;
constexpr size_t EMLINK	= 31;
constexpr size_t EPIPE	= 32;

constexpr size_t EDOM	= 33;
constexpr size_t ERANGE	= 34;

constexpr size_t EAGAIN = 35;

constexpr size_t EWOULDBLOCK = EAGAIN;
constexpr size_t EINPROGRESS = 36;
constexpr size_t EALREADY = 37;

constexpr size_t ENOTSOCK = 38;
constexpr size_t EDESTADDRREQ = 39;
constexpr size_t EMSGSIZE = 40;
constexpr size_t EPROTOTYPE = 41;
constexpr size_t ENOPROTOOPT = 42;
constexpr size_t EPROTONOSUPPORT = 43;
constexpr size_t ESOCKTNOSUPPORT = 44;
constexpr size_t EOPNOTSUPP = 45;
constexpr size_t EPFNOSUPPORT = 46;
constexpr size_t EAFNOSUPPORT = 47;
constexpr size_t EADDRINUSE = 48;
constexpr size_t EADDRNOTAVAIL = 49;

constexpr size_t ENETDOWN = 50;
constexpr size_t ENETUNREACH = 51;
constexpr size_t ENETRESET = 52;
constexpr size_t ECONNABORTED = 53;
constexpr size_t ECONNRESET = 54;
constexpr size_t ENOBUFS = 55;
constexpr size_t EISCONN = 56;
constexpr size_t ENOTCONN = 57;
constexpr size_t ESHUTDOWN = 58;
constexpr size_t ETOOMANYREFS = 59;
constexpr size_t ETIMEDOUT = 60;
constexpr size_t ECONNREFUSED = 61;

constexpr size_t ELOOP = 62;
constexpr size_t ENAMETOOLONG = 63;

constexpr size_t EHOSTDOWN = 64;
constexpr size_t EHOSTUNREACH = 65;
constexpr size_t ENOTEMPTY = 66;

constexpr size_t EPROCLIM = 67;
constexpr size_t EUSERS	= 68;
constexpr size_t EDQUOT	= 69;

constexpr size_t ESTALE	= 70;
constexpr size_t EREMOTE = 71;
constexpr size_t EBADRPC = 72;
constexpr size_t ERPCMISMATCH = 73;
constexpr size_t EPROGUNAVAIL = 74;
constexpr size_t EPROGMISMATCH = 75;
constexpr size_t EPROCUNAVAIL = 76;


constexpr size_t ENOLCK	= 77;
constexpr size_t ENOSYS	= 78;

constexpr size_t EFTYPE	= 79;
constexpr size_t EOVERFLOW = 80;
constexpr size_t EILSEQ = 81;

constexpr size_t EBADMSG = 82;
constexpr size_t ECANCELED = 83;
constexpr size_t EIDRM = 84;
constexpr size_t EMULTIHOP = 85;
constexpr size_t ENOLINK = 86;
constexpr size_t ENOMSG	= 87;
constexpr size_t ENOTRECOVERABLE = 88;
constexpr size_t EOWNERDEAD	= 90;
constexpr size_t EPROTO	= 91;
constexpr size_t ENODATA = 92;
constexpr size_t ETIME = 93;
constexpr size_t ENOKEY = 94;
constexpr size_t EBADFD = 95;
constexpr size_t ENOMEDIUM = 96;
constexpr size_t ENONET	= 97;
constexpr size_t ESTRPIPE = 98;
constexpr size_t EREMOTEIO = 99;
constexpr size_t ERFKILL = 100;
constexpr size_t EBADR = 101;
constexpr size_t EUNATCH = 102;
constexpr size_t EMEDIUMTYPE = 103;
constexpr size_t EKEYREJECTED = 104;
constexpr size_t EUCLEAN = 105;
constexpr size_t EBADSLT = 106;
constexpr size_t ENOANO	= 107;
constexpr size_t ENOCSI	= 108;
constexpr size_t ENOSTR	= 109;
constexpr size_t ENOPKG	= 110;
constexpr size_t EKEYREVOKED = 111;
constexpr size_t EXFULL	= 112;
constexpr size_t ELNRNG	= 113;
constexpr size_t ENOTUNIQ= 114;
constexpr size_t ERESTART= 115;
constexpr size_t ENOTSUP = 116;

#endif
