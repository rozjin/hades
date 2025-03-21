#ifndef TERMIOS_HPP
#define TERMIOS_HPP

namespace tty {
    using cc_t = unsigned char;
    using speed_t = unsigned int;
    using tcflag_t = unsigned int;

    #define NCCS     32
    #define VINTR    0
    #define VQUIT    1
    #define VERASE   2
    #define VKILL    3
    #define VEOF     4
    #define VTIME    5
    #define VMIN     6
    #define VSWTC    7
    #define VSTART   8
    #define VSTOP    9
    #define VSUSP    10
    #define VEOL     11
    #define VREPRINT 12
    #define VDISCARD 13
    #define VWERASE  14
    #define VLNEXT   15
    #define VEOL2    16

    #define BRKINT 0000002
    #define ICRNL 0000400
    #define IGNBRK 0000001
    #define IGNCR 0000200
    #define IGNPAR 0000004
    #define INLCR 0000100
    #define INPCK 0000020
    #define ISTRIP 0000040
    #define IXANY 0004000
    #define IXOFF 0010000
    #define IXON 0002000
    #define PARMRK 0000010

    #define OPOST 0000001
    #define ONLCR 0000004
    #define OCRNL 0000010
    #define ONOCR 0000020
    #define ONLRET 0000040
    #define OFDEL 0000200
    #define OFILL 0000100

    #define NLDLY 0000400
    #define NL0 0000000
    #define NL1 0000400

    #define CRDLY 0003000
    #define CR0 0000000
    #define CR1 0001000
    #define CR2 0002000
    #define CR3 0003000

    #define TABDLY 0014000
    #define TAB0 0000000
    #define TAB1 0004000
    #define TAB2 0010000
    #define TAB3 0014000

    #define XTABS 0014000
    #define BSDLY 0020000
    #define BS0 0000000
    #define BS1 0020000

    #define VTDLY 0040000
    #define VT0 0000000
    #define VT1 0040000

    #define FFDLY 0100000
    #define FF0 0000000
    #define FF1 0100000

    #define CSIZE 0000060
    #define CS5 0000000
    #define CS6 0000020
    #define CS7 0000040
    #define CS8 0000060

    #define CSTOPB 0000100
    #define CREAD 0000200
    #define PARENB 0000400
    #define PARODD 0001000
    #define HUPCL 0002000
    #define CLOCAL 0004000

    #define ECHO 0000010
    #define ECHOE 0000020
    #define ECHOK 0000040
    #define ECHONL 0000100
    #define ICANON 0000002
    #define IEXTEN 0100000
    #define ISIG 0000001
    #define NOFLSH 0000200
    #define TOSTOP 0000400

    #define ECHOCTL 0x200

    struct termios {
        tcflag_t c_iflag;
        tcflag_t c_oflag;
        tcflag_t c_cflag;
        tcflag_t c_lflag;
        cc_t c_line;
        cc_t c_cc[NCCS];
        speed_t ibaud;
        speed_t obaud;
    };
};

#endif