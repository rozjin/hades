#ifndef SYSCALL_HPP
#define SYSCALL_HPP

#include <arch/x86/types.hpp>

namespace x86 {
    using syscall_handler = void (*)(arch::irq_regs *r);
}

#endif