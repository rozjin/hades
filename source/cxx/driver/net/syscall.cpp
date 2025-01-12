#include <arch/types.hpp>
#include <arch/x86/types.hpp>
#include <util/errors.hpp>
#include <cstddef>

static const char *hostname[253];
void syscall_sethostname(arch::irq_regs *r) {
    const char *name = (const char *) r->rdi;
    size_t len = r->rsi;

    if (len > 252) {
        arch::set_errno(ENAMETOOLONG);
        r->rax = -1;
        return;
    }

    size_t bytes = arch::copy_from_user(hostname, name, len);
    if (bytes != len) {
        arch::set_errno(EFAULT);
        r->rax = -1;
        return;
    }

    hostname[len] = 0;
    r->rax = 0;
}

void syscall_gethostname(arch::irq_regs *r) {
    char *name = (char *) r->rdi;
    size_t len = r->rsi;

    if (len > 252) {
        arch::set_errno(ENAMETOOLONG);
        r->rax = -1;
        return;
    }

    size_t bytes = arch::copy_to_user(name, hostname, len);
    if (bytes != len) {
        arch::set_errno(EFAULT);
        r->rax = -1;
        return;
    }

    r->rax = 0;
}