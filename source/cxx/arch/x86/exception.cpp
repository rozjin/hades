#include <arch/x86/smp.hpp>
#include <arch/x86/types.hpp>

/*
extern "C" {
    extern void *_ex_table_begin;
    extern void *_ex_table_end;
}

struct [[gnu::packed]] exception_entry {
    uint64_t insn;
    uint64_t fixup;
};

exception_entry *ex_table_begin = (exception_entry *) &_ex_table_begin;
exception_entry *ex_table_end = (exception_entry *) &ex_table_end;

exception_entry *search_exceptions(uint64_t rip) {
    exception_entry *current = ex_table_begin;
    while (current != ex_table_end) {
        if (current->insn == rip) {
            return current;
        }

        current++;
    }

    return nullptr;
}

bool x86::handle_user_exception(arch::irq_regs *r) {
    uint64_t faulting_addr;
    asm volatile("mov %%cr2, %0": "=a"(faulting_addr));
    
    auto entry = search_exceptions(r->rip);
    if (!entry) {
        return false;
    }

    r->rip = entry->fixup;
    return true;
}
*/