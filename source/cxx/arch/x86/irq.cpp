#include "mm/common.hpp"
#include <cstddef>
#include <cstdint>
#include <mm/mm.hpp>
#include <mm/vmm.hpp>
#include <sys/x86/apic.hpp>
#include <util/log/log.hpp>
#include <util/log/panic.hpp>
#include <util/io.hpp>
#include <arch/types.hpp>
#include <arch/x86/types.hpp>
#include <sys/sched/signal.hpp>
#include <sys/sched/sched.hpp>
#include <arch/x86/smp.hpp>

const char *exceptions[] = {
	"Divide by zero",
	"Debug",
	"NMI",
	"Breakpoint",
	"Overflow",
	"Bound Range Exceeded",
	"Invalid Opcode",
	"Device Not Available", 
	"Double fault", 
	"Co-processor Segment Overrun",
	"Invalid TSS",
	"Segment not present",
	"Stack-Segment Fault",
	"GPF",
	"Page Fault",
	"Reserved",
	"x87 Floating Point Exception",
	"Alignment check",
	"Machine check",
	"SIMD floating-point exception",
	"Virtualization Excpetion",
	"Deadlock",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Security Exception",
	"Reserved",
	"Triple Fault",
	"FPU error"
};

void arch::irq_on() {
    x86::irq_on();
}

void arch::irq_off() {
    x86::irq_off();
}

void arch::init_irqs() {
    x86::init_irqs();
    x86::hook_irqs();
}

void arch::route_irq(size_t irq, size_t vector) {
    x86::route_irq(irq, vector);
}

size_t arch::install_irq(irq_fn handler) {
    return x86::install_irq(handler);
}

size_t last_handler = 1;
x86::irq_fn handlers[224] = {};

x86::irq_ptr x86_ptr = {};
x86::irq_entry x86_entries[256] = { { 0 } };

static log::subsystem logger = log::make_subsystem("IRQ");
void trace(arch::irq_regs *r) {
    kmsg(logger, "stracktrace: ");

    size_t max_frames = 10;
    size_t parsed = 0;

    uint64_t rbp = (uint64_t) memory::add_virt(r->rbp);
    while (true) {
        uint64_t *stack = (uint64_t *) rbp;

        if (!stack[0]) {
            break;
        }

        rbp = memory::add_virt(stack[0]);
        kmsg(logger, "  rip %lx, rbp: %lx", stack[1], stack[0]);

        parsed++;
        if (!rbp || parsed == max_frames) {
            break;
        }
    }
}

extern "C" {
    void x86_irq_handler(arch::irq_regs *r) {
        if (r->cs & 0x3) {
            x86::swapgs();
        }

        uint64_t cr3 = x86::read_cr3();
        uint64_t cr2 = 0;
        asm volatile("movq %%cr2, %0" : "=r"(cr2));

        if (r->int_no == 14) {
            if (x86::handle_pf(r)) {
                x86::write_cr3(cr3);
                goto end_isr;
            }
        }

        if (r->int_no < 32) {
            //vmm::boot->swap_in();
            if (r->cs != 0x1B) {
                x86::stop_all_cpus();

                kmsg(logger, log::level::ERR, "%s exception on CPU %u, pid: %lu, tid: %lu \n"\
                                            "RAX: %lx, RBX: %lx \n"\
                                            "RCX: %lx, RDX: %lx\n"\
                                            "RBP: %lx, RDI: %lx\n"\
                                            "RSI: %lx, R8: %lx\n"\
                                            "R9: %lx, R10: %lx, R11: %lx, R12: %lx, R13: %lx, R14: %lx, R15: %lx\n"\
                                            "RSP: %lx\n"\
                                            "ERR: %lx, RIP: %lx\n"\
                                            "CR2: %lx, CR3: %lx\n"\
                                            "CS: %x, SS: %x, RFLAGS: %lx\n",
                                exceptions[r->int_no], x86::get_cpu(), x86::get_locals()->pid, x86::get_locals()->tid,
                                r->rax, r->rbx, 
                                r->rcx, r->rdx, 
                                r->rbp, r->rdi, 
                                r->rsi, r->r8,
                                r->r9, r->r10, r->r11, r->r12, r->r13, r->r14, r->r15,
                                r->rsp,
                                r->err, r->rip,
                                cr2, cr3,
                                r->cs, r->ss, r->rflags);                
                if (r->int_no == 14) {
                    kmsg(logger, "# PF Flags: ");
                    if (r->err & (1 << 0)) { kmsg(logger, "  P"); } else { kmsg(logger, "  NP"); }
                    if (r->err & (1 << 1)) { kmsg(logger, "  W"); } else { kmsg(logger, "  R"); }
                    if (r->err & (1 << 2)) { kmsg(logger, "  U"); } else { kmsg(logger, "  S"); }
                    if (r->err & (1 << 3)) { kmsg(logger, "  RES"); }
                }

                trace(r);
                while (true) { asm volatile("hlt"); }
            } else {
                kmsg(logger, log::level::ERR, "%s user exception on CPU %u, pid: %lu, tid: %lu \n"\
                                            "RAX: %lx, RBX: %lx \n"\
                                            "RCX: %lx, RDX: %lx\n"\
                                            "RBP: %lx, RDI: %lx\n"\
                                            "RSI: %lx, R8: %lx\n"\
                                            "R9: %lx, R10: %lx, R11: %lx, R12: %lx, R13: %lx, R14: %lx, R15: %lx\n"\
                                            "RSP: %lx\n"\
                                            "ERR: %lx, RIP: %lx\n"\
                                            "CR2: %lx, CR3: %lx\n"\
                                            "CS: %x, SS: %x, RFLAGS: %lx",
                                exceptions[r->int_no], x86::get_cpu(), x86::get_locals()->pid, x86::get_locals()->tid,
                                r->rax, r->rbx, 
                                r->rcx, r->rdx, 
                                r->rbp, r->rdi, 
                                r->rsi, r->r8,
                                r->r9, r->r10, r->r11, r->r12, r->r13, r->r14, r->r15,
                                r->rsp,
                                r->err, r->rip,
                                cr2, cr3,
                                r->cs, r->ss, r->rflags);

                if (r->int_no == 14) {
                    kmsg(logger, "# PF Flags: ");
                    if (r->err & (1 << 0)) { kmsg(logger, "  P"); } else { kmsg(logger, "  NP"); }
                    if (r->err & (1 << 1)) { kmsg(logger, "  W"); } else { kmsg(logger, "  R"); }
                    if (r->err & (1 << 2)) { kmsg(logger, "  U"); } else { kmsg(logger, "  S"); }
                    if (r->err & (1 << 3)) { kmsg(logger, "  RES"); }
                }

                x86::stop_all_cpus();
                while (true) { asm volatile("hlt"); }

                auto task = x86::get_thread();

                x86::get_locals()->task = nullptr;
                x86::get_locals()->pid = -1;

                task->state = sched::thread::DEAD;                    
                sched::threads[task->tid] = (sched::thread *) 0;
                task->proc->kill(255);

                sched::swap_task(r);
                goto end_isr;
            }
        }

        if (handlers[r->int_no - x86::IRQ0]) {
            handlers[r->int_no - x86::IRQ0](r);
        }

        end_isr:
            if (r->cs & 0x3) {
                x86::swapgs();
            }

            apic::lapic::eoi();
    }
};

void x86::set_gate(uint8_t num, uint64_t base, uint8_t flags) {
    x86_entries[num].base_lo =  (uint16_t) (base >> 0);
    x86_entries[num].base_mid = (uint16_t) (base >> 16);
    x86_entries[num].base_hi =  (uint32_t) (base >> 32);

    x86_entries[num].ist = 0;
    x86_entries[num].sel = 0x8;

    x86_entries[num].always0 = 0;
    x86_entries[num].flags = flags;
}

void x86::set_ist(uint8_t num, uint8_t idx) {
    x86_entries[num].ist = (idx & 0b111);
}

void x86::route_irq(size_t irq, size_t vector) {
    apic::ioapic::route(apic::lapic::id(), irq, vector + x86::IRQ0, 0);
}

size_t x86::install_irq(irq_fn handler) {
    size_t idx = last_handler++;
    handlers[idx] = handler;

    return idx;
}

void x86::install_irq(size_t irq, irq_fn handler) {
    handlers[irq] = handler;
}

void x86::irq_on() {
    asm volatile("sti");
}

void x86::irq_off() {
    asm volatile("cli");
}

bool arch::get_irq_state() {
    uint64_t rflags = 0;
    asm volatile ("pushfq; \
                    pop %0 "
                    : "=r"(rflags)
    );

    return (rflags >> 9) & 1;
};

void x86::hook_irqs() {
    asm volatile("lidtq (%0)" : : "r"(&x86_ptr));
}

void x86::init_irqs() {
    x86_ptr.limit = (sizeof(x86::irq_entry) * 256) - 1;
    x86_ptr.base = ((uint64_t) &x86_entries);

    x86::set_gate(0, (uint64_t) isr0, 0x8E);
    x86::set_gate(1, (uint64_t) isr1, 0x8E);
    x86::set_gate(2, (uint64_t) isr2, 0x8E);
    x86::set_gate(3, (uint64_t) isr3, 0x8E);
    x86::set_gate(4, (uint64_t) isr4, 0x8E);
    x86::set_gate(5, (uint64_t) isr5, 0x8E);
    x86::set_gate(6, (uint64_t) isr6, 0x8E);
    x86::set_gate(7, (uint64_t) isr7, 0x8E);
    x86::set_gate(8, (uint64_t) isr8, 0x8E);
    x86::set_gate(9, (uint64_t) isr9, 0x8E);
    x86::set_gate(10, (uint64_t) isr10, 0x8E);
    x86::set_gate(11, (uint64_t) isr11, 0x8E);
    x86::set_gate(12, (uint64_t) isr12, 0x8E);
    x86::set_gate(13, (uint64_t) isr13, 0x8E);
    x86::set_gate(14, (uint64_t) isr14, 0x8E);
    x86::set_gate(15, (uint64_t) isr15, 0x8E);
    x86::set_gate(16, (uint64_t) isr16, 0x8E);
    x86::set_gate(17, (uint64_t) isr17, 0x8E);
    x86::set_gate(18, (uint64_t) isr18, 0x8E);
    x86::set_gate(19, (uint64_t) isr19, 0x8E);
    x86::set_gate(20, (uint64_t) isr20, 0x8E);
    x86::set_gate(21, (uint64_t) isr21, 0x8E);
    x86::set_gate(22, (uint64_t) isr22, 0x8E);
    x86::set_gate(23, (uint64_t) isr23, 0x8E);
    x86::set_gate(24, (uint64_t) isr24, 0x8E);
    x86::set_gate(25, (uint64_t) isr25, 0x8E);
    x86::set_gate(26, (uint64_t) isr26, 0x8E);
    x86::set_gate(27, (uint64_t) isr27, 0x8E);
    x86::set_gate(28, (uint64_t) isr28, 0x8E);
    x86::set_gate(29, (uint64_t) isr29, 0x8E);
    x86::set_gate(30, (uint64_t) isr30, 0x8E);
    x86::set_gate(31, (uint64_t) isr31, 0x8E);
    x86::set_gate(32, (uint64_t) isr32, 0x8E);
    x86::set_gate(33, (uint64_t) isr33, 0x8E);
    x86::set_gate(34, (uint64_t) isr34, 0x8E);
    x86::set_gate(35, (uint64_t) isr35, 0x8E);
    x86::set_gate(36, (uint64_t) isr36, 0x8E);
    x86::set_gate(37, (uint64_t) isr37, 0x8E);
    x86::set_gate(38, (uint64_t) isr38, 0x8E);
    x86::set_gate(39, (uint64_t) isr39, 0x8E);
    x86::set_gate(40, (uint64_t) isr40, 0x8E);
    x86::set_gate(41, (uint64_t) isr41, 0x8E);
    x86::set_gate(42, (uint64_t) isr42, 0x8E);
    x86::set_gate(43, (uint64_t) isr43, 0x8E);
    x86::set_gate(44, (uint64_t) isr44, 0x8E);
    x86::set_gate(45, (uint64_t) isr45, 0x8E);
    x86::set_gate(46, (uint64_t) isr46, 0x8E);
    x86::set_gate(47, (uint64_t) isr47, 0x8E);
    x86::set_gate(48, (uint64_t) isr48, 0x8E);
    x86::set_gate(49, (uint64_t) isr49, 0x8E);
    x86::set_gate(50, (uint64_t) isr50, 0x8E);
    x86::set_gate(51, (uint64_t) isr51, 0x8E);
    x86::set_gate(52, (uint64_t) isr52, 0x8E);
    x86::set_gate(53, (uint64_t) isr53, 0x8E);
    x86::set_gate(54, (uint64_t) isr54, 0x8E);
    x86::set_gate(55, (uint64_t) isr55, 0x8E);
    x86::set_gate(56, (uint64_t) isr56, 0x8E);
    x86::set_gate(57, (uint64_t) isr57, 0x8E);
    x86::set_gate(58, (uint64_t) isr58, 0x8E);
    x86::set_gate(59, (uint64_t) isr59, 0x8E);
    x86::set_gate(60, (uint64_t) isr60, 0x8E);
    x86::set_gate(61, (uint64_t) isr61, 0x8E);
    x86::set_gate(62, (uint64_t) isr62, 0x8E);
    x86::set_gate(63, (uint64_t) isr63, 0x8E);
    x86::set_gate(64, (uint64_t) isr64, 0x8E);
    x86::set_gate(65, (uint64_t) isr65, 0x8E);
    x86::set_gate(66, (uint64_t) isr66, 0x8E);
    x86::set_gate(67, (uint64_t) isr67, 0x8E);
    x86::set_gate(68, (uint64_t) isr68, 0x8E);
    x86::set_gate(69, (uint64_t) isr69, 0x8E);
    x86::set_gate(70, (uint64_t) isr70, 0x8E);
    x86::set_gate(71, (uint64_t) isr71, 0x8E);
    x86::set_gate(72, (uint64_t) isr72, 0x8E);
    x86::set_gate(73, (uint64_t) isr73, 0x8E);
    x86::set_gate(74, (uint64_t) isr74, 0x8E);
    x86::set_gate(75, (uint64_t) isr75, 0x8E);
    x86::set_gate(76, (uint64_t) isr76, 0x8E);
    x86::set_gate(77, (uint64_t) isr77, 0x8E);
    x86::set_gate(78, (uint64_t) isr78, 0x8E);
    x86::set_gate(79, (uint64_t) isr79, 0x8E);
    x86::set_gate(80, (uint64_t) isr80, 0x8E);
    x86::set_gate(81, (uint64_t) isr81, 0x8E);
    x86::set_gate(82, (uint64_t) isr82, 0x8E);
    x86::set_gate(83, (uint64_t) isr83, 0x8E);
    x86::set_gate(84, (uint64_t) isr84, 0x8E);
    x86::set_gate(85, (uint64_t) isr85, 0x8E);
    x86::set_gate(86, (uint64_t) isr86, 0x8E);
    x86::set_gate(87, (uint64_t) isr87, 0x8E);
    x86::set_gate(88, (uint64_t) isr88, 0x8E);
    x86::set_gate(89, (uint64_t) isr89, 0x8E);
    x86::set_gate(90, (uint64_t) isr90, 0x8E);
    x86::set_gate(91, (uint64_t) isr91, 0x8E);
    x86::set_gate(92, (uint64_t) isr92, 0x8E);
    x86::set_gate(93, (uint64_t) isr93, 0x8E);
    x86::set_gate(94, (uint64_t) isr94, 0x8E);
    x86::set_gate(95, (uint64_t) isr95, 0x8E);
    x86::set_gate(96, (uint64_t) isr96, 0x8E);
    x86::set_gate(97, (uint64_t) isr97, 0x8E);
    x86::set_gate(98, (uint64_t) isr98, 0x8E);
    x86::set_gate(99, (uint64_t) isr99, 0x8E);
    x86::set_gate(100, (uint64_t) isr100, 0x8E);
    x86::set_gate(101, (uint64_t) isr101, 0x8E);
    x86::set_gate(102, (uint64_t) isr102, 0x8E);
    x86::set_gate(103, (uint64_t) isr103, 0x8E);
    x86::set_gate(104, (uint64_t) isr104, 0x8E);
    x86::set_gate(105, (uint64_t) isr105, 0x8E);
    x86::set_gate(106, (uint64_t) isr106, 0x8E);
    x86::set_gate(107, (uint64_t) isr107, 0x8E);
    x86::set_gate(108, (uint64_t) isr108, 0x8E);
    x86::set_gate(109, (uint64_t) isr109, 0x8E);
    x86::set_gate(110, (uint64_t) isr110, 0x8E);
    x86::set_gate(111, (uint64_t) isr111, 0x8E);
    x86::set_gate(112, (uint64_t) isr112, 0x8E);
    x86::set_gate(113, (uint64_t) isr113, 0x8E);
    x86::set_gate(114, (uint64_t) isr114, 0x8E);
    x86::set_gate(115, (uint64_t) isr115, 0x8E);
    x86::set_gate(116, (uint64_t) isr116, 0x8E);
    x86::set_gate(117, (uint64_t) isr117, 0x8E);
    x86::set_gate(118, (uint64_t) isr118, 0x8E);
    x86::set_gate(119, (uint64_t) isr119, 0x8E);
    x86::set_gate(120, (uint64_t) isr120, 0x8E);
    x86::set_gate(121, (uint64_t) isr121, 0x8E);
    x86::set_gate(122, (uint64_t) isr122, 0x8E);
    x86::set_gate(123, (uint64_t) isr123, 0x8E);
    x86::set_gate(124, (uint64_t) isr124, 0x8E);
    x86::set_gate(125, (uint64_t) isr125, 0x8E);
    x86::set_gate(126, (uint64_t) isr126, 0x8E);
    x86::set_gate(127, (uint64_t) isr127, 0x8E);
    x86::set_gate(128, (uint64_t) isr128, 0x8E);
    x86::set_gate(129, (uint64_t) isr129, 0x8E);
    x86::set_gate(130, (uint64_t) isr130, 0x8E);
    x86::set_gate(131, (uint64_t) isr131, 0x8E);
    x86::set_gate(132, (uint64_t) isr132, 0x8E);
    x86::set_gate(133, (uint64_t) isr133, 0x8E);
    x86::set_gate(134, (uint64_t) isr134, 0x8E);
    x86::set_gate(135, (uint64_t) isr135, 0x8E);
    x86::set_gate(136, (uint64_t) isr136, 0x8E);
    x86::set_gate(137, (uint64_t) isr137, 0x8E);
    x86::set_gate(138, (uint64_t) isr138, 0x8E);
    x86::set_gate(139, (uint64_t) isr139, 0x8E);
    x86::set_gate(140, (uint64_t) isr140, 0x8E);
    x86::set_gate(141, (uint64_t) isr141, 0x8E);
    x86::set_gate(142, (uint64_t) isr142, 0x8E);
    x86::set_gate(143, (uint64_t) isr143, 0x8E);
    x86::set_gate(144, (uint64_t) isr144, 0x8E);
    x86::set_gate(145, (uint64_t) isr145, 0x8E);
    x86::set_gate(146, (uint64_t) isr146, 0x8E);
    x86::set_gate(147, (uint64_t) isr147, 0x8E);
    x86::set_gate(148, (uint64_t) isr148, 0x8E);
    x86::set_gate(149, (uint64_t) isr149, 0x8E);
    x86::set_gate(150, (uint64_t) isr150, 0x8E);
    x86::set_gate(151, (uint64_t) isr151, 0x8E);
    x86::set_gate(152, (uint64_t) isr152, 0x8E);
    x86::set_gate(153, (uint64_t) isr153, 0x8E);
    x86::set_gate(154, (uint64_t) isr154, 0x8E);
    x86::set_gate(155, (uint64_t) isr155, 0x8E);
    x86::set_gate(156, (uint64_t) isr156, 0x8E);
    x86::set_gate(157, (uint64_t) isr157, 0x8E);
    x86::set_gate(158, (uint64_t) isr158, 0x8E);
    x86::set_gate(159, (uint64_t) isr159, 0x8E);
    x86::set_gate(160, (uint64_t) isr160, 0x8E);
    x86::set_gate(161, (uint64_t) isr161, 0x8E);
    x86::set_gate(162, (uint64_t) isr162, 0x8E);
    x86::set_gate(163, (uint64_t) isr163, 0x8E);
    x86::set_gate(164, (uint64_t) isr164, 0x8E);
    x86::set_gate(165, (uint64_t) isr165, 0x8E);
    x86::set_gate(166, (uint64_t) isr166, 0x8E);
    x86::set_gate(167, (uint64_t) isr167, 0x8E);
    x86::set_gate(168, (uint64_t) isr168, 0x8E);
    x86::set_gate(169, (uint64_t) isr169, 0x8E);
    x86::set_gate(170, (uint64_t) isr170, 0x8E);
    x86::set_gate(171, (uint64_t) isr171, 0x8E);
    x86::set_gate(172, (uint64_t) isr172, 0x8E);
    x86::set_gate(173, (uint64_t) isr173, 0x8E);
    x86::set_gate(174, (uint64_t) isr174, 0x8E);
    x86::set_gate(175, (uint64_t) isr175, 0x8E);
    x86::set_gate(176, (uint64_t) isr176, 0x8E);
    x86::set_gate(177, (uint64_t) isr177, 0x8E);
    x86::set_gate(178, (uint64_t) isr178, 0x8E);
    x86::set_gate(179, (uint64_t) isr179, 0x8E);
    x86::set_gate(180, (uint64_t) isr180, 0x8E);
    x86::set_gate(181, (uint64_t) isr181, 0x8E);
    x86::set_gate(182, (uint64_t) isr182, 0x8E);
    x86::set_gate(183, (uint64_t) isr183, 0x8E);
    x86::set_gate(184, (uint64_t) isr184, 0x8E);
    x86::set_gate(185, (uint64_t) isr185, 0x8E);
    x86::set_gate(186, (uint64_t) isr186, 0x8E);
    x86::set_gate(187, (uint64_t) isr187, 0x8E);
    x86::set_gate(188, (uint64_t) isr188, 0x8E);
    x86::set_gate(189, (uint64_t) isr189, 0x8E);
    x86::set_gate(190, (uint64_t) isr190, 0x8E);
    x86::set_gate(191, (uint64_t) isr191, 0x8E);
    x86::set_gate(192, (uint64_t) isr192, 0x8E);
    x86::set_gate(193, (uint64_t) isr193, 0x8E);
    x86::set_gate(194, (uint64_t) isr194, 0x8E);
    x86::set_gate(195, (uint64_t) isr195, 0x8E);
    x86::set_gate(196, (uint64_t) isr196, 0x8E);
    x86::set_gate(197, (uint64_t) isr197, 0x8E);
    x86::set_gate(198, (uint64_t) isr198, 0x8E);
    x86::set_gate(199, (uint64_t) isr199, 0x8E);
    x86::set_gate(200, (uint64_t) isr200, 0x8E);
    x86::set_gate(201, (uint64_t) isr201, 0x8E);
    x86::set_gate(202, (uint64_t) isr202, 0x8E);
    x86::set_gate(203, (uint64_t) isr203, 0x8E);
    x86::set_gate(204, (uint64_t) isr204, 0x8E);
    x86::set_gate(205, (uint64_t) isr205, 0x8E);
    x86::set_gate(206, (uint64_t) isr206, 0x8E);
    x86::set_gate(207, (uint64_t) isr207, 0x8E);
    x86::set_gate(208, (uint64_t) isr208, 0x8E);
    x86::set_gate(209, (uint64_t) isr209, 0x8E);
    x86::set_gate(210, (uint64_t) isr210, 0x8E);
    x86::set_gate(211, (uint64_t) isr211, 0x8E);
    x86::set_gate(212, (uint64_t) isr212, 0x8E);
    x86::set_gate(213, (uint64_t) isr213, 0x8E);
    x86::set_gate(214, (uint64_t) isr214, 0x8E);
    x86::set_gate(215, (uint64_t) isr215, 0x8E);
    x86::set_gate(216, (uint64_t) isr216, 0x8E);
    x86::set_gate(217, (uint64_t) isr217, 0x8E);
    x86::set_gate(218, (uint64_t) isr218, 0x8E);
    x86::set_gate(219, (uint64_t) isr219, 0x8E);
    x86::set_gate(220, (uint64_t) isr220, 0x8E);
    x86::set_gate(221, (uint64_t) isr221, 0x8E);
    x86::set_gate(222, (uint64_t) isr222, 0x8E);
    x86::set_gate(223, (uint64_t) isr223, 0x8E);
    x86::set_gate(224, (uint64_t) isr224, 0x8E);
    x86::set_gate(225, (uint64_t) isr225, 0x8E);
    x86::set_gate(226, (uint64_t) isr226, 0x8E);
    x86::set_gate(227, (uint64_t) isr227, 0x8E);
    x86::set_gate(228, (uint64_t) isr228, 0x8E);
    x86::set_gate(229, (uint64_t) isr229, 0x8E);
    x86::set_gate(230, (uint64_t) isr230, 0x8E);
    x86::set_gate(231, (uint64_t) isr231, 0x8E);
    x86::set_gate(232, (uint64_t) isr232, 0x8E);
    x86::set_gate(233, (uint64_t) isr233, 0x8E);
    x86::set_gate(234, (uint64_t) isr234, 0x8E);
    x86::set_gate(235, (uint64_t) isr235, 0x8E);
    x86::set_gate(236, (uint64_t) isr236, 0x8E);
    x86::set_gate(237, (uint64_t) isr237, 0x8E);
    x86::set_gate(238, (uint64_t) isr238, 0x8E);
    x86::set_gate(239, (uint64_t) isr239, 0x8E);
    x86::set_gate(240, (uint64_t) isr240, 0x8E);
    x86::set_gate(241, (uint64_t) isr241, 0x8E);
    x86::set_gate(242, (uint64_t) isr242, 0x8E);
    x86::set_gate(243, (uint64_t) isr243, 0x8E);
    x86::set_gate(244, (uint64_t) isr244, 0x8E);
    x86::set_gate(245, (uint64_t) isr245, 0x8E);
    x86::set_gate(246, (uint64_t) isr246, 0x8E);
    x86::set_gate(247, (uint64_t) isr247, 0x8E);
    x86::set_gate(248, (uint64_t) isr248, 0x8E);
    x86::set_gate(249, (uint64_t) isr249, 0x8E);
    x86::set_gate(250, (uint64_t) isr250, 0x8E);
    x86::set_gate(251, (uint64_t) isr251, 0x8E);
    x86::set_gate(252, (uint64_t) isr252, 0x8E);
    x86::set_gate(253, (uint64_t) isr253, 0x8E);
    x86::set_gate(254, (uint64_t) isr254, 0x8E);
    x86::set_gate(255, (uint64_t) isr255, 0x8E);

    x86::set_ist(0, 2);
    x86::set_ist(1, 2);
    x86::set_ist(2, 2);
    x86::set_ist(3,  2);
    x86::set_ist(4, 2);
    x86::set_ist(5, 2);
    x86::set_ist(6, 2);
    x86::set_ist(7, 2);
    x86::set_ist(8, 2);
    x86::set_ist(9, 2);
    x86::set_ist(10, 2);
    x86::set_ist(11, 2);
    x86::set_ist(12, 2);
    x86::set_ist(13, 2);
    x86::set_ist(14, 2);
    x86::set_ist(15, 2);
    x86::set_ist(16, 2);
    x86::set_ist(17, 2);
    x86::set_ist(18, 2);
    x86::set_ist(19, 2);
    x86::set_ist(20, 2);
    x86::set_ist(21, 2);
    x86::set_ist(22, 2);
    x86::set_ist(23, 2);
    x86::set_ist(24, 2);
    x86::set_ist(25, 2);
    x86::set_ist(26, 2);
    x86::set_ist(27, 2);
    x86::set_ist(28, 2);
    x86::set_ist(29, 2);
    x86::set_ist(30, 2);
    x86::set_ist(31, 2);
    x86::set_ist(251, 2);

    x86::set_ist(32, 1);
    x86::set_ist(33, 1);
}