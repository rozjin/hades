#ifndef ARCH_X86_64_TYPES
#define ARCH_X86_64_TYPES

#include <cstddef>
#include <cstdint>
#include <mm/common.hpp>
#include <sys/sched/time.hpp>
#include <util/types.hpp>

namespace vfs {
    struct fd;
}

namespace sched {
    struct process_env;
    class process;
    class thread;
}

namespace vmm {
    using vmm_ctx_map = uint64_t *;

    enum class page_flags: uint64_t {
        PRESENT = (1 << 0),
        WRITE = (1 << 1),
        USER =  (1 << 2),
        LARGE = (1 << 7),

        DEMAND = (1 << 9),

        COW = (1 << 10),

        SHARED = (1 << 11),
        PRIVATE = (1ULL << 52),
        DIRTY = (1ULL << 53),

        EXEC = (1ULL << 63)
    };

    inline constexpr page_flags
    operator&(page_flags x, page_flags y) {
        return static_cast<page_flags>
        (static_cast<int>(x) & static_cast<int>(y));
    }

    inline constexpr page_flags
    operator|(page_flags x, page_flags y) {
        return static_cast<page_flags>
        (static_cast<int>(x) | static_cast<int>(y));
    }

    inline constexpr page_flags
    operator^(page_flags x, page_flags y) {
        return static_cast<page_flags>
        (static_cast<int>(x) ^ static_cast<int>(y));
    }

    inline constexpr page_flags
    operator~(page_flags x) {
        return static_cast<page_flags>(~static_cast<int>(x));
    }

    inline page_flags &
    operator&=(page_flags & x, page_flags y) {
        x = x & y;
        return x;
    }

    inline page_flags &
    operator|=(page_flags & x, page_flags y) {
        x = x | y;
        return x;
    }

    inline page_flags &
    operator^=(page_flags & x, page_flags y) {
        x = x ^ y;
        return x;
    }
};

namespace arch {
    struct [[gnu::packed]] irq_regs {
        uint64_t r15, r14, r13, r12, r11, r10, r9, r8,
                 rsi, rdi, rbp, rdx, rcx, rbx, rax;
        uint64_t int_no, err;
        uint64_t rip, cs, rflags, rsp, ss;
    };

    struct [[gnu::packed]] sched_regs {
        uint64_t rax, rbx, rcx, rdx, rbp, rdi, rsi, r8, r9, r10, r11, r12, r13, r14, r15;
        uint64_t rsp, rip;

        uint64_t ss, cs;
        uint64_t fs, gs;
        uint64_t rflags;
        uint64_t cr3;

        uint32_t mxcsr;
        uint16_t fcw;
    };

    struct thread_ctx {
        sched_regs reg;

        alignas(16)
        char sse_region[512];


        uint8_t privilege;
        int cpu;
    };

    using entry_trampoline = uint64_t;
}

namespace x86 {
    arch::irq_regs sched_to_irq(arch::sched_regs *r);
    arch::sched_regs irq_to_sched(arch::irq_regs *r);

    size_t copy_to_user(void *dst, const void *src, size_t length);
    size_t copy_from_user(void *dst, const void *src, size_t length);

    struct [[gnu::packed]] irq_ptr {
        uint16_t limit;
        uint64_t base;
    };

    struct [[gnu::packed]] irq_entry {
        uint16_t base_lo;
        uint16_t sel;
        uint8_t ist;
        uint8_t flags;
        uint16_t base_mid;
        uint32_t base_hi;
        uint32_t always0;
    };

    void init_irqs();
    void hook_irqs();

    void irq_on();
    void irq_off();
    void stall_cpu();

    using irq_fn = void(*)(arch::irq_regs *r);
    using irq_ext = void(*)(arch::irq_regs *r, void *aux);
    struct irq_handler {
        union {
            irq_fn reg;
            irq_ext ext;
        } fn;
        void *aux;
    };

    size_t alloc_vector();
    void install_vector(size_t vector, irq_fn handler);
    void install_vector(size_t vector, irq_ext handler, void *aux = nullptr);
    void route_irq(size_t irq, size_t vector);

    void set_gate(uint8_t num, uint64_t base, uint8_t flags);
    void set_ist(uint8_t num, uint8_t idx);

    uint16_t get_fcw();
    void set_fcw(uint16_t fcw);

    uint32_t get_mxcsr();
    void set_mxcsr(uint32_t mxcsr);

    void save_sse(char *sse_region);
    void load_sse(char *sse_region);

    void handle_tick(arch::irq_regs *r);    
    void do_tick();

    void init_syscalls();
    void init_idle();
    void init_sse();

    void init_bsp();
    void init_ap();

    bool handle_user_exception(arch::irq_regs *r);
    bool handle_pf(arch::irq_regs *r);
    void cleanup_vmm_ctx(sched::process *process);
    
    void init_thread(sched::thread *task);
    void start_thread(sched::thread *task);
    void stop_thread(sched::thread *task);
    void kill_thread(sched::thread *task);

    ssize_t do_futex(uintptr_t vaddr, int op, int expected, sched::timespec *timeout);

    void sigreturn_kill(sched::process *proc, ssize_t status);
    void sigreturn_default(sched::process *proc, sched::thread *task);
    void sighandler_default(sched::process *proc, sched::thread *task, int sig);

    namespace loader {
        bool load_elf(const char *path, vfs::fd *fd, sched::process_env *env);
        void place_params(char **envp, char **argv, sched::thread *task, sched::process_env *env);
        uint64_t *place_args(uint64_t* location, sched::process_env *env);
        uint64_t *place_auxv(uint64_t *location, sched::process_env *env);
        void load_params(char **argv, char** envp, sched::process_env *env);
    }

    constexpr size_t IRQ0 = 32;

    constexpr size_t entries_per_table = 512;
    constexpr size_t perms_mask = 0xFFF0000000000FFF;
    constexpr size_t addr_mask = ~perms_mask;

    constexpr uint64_t EFER = 0xC0000080;
    constexpr uint64_t STAR = 0xC0000081;
    constexpr uint64_t LSTAR = 0xC0000082;
    constexpr uint64_t SFMASK = 0xC0000084;

    constexpr size_t MSR_FS_BASE = 0xC0000100;
    constexpr size_t MSR_GS_BASE = 0xC0000101;
    constexpr size_t KERNEL_GS_BASE = 0xC0000102;

    template<typename V>
    void wrmsr(uint64_t msr, V value) {
        uint32_t low = ((uint64_t) value) & 0xFFFFFFFF;
        uint32_t high = ((uint64_t) value) >> 32;
        asm volatile (
            "wrmsr"
            :
            : "c"(msr), "a"(low), "d"(high)
        );
    }

    template<typename V>
    V rdmsr(uint64_t msr) {
        uint32_t low, high;
        asm volatile (
            "rdmsr"
            : "=a"(low), "=d"(high)
            : "c"(msr)
        );
        return (V) (((uint64_t ) high << 32) | low);
    }

    inline uint64_t tsc() {
        uint64_t rax, rdx;
        asm volatile(
            "rdtsc"
            : "=a"(rax), "=d"(rdx)
        );

        return (rdx << 32) | rax;
    }

    inline void swapgs() {
        asm volatile ("swapgs" ::: "memory");
    }

    inline void set_kernel_gs(uint64_t addr) {
        wrmsr(MSR_GS_BASE, addr);
    }

    inline void set_user_gs(uint64_t addr) {
        wrmsr(KERNEL_GS_BASE, addr);
    }

    inline uint64_t get_user_gs() {
        return rdmsr<uint64_t>(KERNEL_GS_BASE);
    }

    inline void set_user_fs(uint64_t addr) {
        wrmsr(MSR_FS_BASE, addr);
    }

    inline uint64_t get_user_fs() {
        return rdmsr<uint64_t>(MSR_FS_BASE);
    }

    inline uint64_t get_cr3(vmm::vmm_ctx_map map) {
        return (uint64_t) memory::remove_virt(map);
    }

    inline uint64_t read_cr3() {
        uint64_t ret;
        asm volatile("movq %%cr3, %0;" : "=r"(ret));
        return ret;
    }

    inline void write_cr3(uint64_t cr3) {
        asm volatile("movq %0, %%cr3;" ::"r"(cr3) : "memory");

    }

    inline void swap_cr3(vmm::vmm_ctx_map map) {
        asm volatile("mov %0, %%cr3;    \
                    mov %%cr3, %%rax; \
                    mov %%rax, %%cr3"
                    :
                    : "r"((size_t) memory::remove_virt(map))
        );
    }

    inline void invlpg(uint64_t virt) {
        asm volatile("invlpg (%0)":: "r"(virt) : "memory");
    }
}

extern "C" {
    extern void isr0();
    extern void isr1();
    extern void isr2();
    extern void isr3();
    extern void isr4();
    extern void isr5();
    extern void isr6();
    extern void isr7();
    extern void isr8();
    extern void isr9();
    extern void isr10();
    extern void isr11();
    extern void isr12();
    extern void isr13();
    extern void isr14();
    extern void isr15();
    extern void isr16();
    extern void isr17();
    extern void isr18();
    extern void isr19();
    extern void isr20();
    extern void isr21();
    extern void isr22();
    extern void isr23();
    extern void isr24();
    extern void isr25();
    extern void isr26();
    extern void isr27();
    extern void isr28();
    extern void isr29();
    extern void isr30();
    extern void isr31();
    extern void isr32();
    extern void isr33();
    extern void isr34();
    extern void isr35();
    extern void isr36();
    extern void isr37();
    extern void isr38();
    extern void isr39();
    extern void isr40();
    extern void isr41();
    extern void isr42();
    extern void isr43();
    extern void isr44();
    extern void isr45();
    extern void isr46();
    extern void isr47();
    extern void isr48();
    extern void isr49();
    extern void isr50();
    extern void isr51();
    extern void isr52();
    extern void isr53();
    extern void isr54();
    extern void isr55();
    extern void isr56();
    extern void isr57();
    extern void isr58();
    extern void isr59();
    extern void isr60();
    extern void isr61();
    extern void isr62();
    extern void isr63();
    extern void isr64();
    extern void isr65();
    extern void isr66();
    extern void isr67();
    extern void isr68();
    extern void isr69();
    extern void isr70();
    extern void isr71();
    extern void isr72();
    extern void isr73();
    extern void isr74();
    extern void isr75();
    extern void isr76();
    extern void isr77();
    extern void isr78();
    extern void isr79();
    extern void isr80();
    extern void isr81();
    extern void isr82();
    extern void isr83();
    extern void isr84();
    extern void isr85();
    extern void isr86();
    extern void isr87();
    extern void isr88();
    extern void isr89();
    extern void isr90();
    extern void isr91();
    extern void isr92();
    extern void isr93();
    extern void isr94();
    extern void isr95();
    extern void isr96();
    extern void isr97();
    extern void isr98();
    extern void isr99();
    extern void isr100();
    extern void isr101();
    extern void isr102();
    extern void isr103();
    extern void isr104();
    extern void isr105();
    extern void isr106();
    extern void isr107();
    extern void isr108();
    extern void isr109();
    extern void isr110();
    extern void isr111();
    extern void isr112();
    extern void isr113();
    extern void isr114();
    extern void isr115();
    extern void isr116();
    extern void isr117();
    extern void isr118();
    extern void isr119();
    extern void isr120();
    extern void isr121();
    extern void isr122();
    extern void isr123();
    extern void isr124();
    extern void isr125();
    extern void isr126();
    extern void isr127();
    extern void isr128();
    extern void isr129();
    extern void isr130();
    extern void isr131();
    extern void isr132();
    extern void isr133();
    extern void isr134();
    extern void isr135();
    extern void isr136();
    extern void isr137();
    extern void isr138();
    extern void isr139();
    extern void isr140();
    extern void isr141();
    extern void isr142();
    extern void isr143();
    extern void isr144();
    extern void isr145();
    extern void isr146();
    extern void isr147();
    extern void isr148();
    extern void isr149();
    extern void isr150();
    extern void isr151();
    extern void isr152();
    extern void isr153();
    extern void isr154();
    extern void isr155();
    extern void isr156();
    extern void isr157();
    extern void isr158();
    extern void isr159();
    extern void isr160();
    extern void isr161();
    extern void isr162();
    extern void isr163();
    extern void isr164();
    extern void isr165();
    extern void isr166();
    extern void isr167();
    extern void isr168();
    extern void isr169();
    extern void isr170();
    extern void isr171();
    extern void isr172();
    extern void isr173();
    extern void isr174();
    extern void isr175();
    extern void isr176();
    extern void isr177();
    extern void isr178();
    extern void isr179();
    extern void isr180();
    extern void isr181();
    extern void isr182();
    extern void isr183();
    extern void isr184();
    extern void isr185();
    extern void isr186();
    extern void isr187();
    extern void isr188();
    extern void isr189();
    extern void isr190();
    extern void isr191();
    extern void isr192();
    extern void isr193();
    extern void isr194();
    extern void isr195();
    extern void isr196();
    extern void isr197();
    extern void isr198();
    extern void isr199();
    extern void isr200();
    extern void isr201();
    extern void isr202();
    extern void isr203();
    extern void isr204();
    extern void isr205();
    extern void isr206();
    extern void isr207();
    extern void isr208();
    extern void isr209();
    extern void isr210();
    extern void isr211();
    extern void isr212();
    extern void isr213();
    extern void isr214();
    extern void isr215();
    extern void isr216();
    extern void isr217();
    extern void isr218();
    extern void isr219();
    extern void isr220();
    extern void isr221();
    extern void isr222();
    extern void isr223();
    extern void isr224();
    extern void isr225();
    extern void isr226();
    extern void isr227();
    extern void isr228();
    extern void isr229();
    extern void isr230();
    extern void isr231();
    extern void isr232();
    extern void isr233();
    extern void isr234();
    extern void isr235();
    extern void isr236();
    extern void isr237();
    extern void isr238();
    extern void isr239();
    extern void isr240();
    extern void isr241();
    extern void isr242();
    extern void isr243();
    extern void isr244();
    extern void isr245();
    extern void isr246();
    extern void isr247();
    extern void isr248();
    extern void isr249();
    extern void isr250();
    extern void isr251();
    extern void isr252();
    extern void isr253();
    extern void isr254();
    extern void isr255();

    extern void x86_irq_handler(arch::irq_regs *regs);
}

#endif