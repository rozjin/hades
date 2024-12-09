#include <fs/vfs.hpp>
#include <sys/sched/sched.hpp>

bool sched::process_env::load_elf(const char *path, vfs::fd *fd) {
    return arch::loader::load_elf(path, fd, this);
}

void sched::process_env::set_entry() {
    arch::loader::set_entry(this);
}

void sched::process_env::load_params(char **argv, char** envp) {
    arch::loader::load_params(argv, envp, this);

}
void sched::process_env::place_params(char **envp, char **argv, thread *target) {
    arch::loader::place_params(envp, argv, target, this);
}

uint64_t *sched::process_env::place_args(uint64_t* location) {
    return arch::loader::place_args(location, this);
}

uint64_t *sched::process_env::place_auxv(uint64_t *location) {
    return arch::loader::place_auxv(location, this);
}