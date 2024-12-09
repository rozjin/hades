#include <sys/sched/sched.hpp>
#include <arch/x86/types.hpp>
#include <arch/types.hpp>

void x86::loader::place_params(char **envp, char **argv, sched::thread *task, sched::process_env *env) {
    uint64_t *location = (uint64_t *) task->ustack;
    uint64_t args_location = (uint64_t) location;

    location = x86::loader::place_args(location, env);
    location = x86::loader::place_auxv(location, env);

    *(--location) = 0;
    location -= env->params.envc;
    for (size_t i = 0; i < (size_t) env->params.envc; i++) {
        args_location -= strlen(env->params.envp[i]) + 1;
        location[i] = args_location;
    }

    *(--location) = 0;
    location -= env->params.argc;
    for (size_t i = 0; i < (size_t) env->params.argc; i++) {
        args_location -= strlen(env->params.argv[i]) + 1;
        location[i] = args_location;
    }

    *(--location) = env->params.argc;
    task->ctx.reg.rsp = (uint64_t) location;
}

log::subsystem logger = log::make_subsystem("ELF");
bool x86::loader::load_elf(const char *path, vfs::fd *fd, sched::process_env *env) {
    if (!fd) {
        return false;
    }

    env->file.ctx = env->proc->mem_ctx;
    auto res = env->file.init(fd);
    if (!res) return false;

    env->file.load_aux();
    env->file.load();

    env->entry = env->file.aux.at_entry;
    env->has_interp = env->file.load_interp(&env->interp_path);

    vfs::close(fd);

    if (env->has_interp) {
        fd = vfs::open(nullptr, env->interp_path, fd->table, 0, 0);
        kmsg(logger, "fd: %lx, path: %s", fd, env->interp_path);
        if (!fd) {
            kfree(env->interp_path);
            return -1;
        }

        env->interp.ctx = env->proc->mem_ctx;
        env->interp.load_offset = 0x40000000;
        env->interp.fd = fd;

        res = env->interp.init(fd);
        if (!res) {
            kfree(env->interp_path);
            vfs::close(fd);
            return false;
        }

        env->interp.load_aux();
        env->interp.load();

        env->entry = env->interp.aux.at_entry;

        vfs::close(fd);
    }

    env->file_path = (char *) kmalloc(strlen(path) + 1);
    strcpy(env->file_path, path);

    env->is_loaded = true;

    return true;
}

uint64_t *x86::loader::place_args(uint64_t *location, sched::process_env *env) {
    for (size_t i = 0; i < (size_t) env->params.envc; i++) {
        location = (uint64_t *)((char *) location - (strlen(env->params.envp[i]) + 1));
        strcpy((char *) location, env->params.envp[i]);
    }

    for (size_t i = 0; i < (size_t) env->params.argc; i++) {
        location = (uint64_t *)((char *) location - (strlen(env->params.argv[i]) + 1));
        strcpy((char *) location, env->params.argv[i]);
    }

    location = (uint64_t *) ((uint64_t) location & -16ll);

    if ((env->params.argc + env->params.envc + 1) & 1) {
        location--;
    }

    return location;
}

uint64_t *x86::loader::place_auxv(uint64_t *location, sched::process_env *env) {
    location -= 10;

    location[0] = ELF_AT_PHNUM;
    location[1] = env->file.aux.at_phnum;

    location[2] = ELF_AT_PHENT;
    location[3] = env->file.aux.at_phent;

    location[4] = ELF_AT_PHDR;
    location[5] = env->file.aux.at_phdr;

    location[6] = ELF_AT_ENTRY;
    location[7] = env->file.aux.at_entry;

    location[8] = 0; location[9] = 0;

    return location;
}

void x86::loader::load_params(char **argv, char **envp, sched::process_env *env) {
    for (;; env->params.envc++) {
        if (envp[env->params.envc] == nullptr) break;
    }

    for (;; env->params.argc++) {
        if (argv[env->params.argc] == nullptr) break;
    }

    env->params.argv = (char **) kmalloc(sizeof (char *) * env->params.argc);
    env->params.envp = (char **) kmalloc(sizeof (char *) * env->params.envc);

    for (size_t i = 0; i < (size_t) env->params.argc; i++) {
        env->params.argv[i] = (char *) kmalloc(strlen(argv[i] + 1));
        strcpy(env->params.argv[i], argv[i]);
    }

    for (size_t i = 0; i < (size_t) env->params.envc; i++) {
        env->params.envp[i] = (char *) kmalloc(strlen(envp[i] + 1));
        strcpy(env->params.envp[i], envp[i]);
    }
}

bool arch::loader::load_elf(const char *path, vfs::fd *fd, sched::process_env *env) {
    return x86::loader::load_elf(path, fd, env);
}

void arch::loader::set_entry(sched::process_env *env) {
    env->proc->main_thread->ctx.reg.rip = env->entry;
}

void arch::loader::load_params(char **argv, char **envp, sched::process_env *env) {
    x86::loader::load_params(argv, envp, env);
}

void arch::loader::place_params(char **envp, char **argv, sched::thread *task, sched::process_env *env) {
    x86::loader::place_params(envp, argv, task, env);
}

uint64_t *arch::loader::place_args(uint64_t *location, sched::process_env *env) {
    return x86::loader::place_args(location, env);
}

uint64_t *arch::loader::place_auxv(uint64_t *location, sched::process_env *env) {
    return x86::loader::place_auxv(location, env);
}