#include "mm/mm.hpp"
#include "util/types.hpp"
#include <sys/sched/sched.hpp>
#include <arch/x86/types.hpp>
#include <arch/types.hpp>

void sched::process_env::place_params(char **envp, char **argv, sched::thread *task) {
    uint64_t *location = (uint64_t *) task->ustack;
    uint64_t args_location = (uint64_t) location;

    location = place_args(location);
    location = place_auxv(location);

    *(--location) = 0;
    location -= params.envc;
    for (size_t i = 0; i < (size_t) params.envc; i++) {
        args_location -= strlen(params.envp[i]) + 1;
        location[i] = args_location;
    }

    *(--location) = 0;
    location -= params.argc;
    for (size_t i = 0; i < (size_t) params.argc; i++) {
        args_location -= strlen(params.argv[i]) + 1;
        location[i] = args_location;
    }

    *(--location) = params.argc;
    task->ctx.reg.rsp = (uint64_t) location;
}

bool sched::process_env::load_elf(const char *path, shared_ptr<vfs::fd> fd) {
    if (!fd) {
        return false;
    }

    file.ctx = proc->mem_ctx;
    auto res = file.init(fd);
    if (!res) return false;

    file.load_aux();
    file.load();

    entry = file.aux.at_entry;
    has_interp = file.load_interp(&interp_path);

    vfs::close(fd);

    if (has_interp) {
        if (fd->table.expired()) {
            kfree(interp_path);
            return -1;
        }

        fd = vfs::open(nullptr, interp_path, fd->table.lock(), 0, 0, 0, 0);
        if (!fd) {
            kfree(interp_path);
            return -1;
        }

        interp.ctx = proc->mem_ctx;
        interp.load_offset = 0x40000000;
        interp.fd = fd;

        res = interp.init(fd);
        if (!res) {
            kfree(interp_path);
            vfs::close(fd);
            return false;
        }

        interp.load_aux();
        interp.load();
        entry = interp.aux.at_entry;

        vfs::close(fd);
    }

    file_path = (char *) kmalloc(strlen(path) + 1);
    strcpy(file_path, path);

    is_loaded = true;
    return true;
}

uint64_t *sched::process_env::place_args(uint64_t *location) {
    for (size_t i = 0; i < (size_t) params.envc; i++) {
        location = (uint64_t *)((char *) location - (strlen(params.envp[i]) + 1));
        strcpy((char *) location, params.envp[i]);
    }

    for (size_t i = 0; i < (size_t) params.argc; i++) {
        location = (uint64_t *)((char *) location - (strlen(params.argv[i]) + 1));
        strcpy((char *) location, params.argv[i]);
    }

    location = (uint64_t *) ((uint64_t) location & -16LL);

    if ((params.argc + params.envc + 1) & 1) {
        location--;
    }

    return location;
}

uint64_t *sched::process_env::place_auxv(uint64_t *location) {
    location -= 10;

    location[0] = ELF_AT_PHNUM;
    location[1] = file.aux.at_phnum;

    location[2] = ELF_AT_PHENT;
    location[3] = file.aux.at_phent;

    location[4] = ELF_AT_PHDR;
    location[5] = file.aux.at_phdr;

    location[6] = ELF_AT_ENTRY;
    location[7] = file.aux.at_entry;

    location[8] = 0; location[9] = 0;

    return location;
}

void sched::process_env::load_params(char **argv, char **envp) {
    if (envp) {
        for (;; params.envc++) {
            if (envp[params.envc] == nullptr) break;
        }        
    }

    if (argv) {
        for (;; params.argc++) {
            if (argv[params.argc] == nullptr) break;
        }        
    }

    params.argv = (char **) kmalloc(sizeof (char *) * params.argc);
    params.envp = (char **) kmalloc(sizeof (char *) * params.envc);

    for (size_t i = 0; i < (size_t) params.argc; i++) {
        params.argv[i] = (char *) kmalloc(strlen(argv[i] + 1));
        strcpy(params.argv[i], argv[i]);
    }

    for (size_t i = 0; i < (size_t) params.envc; i++) {
        params.envp[i] = (char *) kmalloc(strlen(envp[i] + 1));
        strcpy(params.envp[i], envp[i]);
    }
}

void sched::process_env::set_entry() {
    proc->main_thread->ctx.reg.rip = entry;
}