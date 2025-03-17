#include "arch/vmm.hpp"
#include "fs/vfs.hpp"
#include "mm/common.hpp"
#include "mm/mm.hpp"
#include "mm/pmm.hpp"
#include "mm/vmm.hpp"
#include "util/misc.hpp"
#include <cstddef>
#include <cstdint>
#include <util/elf.hpp>

bool check_hdr(elf::elf64_hdr *header) {
    uint32_t sig = *(uint32_t *) header;
    if (sig != ELF_SIGNATURE) {
        return false;
    }

    if (header->ident[ELF_EI_OSABI] != ELF_EI_SYSTEM_V && header->ident[ELF_EI_OSABI] != ELF_EI_LINUX) return false;
    if (header->ident[ELF_EI_DATA] != ELF_LITTLE_ENDIAN) return false;
    if (header->ident[ELF_EI_CLASS] != ELF_ELF64) return false;
    if (header->machine != ELF_MACH_X86_64 && header->machine != 0) return false;
    if (header->shstrndx == 0) return false;

    return true;
}

const char *extract_string(void *data, uint32_t index) {
    return (const char *)((char *) data + index);
}

elf::elf64_shdr *find_section(elf::file *file, uint32_t type, const char *name) {
    elf::elf64_shdr *shdr = file->shdrs;

    for (size_t i = 0; i < file->header->sh_num; i++) {
        if (shdr[i].sh_type != type) {
            continue;
        }

        const char *sec_name = extract_string(file->shstrtab, shdr[i].sh_name);
        if (strcmp(sec_name, name) == 0) {
            return &shdr[i];
        }
    }

    return nullptr;
}

bool init_symbols(elf::file *file) {
    if (file->symtab_hdr->sh_entsize != sizeof(elf::elf64_symtab)) {
        return false;
    }

    uint64_t ents = file->symtab_hdr->sh_size / file->symtab_hdr->sh_entsize;
    elf::elf64_symtab *symtab = (elf::elf64_symtab *) file->symtab;

    for (size_t i = 0; i < ents; i++) {
        if ((symtab[i].st_info & STT_FUNC) != STT_FUNC) {
            continue;
        }

        auto symbol = elf::symbol{
            .name = extract_string(file->strtab, symtab[i].st_name),
            .addr = symtab[i].st_value,
            .len = symtab[i].st_size
        };

        file->symbols.push_back(symbol);
    }

    return true;
}

bool elf::file::init(vfs::fd *fd) {
    this->fd = fd;

    elf64_hdr *hdr = (elf64_hdr *) kmalloc(64);
    auto res = vfs::read(fd, hdr, 64);
    if (res != 64) {
        kfree(hdr);
        return false;
    }

    res = check_hdr(hdr);
    if (!res) {
        kfree(hdr);
        return false;
    }

    this->header = hdr;
    this->phdrs = (elf64_phdr *) kcalloc(hdr->ph_num, sizeof(elf64_phdr));
    this->shdrs = (elf64_shdr *) kcalloc(hdr->sh_num, sizeof(elf64_shdr));

    vfs::lseek(fd, hdr->shoff, SEEK_SET);
    res = vfs::read(fd, shdrs, hdr->sh_num * sizeof(elf64_shdr));
    if (res < 0) {
        kfree(hdr);
        kfree(phdrs);
        kfree(shdrs);

        return false;
    }

    vfs::lseek(fd, hdr->phoff, SEEK_SET);
    res = vfs::read(fd, phdrs, hdr->ph_num * sizeof(elf64_phdr));
    if (res < 0) {
        kfree(hdr);
        kfree(phdrs);
        kfree(shdrs);

        return false;
    }

    shstrtab_hdr = shdrs + header->shstrndx;
    shstrtab = pmm::alloc(util::ceil(shstrtab_hdr->sh_size, memory::page_size));

    vfs::lseek(fd, shstrtab_hdr->sh_offset, SEEK_SET);
    res = vfs::read(fd, shstrtab, shstrtab_hdr->sh_size);

    if ((size_t) res != shstrtab_hdr->sh_size) {
        kfree(hdr);
        kfree(phdrs);
        kfree(shdrs);
        pmm::free(shstrtab);

        return false;
    }

    strtab_hdr = find_section(this, SHT_STRTAB, ".strtab");
    if (strtab_hdr == nullptr) {
        kfree(hdr);
        kfree(phdrs);
        kfree(shdrs);
        pmm::free(shstrtab);

        return false;
    }

    strtab = pmm::alloc(util::ceil(strtab_hdr->sh_size, memory::page_size));

    vfs::lseek(fd, strtab_hdr->sh_offset, SEEK_SET);
    res = vfs::read(fd, strtab, strtab_hdr->sh_size);

    if ((size_t) res != strtab_hdr->sh_size) {
        kfree(hdr);
        kfree(phdrs);
        kfree(shdrs);
        pmm::free(shstrtab);
        pmm::free(strtab);

        return false;
    }

    symtab_hdr = find_section(this, SHT_SYMTAB, ".symtab");
    if (symtab_hdr == nullptr) {
        kfree(hdr);
        kfree(phdrs);
        kfree(shdrs);
        pmm::free(shstrtab);
        pmm::free(strtab);

        return false;
    }

    symtab = pmm::alloc(util::ceil(symtab_hdr->sh_size, memory::page_size));

    vfs::lseek(fd, symtab_hdr->sh_offset, SEEK_SET);
    res = vfs::read(fd, symtab, symtab_hdr->sh_size);
    if ((size_t) res != symtab_hdr->sh_size) {
        kfree(hdr);
        kfree(phdrs);
        kfree(shdrs);
        pmm::free(shstrtab);
        pmm::free(strtab);
        pmm::free(symtab);

        return false;
    }

    res = init_symbols(this);
    if (!res) {
        kfree(hdr);
        kfree(phdrs);
        kfree(shdrs);
        pmm::free(shstrtab);
        pmm::free(strtab);
        pmm::free(symtab);

        return false;
    }

    return true;
}

void elf::file::load() {
    for (size_t i = 0; i < header->ph_num; i++) {
        if (phdrs[i].p_type != ELF_PT_LOAD) {
            continue;
        }

        elf64_phdr *phdr = &this->phdrs[i];
        uint64_t base = phdr->p_vaddr + load_offset ;

        size_t misalign = phdr->p_vaddr & (memory::page_size - 1);
        size_t pages = util::ceil(misalign + phdr->p_memsz, memory::page_size);

        if ((misalign + phdr->p_memsz) > memory::page_size) {
            pages = pages + 1;
        }

        vmm::map_flags flags = vmm::map_flags::READ | vmm::map_flags::USER | vmm::map_flags::FILL_NOW;
        if (phdr->p_flags & ELF_PF_W) flags |= vmm::map_flags::WRITE;

        ctx->map((void *)(base - misalign), pages * memory::page_size, flags, true);

        vfs::lseek(fd, phdr->p_offset, SEEK_SET);
        vfs::read(fd, (void *) base, phdr->p_filesz);
    }
}

bool elf::file::load_interp(char **interp_path) {
    elf64_phdr *interp_hdr = nullptr;

    for (size_t i = 0; i < header->ph_num; i++) {
        if (phdrs[i].p_type == ELF_PT_INTERP) {
            interp_hdr = &phdrs[i];
        }
    }

    if (interp_hdr == nullptr) {
        return false;
    }

    *interp_path = (char *) kmalloc(interp_hdr->p_filesz + 1);

    vfs::lseek(fd, interp_hdr->p_offset, SEEK_SET);
    vfs::read(fd, *interp_path, interp_hdr->p_filesz);

    return true;
}

void elf::file::load_aux() {
    aux.at_phdr = 0;
    aux.at_phent = sizeof(elf64_phdr);
    aux.at_phnum = header->ph_num;
    aux.at_entry = load_offset + header->entry;

    for (size_t i = 0; i < header->ph_num; i++) {
        if (phdrs[i].p_type == ELF_PT_PHDR) {
            aux.at_phdr = load_offset + phdrs[i].p_vaddr;
        }
    }
}