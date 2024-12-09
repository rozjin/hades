#include "frg/string.hpp"
#include "util/misc.hpp"
#include <frg/utility.hpp>
#include <util/log/log.hpp>
#include <util/string.hpp>
#include <frg/vector.hpp>
#include <cstdint>
#include <mm/mm.hpp>
#include <cstddef>
#include <fs/fat.hpp>
#include <fs/vfs.hpp>
#include <fs/dev.hpp>

static constexpr size_t FAT12 = 0x1;
static constexpr size_t FAT16 = 0x2;
static constexpr size_t FAT32 = 0x3;

static bool is_dir(uint8_t attrs) {
    return attrs & 0x10;
}

static bool is_bad(uint32_t entry) {
    switch (entry) {
        case 0xFF7:
        case 0xFFF7:
        case 0x0FFFFFF7:
            return true;
        default:
            return false;
    }
}

bool vfs::fatfs::is_eof(uint32_t entry) {
    if (entry == 0) return true;
    switch (this->type) {
        case FAT12:
            if (entry >= 0x0FF8) return true;
            break;
        case FAT16:
            if (entry >= 0xFFF8) return true;
            break;
        case FAT32:
            if (entry >= 0x0FFFFFF8) return true;
            break;
    }

    return false;
}

uint32_t vfs::fatfs::rw_entry(size_t cluster, bool rw, size_t val) {
    uint32_t entry = -1;

    size_t fatEntOffset = -1;
    size_t fatSz = this->superblock->secPerFAT != 0 ? this->superblock->secPerFAT : this->superblock->ebr.nEBR.secPerFAT;
    switch (this->type) {
        case FAT12:
            fatEntOffset = cluster + (cluster / 2);
            break;
        case FAT16:
        case FAT32:
            fatEntOffset = cluster;
            break;
    }

    switch (this->type) {
        case FAT12:
            entry = ((uint8_t *) fat)[fatEntOffset];
            if (cluster & 0x0001) {
                entry >>= 4;
            } else {
                entry &= 0xFFF;
            }
            break;
        case FAT16:
            entry = ((uint16_t *) fat)[fatEntOffset];
            break;
        case FAT32:
            entry = ((uint32_t *) fat)[fatEntOffset] & 0x0FFFFFFF;
            break;
    }

    if (rw) {
        if (is_bad(entry)) {
            return -1;
        }

        switch (this->type) {
            case FAT12:
                if (cluster & 0x0001) {
                    val <<= 4;
                    ((uint16_t *) fat)[fatEntOffset] &= 0x000F;
                } else {
                    val &= 0x0FFF;
                    ((uint16_t *) fat)[fatEntOffset] &= 0xF000;
                }
                ((uint16_t *) fat)[fatEntOffset] &= val;
                break;
            case FAT16:
                ((uint16_t *) fat)[fatEntOffset] = val;
                break;
            case FAT32:
                val = val & 0x0FFFFFFF;
                ((uint32_t *) fat)[fatEntOffset] &= 0xF0000000;
                ((uint32_t *) fat)[fatEntOffset] |= val;
                break;
        }

        devfs->write(this->source, fat, fatSz * this->superblock->bytesPerSec, this->superblock->rsvdSec);
        return val;
    }

    return entry;
}

size_t cluster_to_lba(size_t firstClusterLBA, size_t cluster, size_t secPerClus) {
    return ((cluster - 2) * secPerClus) + firstClusterLBA;
}

vfs::fatfs::rw_result vfs::fatfs::rw_clusters(size_t begin, void *buf, size_t offset, size_t len, bool read_all, bool rw) {
    if (rw) {
        if (len <= 0) return {};
        size_t cluster_count = len / (superblock->bytesPerSec * superblock->secPerClus);
        frg::vector<size_t, memory::mm::heap_allocator> cluster_chain{};
        for (size_t i = 0; i < cluster_count; i++) {
            cluster_chain.push_back(free_list.pop());
        }

        size_t buf_offset = 0;
        size_t sec_offset = 0;
        const size_t clus_size = superblock->secPerClus * superblock->bytesPerSec;
        switch(this->type) {
            case FAT12:
            case FAT16:
                sec_offset = superblock->rsvdSec + (superblock->n_fat * superblock->secPerFAT) + (superblock->n_root * 32 + superblock->bytesPerSec - 1) / superblock->bytesPerSec;
                break;
            case FAT32:
                sec_offset = superblock->rsvdSec + (superblock->n_fat * superblock->secPerFAT);
        }

        for (size_t clus = cluster_chain.pop(); cluster_chain.size() != 0; clus = cluster_chain.pop(), buf_offset = buf_offset + clus_size) {
            if (devfs->write(this->source, (char *) buf + buf_offset, clus_size, sec_offset + (clus * superblock->secPerClus)) < 0) {
                memory::mm::allocator::free(buf);
                return {};
            }
        }

        return {buf, (size_t) len};
    } else {
        frg::vector<size_t, memory::mm::heap_allocator> cluster_chain{};
        uint32_t entry = begin;
        size_t clus_size = superblock->secPerClus * superblock->bytesPerSec;

        if (offset > 0) {
            int skip_clusters = offset / clus_size;
            do {
                if (skip_clusters <= 0) cluster_chain.push_back(entry);
                skip_clusters--;

                entry = rw_entry(entry);
            } while (!is_bad(entry) && !is_eof(entry));
        } else {
            do {
                cluster_chain.push_back(entry);
                entry = rw_entry(entry);
            } while (!is_bad(entry) && !is_eof(entry));
        }

        size_t ret_len = clus_size * cluster_chain.size();
        char *clus_buf = (char *) kmalloc(ret_len);

        size_t fatSz = this->superblock->secPerFAT != 0 ? this->superblock->secPerFAT : this->superblock->ebr.nEBR.secPerFAT;

        size_t firstClusterLBA = superblock->rsvdSec + (superblock->n_fat * fatSz);

        size_t num_blocks;
        if (read_all) {
            num_blocks = cluster_chain.size();
        } else {
            num_blocks = util::ceil(offset + len, clus_size);
            while (num_blocks > cluster_chain.size()) num_blocks--;
        }

        auto clusters = cluster_chain.begin();
        for (size_t i = 0; i < num_blocks; i++) {
            auto clus = *clusters;
            auto res = devfs->read(this->source, clus_buf + (i * clus_size), clus_size,
                cluster_to_lba(firstClusterLBA, clus, superblock->secPerClus) * superblock->bytesPerSec);
            if (res < 0) {
                kfree(clus_buf);
                return {};
            }

            clusters++;
        }

        char *ret = nullptr;
        if (buf == nullptr) {
            if (!read_all) ret = (char *) kmalloc(len);
            else ret = (char *) kmalloc(ret_len);
        } else {
            ret = (char *) buf;
        }

        if (!read_all) {
            memcpy(ret, clus_buf + (offset % clus_size), len);
            kfree(clus_buf);
            return {ret, (size_t) len};
        }

        memcpy(ret, clus_buf, ret_len);
        kfree(clus_buf);
        return {ret, ret_len};
    }
}

static log::subsystem logger = log::make_subsystem("FS");
void vfs::fatfs::init_fs(node *root, node *source) {
    filesystem::init_fs(root, source);

    this->devfs = (vfs::devfs *) this->source->get_fs();
    auto device = this->source;

    // TODO: bad superblock detection

    this->superblock = (super *) kmalloc(512);
    devfs->read(device, this->superblock, 512, 0);

    size_t rootDirSectors = ((this->superblock->n_root * 32) + (this->superblock->bytesPerSec - 1)) / this->superblock->bytesPerSec;

    size_t fatSz = this->superblock->secPerFAT != 0 ? this->superblock->secPerFAT : this->superblock->ebr.nEBR.secPerFAT;
    size_t totSec = this->superblock->n_sectors != 0 ? this->superblock->n_sectors : this->superblock->large_sectors;

    size_t dataSec = totSec - (this->superblock->rsvdSec  + (this->superblock->n_fat + fatSz) + rootDirSectors);
    size_t n_clusters = dataSec / this->superblock->secPerClus;

    if (n_clusters < 4085) {
        this->type = FAT12;
    } else if (n_clusters < 65525) {
        this->type = FAT16;
    } else {
        this->type = FAT32;
    }

    fat = (uint8_t *) kmalloc(fatSz * this->superblock->bytesPerSec);
    devfs->read(device, fat, fatSz * this->superblock->bytesPerSec, this->superblock->rsvdSec * this->superblock->bytesPerSec);

    free_list = frg::vector<size_t, memory::mm::heap_allocator>{};
    free_list.resize(n_clusters);

    for (size_t i = 2; i < n_clusters; i++) {
        size_t entry = rw_entry(i);
        if (entry == 0)
            free_list.push_back(i);
    }

    this->last_free = -1;
    this->root->inum = this->superblock->ebr.nEBR.rootClus;
    this->root->meta->st_ino = this->root->inum;
    kmsg(logger, "Initialized");
}

bool fat_name_matches(const char *name, const char *other, size_t other_len) {
    char tmp[11] = "";

    size_t name_length = 0;
    auto s1 = name;
    while (*s1 != 0x20 && name_length < 8) {
        s1++;
        name_length++;
    }
    memcpy(tmp, name, name_length);

    size_t ext_length = 0;
    auto s2 = name + 8;
    while (*s2 != 0x20 && ext_length < 3) {
        s2++;
        ext_length++;
    }

    if (ext_length > 0) {
        tmp[name_length] = '.';
        memcpy(tmp + name_length + 1, name + 8, ext_length);
    }

    auto len = frg::min(size_t(11), other_len);
    auto matches = strncasecmp(tmp, other, len) == 0;
    return matches;
}

char *fat_stitch_name(const char *name) {
    char *tmp = (char *) kmalloc(11);

    size_t name_length = 0;
    auto s1 = name;
    while (*s1 != 0x20 && name_length < 8) {
        s1++;
        name_length++;
    }
    memcpy(tmp, name, name_length);

    size_t ext_length = 0;
    auto s2 = name + 8;
    while (*s2 != 0x20 && ext_length < 3) {
        s2++;
        ext_length++;
    }

    if (ext_length > 0) {
        tmp[name_length] = '.';
        memcpy(tmp + name_length + 1, name + 8, ext_length);
    }

    tmp[name_length + 1 + ext_length + 1] = '\0';
    return tmp;
}

ssize_t vfs::fatfs::readdir(node *dir) {
    auto res = rw_clusters(dir->inum, nullptr, 0, 0, true);

    fatEntry *ents = (fatEntry *) res.get<0>();
    size_t numEnts = res.get<1>() / sizeof(fatEntry);

    for (size_t j = 0; j < numEnts; j++) {
        fatEntry ent = ents[j];

        if (ent.name[0] == 0) break;
        if ((uint8_t) ent.name[0] == 0xE5) continue;
        if ((ent.attr & 0x0F) == 0x0F) continue;

        uint8_t attrs = ent.attr & 0x3F;
        uint32_t clus = ent.clus_lo | (ent.clus_hi << 16);

        auto name = fat_stitch_name(ent.name);
        auto new_node = frg::construct<vfs::node>(memory::mm::heap, this, name, dir, 0, is_dir(attrs) ? node::type::DIRECTORY :  node::type::FILE, clus);
        kfree(name);
        dir->children.push_back(new_node);

        new_node->stat()->st_ino = clus;
        if (!is_dir(attrs)) {
            new_node->stat()->st_size = ent.size;
        }

        kfree(ents);
    }

    kfree(ents);
    return 0;
}

vfs::node *vfs::fatfs::lookup(node *parent, frg::string_view name) {
    auto res = rw_clusters(parent->inum, nullptr, 0, 0, true);

    fatEntry *ents = (fatEntry *) res.get<0>();
    size_t numEnts = res.get<1>() / sizeof(fatEntry);

    node *new_node = nullptr;
    for (size_t j = 0; j < numEnts; j++) {
        fatEntry ent = ents[j];

        if (ent.name[0] == 0) break;
        if ((uint8_t) ent.name[0] == 0xE5) continue;
        if ((ent.attr & 0x0F) == 0x0F) continue;

        uint8_t attrs = ent.attr & 0x3F;
        if (fat_name_matches(ent.name, name.data(), name.size())) {
            // not yet there
            uint32_t clus = ent.clus_lo | (ent.clus_hi << 16);
            new_node = frg::construct<vfs::node>(memory::mm::heap, this, name, parent, 0, is_dir(attrs) ? node::type::DIRECTORY :  node::type::FILE, clus);
            parent->children.push_back(new_node);

            new_node->stat()->st_ino = clus;
            if (!is_dir(attrs)) {
                new_node->stat()->st_size = ent.size;
            }

            kfree(ents);
            return new_node;
        }
    }

    kfree(ents);
    return nullptr;
}

ssize_t vfs::fatfs::read(node *file, void *buf, size_t len, off_t offset) {
    auto clus = file->inum;
    auto res = rw_clusters(clus, buf, offset, len);

    return res.get<1>();
}

ssize_t vfs::fatfs::write(node *file, void *buf, size_t len, off_t offset) {
    return 0;
}

ssize_t vfs::fatfs::create(node *dst, path name, int64_t type, int64_t flags) {
    return 0;
}

ssize_t vfs::fatfs::mkdir(node *dst, frg::string_view name, int64_t flags) {
    return 0;
}

ssize_t vfs::fatfs::remove(node *dest) {
    return 0;
}

