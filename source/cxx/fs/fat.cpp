#include "frg/string.hpp"
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

static bool is_bad(uint32_t entry) {
    switch (entry) {
        case 0x0FF7:
        case 0xFFF7:
        case 0x0FFFFFF7:
            return true;
        default:
            return false;
    }
}

bool vfs::fatfs::is_eof(uint32_t entry) {
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

vfs::fatfs::rw_result vfs::fatfs::rw_clusters(size_t begin, void *buf, ssize_t offset, ssize_t len, bool rw) {
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

        return {buf, (size_t) len, cluster_chain};
    } else {
        frg::vector<size_t, memory::mm::heap_allocator> cluster_chain{};
        cluster_chain.push_back(begin);

        uint32_t entry = rw_entry(begin);

        size_t skip_clusters = offset / (superblock->secPerClus * superblock->bytesPerSec);
        size_t skipped = 0;

        while (!is_bad(entry) && !is_eof(entry)) {
            if (offset) {
                if (skipped < skip_clusters) cluster_chain.push_back(entry);
                skipped++;
            } else {
                cluster_chain.push_back(entry);
            }

            entry = rw_entry(entry);
        }

        size_t ret_len = (superblock->bytesPerSec * superblock->secPerClus * cluster_chain.size()) - offset;
        char *clus_buf = (char *) kmalloc(ret_len);

        size_t fatSz = this->superblock->secPerFAT != 0 ? this->superblock->secPerFAT : this->superblock->ebr.nEBR.secPerFAT;

        size_t buf_offset = 0;
        size_t sec_offset = superblock->rsvdSec + (superblock->n_fat * fatSz) + (((superblock->n_root * 32) + (superblock->bytesPerSec - 1)) / superblock->bytesPerSec);

        const size_t clus_size = superblock->secPerClus * superblock->bytesPerSec;
        for (size_t clus: cluster_chain) {
            if (devfs->read(this->source, clus_buf + buf_offset, clus_size, sec_offset + ((clus - 2) * superblock->secPerClus)) < 0) {
                memory::mm::allocator::free(clus_buf);
                return {};
            }

            if (len) {
                if (buf_offset > len) break;
            }

            buf_offset = buf_offset + clus_size;
        }

        char *ret = nullptr;
        if (buf == nullptr) {
            if (len) ret = (char *) kmalloc(len);
            else  ret = (char *) kmalloc(ret_len);
        } else {
            ret = (char *) buf;
        }

        if (len) {
            memcpy(ret, clus_buf, len);

            return {ret, (size_t) len, {}};
        } else {
            memcpy(ret, clus_buf, ret_len);
        }

        kfree(clus_buf);

        return {ret, ret_len, {}};
    }
}

void vfs::fatfs::init_fs(node *root, node *source) {
    filesystem::init_fs(root, source);

    static constexpr size_t BLKLMODE = 0x126;

    this->devfs = this->source->get_fs();
    auto device = this->source;
    this->devfs->ioctl(device, BLKLMODE, nullptr);

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
    devfs->read(device, fat, fatSz * this->superblock->bytesPerSec, this->superblock->rsvdSec);

    free_list = frg::vector<size_t, memory::mm::heap_allocator>{};
    free_list.resize(n_clusters);

    for (size_t i = 2; i < n_clusters; i++) {
        size_t entry = rw_entry(i);
        if (entry == 0)
            free_list.push_back(i);
    }

    this->last_free = -1;
}

bool is_name_eq(const char *name, const char *ref, size_t ref_len) {
    auto nameLength = frg::min((size_t) 7, ref_len);
    auto extLength = frg::min((size_t) 3, ref_len);

    auto hasExt = ref_len > 8;

    auto matchesName = strncmp(name, ref, nameLength) == 0;
    auto matchesExt = hasExt ? strncmp(name + 8, ref + 8, extLength) == 0 : true;

    return matchesExt && matchesName;
}

vfs::node *vfs::fatfs::lookup(const pathlist &filepath, vfs::path path, int64_t flags) {
    if (nodenames.contains(path)) return nodenames[path];
 
    fatEntry *ents = nullptr;
    size_t numEnts = 0;
    // we will populate the tree as we go along to avoid re-reads
    switch (this->type) {
        case FAT32: {
            size_t rootClus = this->superblock->ebr.nEBR.rootClus;
            kmsg("RootClus: ", rootClus);

            auto res = rw_clusters(rootClus, nullptr);
            
            ents = (fatEntry *) res.get<0>();
            numEnts = res.get<1>() / sizeof(fatEntry);
        }

        default: break;
    }


    vfs::path current_path = filepath[0];
    vfs::node *current_node = this->root;
    for (size_t i = 0; i < filepath.size(); i++) {
        for (size_t j = 0; j < numEnts; j++) {
            fatEntry ent = ents[j];

            if (ent.name[0] == 0) break;
            if ((uint8_t) ent.name[0] == 0xE5) continue;

            uint8_t attrs = ent.attr & 0x3F;
            if (is_name_eq(ent.name, filepath[i].data(), filepath[i].size())) {
                // not yet there
                if (i != filepath.size() - 1) {
                    if (!(attrs & 0x10)) return nullptr;

                    uint32_t clus = ent.clus_lo;
                    if (this->type == FAT32) clus |= (ent.clus_hi << 16);

                    auto res = rw_clusters(clus, nullptr);
            
                    ents = (fatEntry *) res.get<0>();
                    numEnts = res.get<1>() / sizeof(fatEntry);

                    // node(filesystem *fs, path name, path abspath, node *parent, ssize_t flags, ssize_t type)
                    current_node = frg::construct<vfs::node>(memory::mm::heap, this, filepath[i], current_path, current_node, 0, node::type::DIRECTORY);
                    current_node->stat()->st_ino = clus;

                    nodenames[current_path] = current_node;

                    joinPaths(current_path, filepath[i]);
                    break;
                } else {
                    if (attrs & 0x10) return nullptr;

                    uint32_t clus = ent.clus_lo;
                    if (this->type == FAT32) clus |= (ent.clus_hi << 16);

                    auto res = rw_clusters(clus, nullptr);

                    kmsg("File found: ", ent.name, ", size: ", ent.size);

                    current_node = frg::construct<vfs::node>(memory::mm::heap, this, filepath[i], current_path, current_node, 0, node::type::FILE);
                    current_node->stat()->st_ino = clus;
                    current_node->stat()->st_size = res.get<1>();

                    nodenames[current_path] = current_node;

                    return current_node;
                }
            }
        }
    }

    return nullptr;
}

vfs::ssize_t vfs::fatfs::read(node *file, void *buf, ssize_t len, ssize_t offset) {
    auto clus = file->stat()->st_ino;
    auto res = rw_clusters(clus, buf, offset, len);

    auto bytes = res.get<1>();
    if (bytes < 0) {
        return -error::IO;
    }

    return res.get<1>();
}

vfs::ssize_t vfs::fatfs::write(node *file, void *buf, ssize_t len, ssize_t offset) {
    return 0;
}

vfs::ssize_t vfs::fatfs::create(path name, node *parent, node *nnode, int64_t type, int64_t flags) {
    return 0;
}

vfs::ssize_t vfs::fatfs::mkdir(const pathlist& dirpath, int64_t flags) {
    return 0;
}

vfs::ssize_t vfs::fatfs::remove(node *dest) {
    return 0;
}

vfs::ssize_t vfs::fatfs::lsdir(node *dir, pathlist& names) {
    return 0;
}

