#ifndef EXT2_HPP
#define EXT2_HPP

#include "util/types.hpp"
#include <frg/vector.hpp>
#include <cstddef>
#include <cstdint>
#include <frg/allocation.hpp>
#include <frg/hash.hpp>
#include <frg/hash_map.hpp>
#include <mm/mm.hpp>
#include <fs/vfs.hpp>
#include <fs/dev.hpp>

namespace vfs {
    constexpr size_t EXT2_SIGNATURE = 0xEF53;
    class ext2fs: public vfs::filesystem {
        private:
            struct [[gnu::packed]] super {
                uint32_t inode_count;
                uint32_t block_count;
                uint32_t sb_reserved;
                uint32_t unallocated_blocks;
                uint32_t unallocated_inodes;
                uint32_t sb_block;
                uint32_t block_size;
                uint32_t frag_size;
                uint32_t blocks_per_group;
                uint32_t frags_per_group;
                uint32_t inodes_per_group;
                uint32_t last_mnt_time;
                uint32_t last_written_time;
                uint16_t mnt_count;
                uint16_t mnt_allowed;
                uint16_t signature;
                uint16_t fs_state;
                uint16_t error_response;
                uint16_t version_min;
                uint32_t last_fsck;
                uint32_t forced_fsck;
                uint32_t os_id;
                uint32_t version_maj;
                uint16_t user_id;
                uint16_t group_id;
                uint32_t first_inode;
                uint16_t inode_size;
                uint16_t sb_bgd;
                uint32_t opt_features;
                uint32_t req_features;
                uint32_t non_supported_features;
                uint64_t uuid[2];
                uint64_t volume_name[2];
                uint64_t last_mnt_path[8];
            };

            struct [[gnu::packed]] bgd {
                uint32_t block_addr_bitmap;
                uint32_t block_addr_inode;
                uint32_t inode_table_block;
                uint16_t unallocated_blocks;
                uint16_t unallocated_inodes;
                uint16_t dir_count;
                uint16_t reserved[7];
            };

            struct [[gnu::packed]] inode {
                uint16_t permissions;
                uint16_t uid;
                uint32_t size32l;
                uint32_t access_time;
                uint32_t creation_time;
                uint32_t mod_time;
                uint32_t del_time;
                uint16_t gid;
                uint16_t hard_link_count;
                uint32_t sector_count;
                uint32_t flags;
                uint32_t oss1;
                uint32_t blocks[15];
                uint32_t gen_num;
                uint32_t eab;
                uint32_t size32h;
                uint32_t frag_addr;
                char oss2[12];
            };

            struct [[gnu::packed]] dirent {
                uint32_t inode_index;
                uint16_t entry_size;
                uint8_t name_length;
                uint8_t dir_type;
            };

            struct ext2_private {
                dirent *dent;
                char *name;
                ext2_private *next;
            };

            super *superblock;
            uint64_t block_size;
            uint64_t frag_size;
            uint64_t bgd_count;

            int read_inode_entry(inode *inode, int index);
            int write_inode_entry(inode *inode, int index);

            int read_bgd(bgd *bgd, int index);
            int write_bgd(bgd *bgd, int index);

            int bgd_allocate_inode(bgd *bgd, int bgd_index);
            int bgd_allocate_block(bgd *bgd, int bgd_index);

            int allocate_inode();
            int allocate_block();

            int free_inode(uint32_t inode);
            int free_block(uint32_t block);

            int read_inode(inode *inode, void *buf, size_t count, off_t off);
            int write_inode(inode *inode, int index, void *buf, size_t count, off_t off);

            int inode_set_block(inode *inode, int index, uint32_t iblock, uint32_t block);
            int inode_get_block(inode *inode, uint32_t iblock, uint32_t *res);

            int read_dirents(inode *inode, ext2_private **files);
            int write_dirent(inode *dir, int dir_inode, const char *name, int inode, int type);

            int read_symlink(inode *inode, char **path);

            uint64_t read_inode_size(inode *inode) {
                return inode->size32l | ((uint64_t) inode->size32h << 32);
            }

            uint64_t write_inode_size(inode *inode, int index, uint64_t size) {
                inode->size32l = (uint32_t) size;
                inode->size32h = (uint32_t) (size >> 32);

                if (write_inode_entry(inode, index) == -1) {
                    return -1;
                }

                return 0;
            }
        public:
            ext2fs(shared_ptr<node> root, weak_ptr<node> device):
                vfs::filesystem(root, device) {}

            bool load() override;

            weak_ptr<node> lookup(shared_ptr<node> parent, frg::string_view name) override;
            ssize_t readdir(shared_ptr<node> dir) override;

            ssize_t read(shared_ptr<node> file, void *buf, size_t len, off_t offset) override;
            ssize_t write(shared_ptr<node> file, void *buf, size_t len, off_t offset) override;
            ssize_t truncate(shared_ptr<node> file, off_t offset) override;

            ssize_t create(shared_ptr<node> dst, path name, int64_t type, int64_t flags, mode_t mode,
                uid_t uid, gid_t gid) override;
            ssize_t mkdir(shared_ptr<node> dst, frg::string_view name, int64_t flags, mode_t mode,
                uid_t uid, gid_t gid) override;

            //ssize_t remove(node *dst) override;
            ssize_t unlink(shared_ptr<node> dst) override;
    };
}

#endif