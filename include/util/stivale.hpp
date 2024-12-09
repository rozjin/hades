#ifndef STIVALE_HPP
#define STIVALE_HPP

#include <cstdint>
#include <cstddef>
#include <mm/common.hpp>
#include <util/misc.hpp>

namespace stivale {
    struct [[gnu::packed]] tag {
        uint64_t identifier;
        uint64_t next;
    };

    /* --- Header --------------------------------------------------------------- */
    /*  Information passed from the kernel to the bootloader                      */

    namespace kernel {
        struct header {
            uint64_t main;
            uint64_t stack;
            uint64_t flags;
            uint64_t tags;
        };

        struct tag_id {
            enum {
                framebuffer = 0x3ecc1bc43d0f7971,
                smp = 0x1ab015085f3273df,
                pg5 = 0x932f477032007e8f
            };
        };

        namespace tags {
            struct [[gnu::packed]] framebuffer {
                struct stivale::tag tag;
                uint16_t width;
                uint16_t height;
                uint16_t bpp;
            };

            struct [[gnu::packed]] smp {
                struct stivale::tag tag;
                uint64_t flags;
            };
        }
    };

    /* --- Struct --------------------------------------------------------------- */
    /*  Information passed from the bootloader to the kernel                      */

    namespace boot {
        struct tag_id {
            enum {
                cmdline = 0xe5e76a1b4597a781,
                mmap = 0x2187f79e8612de07,
                framebuffer = 0x506461d2950408fa,
                modules = 0x4b6fe466aade04ce,
                rsdp = 0x9e1786930a375e78,
                epoch = 0x566a7bed888e1407,
                firmware = 0x359d837855e3858c,
                smp = 0x34d1d96339647025
            };
        };

        struct [[gnu::packed]] header {
            char brand[64];
            char version[64];

            uint64_t tags;
        };

        namespace info {
            struct type {
                enum {
                    USABLE = 1,
                    RESERVED = 2,
                    ACPI_RECLAIMABLE = 3,
                    ACPI_NVS = 4,
                    BAD_MEMORY = 5,
                    BOOTLOADER_RECLAIMABLE = 0x1000,
                    KERNEL_AND_MODULES = 0x1001
                };
            };

            struct [[gnu::packed]] region {
                uint64_t base;
                uint64_t length;
                uint32_t type;
                uint32_t unused;

                size_t end() {
                    return base + length;
                }
            };

            struct [[gnu::packed]] module {
                uint64_t begin;
                uint64_t end;

                char string[128];
            };

            struct [[gnu::packed]] processor {
                uint32_t processor_id;
                uint32_t lapic_id;
                uint64_t target_stack;
                uint64_t goto_address;
                uint64_t extra_argument;
            };
        };

        namespace tags {
            struct [[gnu::packed]] args {
                stivale::tag tag;
                uint64_t cmdline;
            };

            struct [[gnu::packed]] region_map {
                stivale::tag tag;
                uint64_t entries;
                stivale::boot::info::region regionmap[];

                stivale::boot::info::region *begin() {
                    return regionmap;
                }

                stivale::boot::info::region *end() {
                    return &regionmap[entries];
                }

                size_t page_count() {
                    uintptr_t highest_page = 0;
                    for (size_t i = 0; i < entries; i++) {
                        if (regionmap[i].type != info::type::USABLE) {
                            continue;
                        }

                        uintptr_t top = regionmap[i].base + regionmap[i].length;

                        if (top > highest_page) {
                            highest_page = top;
                        }
                    }

                    return highest_page / memory::page_size;
                }

                void *find_free(size_t length) {
                    for (size_t i = 0; i < entries; i++) {
                        auto& region = regionmap[i];
                        if (region.base < 0x100000) {
                            continue;
                        }

                        if (region.type != info::type::USABLE) {
                            continue;
                        }

                        if (region.length < length) {
                            continue;
                        }

                        return (void *) region.base;
                    }

                    return nullptr;
                }
            };

            struct [[gnu::packed]] framebuffer {
                stivale::tag tag;
                uint64_t addr;
                uint16_t width;
                uint16_t height;
                uint16_t pitch;
                uint16_t bpp;
                
                uint8_t memory_model;
                uint8_t  red_mask_size;
                uint8_t  red_mask_shift;
                uint8_t  green_mask_size;
                uint8_t  green_mask_shift;
                uint8_t  blue_mask_size;
                uint8_t  blue_mask_shift;
                uint8_t  unused;
            };

            struct [[gnu::packed]] modules {
                stivale::tag tag;
                uint64_t module_count;
                stivale::boot::info::module modules[];
            };

            struct [[gnu::packed]] rsdp {
                stivale::tag tag;
                uint64_t rsdp;
            };

            struct [[gnu::packed]] epoch {
                stivale::tag tag;
                uint64_t epoch;
            };

            struct [[gnu::packed]] firmware {
                stivale::tag tag;
                uint64_t flags;
            };

            struct [[gnu::packed]] smp {
                stivale::tag tag;
                uint64_t identifier;
                uint64_t next;
                uint64_t cpu_count;
                stivale::boot::info::processor processors[];

                stivale::boot::info::processor *begin() {
                    return memory::add_virt(processors);
                }

                stivale::boot::info::processor *end() {
                    return &(memory::add_virt(processors)[cpu_count]);
                }

                stivale::boot::info::processor *get_cpu(size_t lid) {
                    for (size_t i = 0; i < cpu_count; i++) {
                        auto cpu = memory::add_virt(processors)[i];
                        if (cpu.lapic_id == lid) {
                            return &(memory::add_virt(processors)[i]);
                        }
                    }

                    return nullptr;
                }
            };
        };
    };

    class info_parser {
        private:
            stivale::boot::header *header;
        public:
            info_parser() {
                this->header = nullptr;
            }

            info_parser(stivale::boot::header *header) {
                this->header = memory::add_virt(header);
            }

            stivale::boot::tags::framebuffer *fb() {
                for (uint64_t tag = header->tags; tag != 0; tag = ((stivale::tag *) tag)->next) {
                    if (((stivale::tag *) tag)->identifier == stivale::boot::tag_id::framebuffer) {
                        return (stivale::boot::tags::framebuffer *) tag;
                    }
                }

                return nullptr;
            }

            stivale::boot::tags::smp *smp() {
                for (uint64_t tag = memory::add_virt(header)->tags; tag != 0; tag = (memory::add_virt(((stivale::tag *) tag))->next)) {
                    if (memory::add_virt(((stivale::tag *) tag))->identifier == stivale::boot::tag_id::smp) {
                        return memory::add_virt((stivale::boot::tags::smp *) tag);
                    }
                }

                return nullptr;
            }

            stivale::boot::tags::rsdp *rsdp() {
                for (uint64_t tag = header->tags; tag != 0; tag = ((stivale::tag *) tag)->next) {
                    if (((stivale::tag *) tag)->identifier == stivale::boot::tag_id::rsdp) {
                        return (stivale::boot::tags::rsdp *) tag;
                    }
                }

                return nullptr;
            }

            stivale::boot::tags::region_map *mmap() {
                for (uint64_t tag = header->tags; tag != 0; tag = ((stivale::tag *) tag)->next) {
                    if (((stivale::tag *) tag)->identifier == stivale::boot::tag_id::mmap) {
                        return (stivale::boot::tags::region_map *) tag;
                    }
                }

                return nullptr;
            }

            stivale::boot::tags::modules *modules() {
                for (uint64_t tag = header->tags; tag != 0; tag = ((stivale::tag *) tag)->next) {
                    if (((stivale::tag *) tag)->identifier == stivale::boot::tag_id::modules) {
                        return (stivale::boot::tags::modules *) tag;
                    }
                }

                return nullptr;
            }
    };

    inline stivale::info_parser parser{};
};

#endif