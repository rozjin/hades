#include <arch/vmm.hpp>
#include <lai/core.h>
#include <cstddef>
#include <cstdint>
#include <mm/common.hpp>
#include <sys/acpi.hpp>
#include <util/string.hpp>
#include <util/log/log.hpp>
#include <util/log/panic.hpp>

#define member(structType, elementType, structPtr, memberName) \
  ((elementType*)(((char*)(structPtr)) + offsetof(structType, memberName)))

acpi::fadt *_fadt = nullptr;
acpi::xsdt *_xsdt = nullptr;
acpi::rsdt *_rsdt = nullptr;
acpi::rsdp *_rsdp = nullptr;

bool use_xsdt = false;;
bool use_x_dsdt = false;

namespace acpi {
    namespace madt {
        frg::vector<ioapic *, memory::mm::heap_allocator> ioapics{};
        frg::vector<iso *, memory::mm::heap_allocator> isos{};
        frg::vector<nmi *, memory::mm::heap_allocator> nmis{};
    };

    acpi::sdt *tables[22];

    uint8_t _rsdp_check() {
        uint8_t sum = 0;
        if (_rsdp->version == 0) {
            for (size_t i = 0; i < sizeof(acpi::rsdp) - 16; i++) {
                sum += ((uint8_t *) _rsdp)[i];
            }
        } else {
            for (size_t i = 0; i < sizeof(acpi::rsdp); i++) {
                sum += ((uint8_t *) _rsdp)[i];
            }
        }
        return sum;
    }

    uint8_t _rsdt_check() {
        uint8_t sum = 0;
        for (size_t i = 0; i < _rsdt->_sdt.length; i++) {
            sum += ((uint8_t *) _rsdt)[i];
        }
        return sum;
    }

    uint8_t _xsdt_check() {
        return 0;
        uint8_t sum = 0;
        for (size_t i = 0; i < _xsdt->_sdt.length; i++) {
            sum += ((uint8_t *) _xsdt)[i];
        }
        return sum;
    }
}

static log::subsystem logger = log::make_subsystem("ACPI");
acpi::sdt *find_table(const char *sig, size_t index) {
    acpi::sdt *ptr;
    size_t count = 0;

    if (use_xsdt) {
        for (size_t i = 0; i < (_xsdt->_sdt.length - sizeof(acpi::sdt)) / 8; i++) {
            ptr = (acpi::sdt *) _xsdt->ptrs[i];
            ptr = (acpi::sdt *) ((char *) ptr + memory::x86::virtualBase);
            if (!strncmp(ptr->signature, sig, 4)) {
                kmsg(logger, "Found table ", sig);
                if (index == count++) {
                    return ptr;
                }
            }
        }
    } else {
        for (size_t i = 0; i < (_rsdt->_sdt.length - sizeof(acpi::sdt)) / 4; i++) {
            ptr = (acpi::sdt *) ((uint64_t) _rsdt->ptrs[i]);
            ptr = (acpi::sdt *) ((char *) ptr + memory::x86::virtualBase);
            if (!strncmp(ptr->signature, sig, 4)) {
                kmsg(logger, "Found table ", sig);
                if (index == count++) {
                    return ptr;
                }
            }
        }
    }

    return nullptr;
}

acpi::sdt *acpi::table(const char *sig, size_t index) {
    if (!strncmp(sig, "DSDT", 4)) {
        if (use_x_dsdt) return (acpi::sdt *) (_fadt->x_dsdt + memory::x86::virtualBase);
        return (acpi::sdt *) (_fadt->dsdt + memory::x86::virtualBase); 
    }

    return find_table(sig, index);
}

void acpi::init(stivale::boot::tags::rsdp *info) {
    _rsdp = (acpi::rsdp *) (info->rsdp + memory::x86::virtualBase);
    if (!_rsdp) {
        panic("[ACPI] RSDP Not Found!");
    }

    if ((_rsdp_check() & 0xF) == 0) {
        kmsg(logger, "RSDP Checksum is %u", _rsdp_check());
    } else {
        panic("[ACPI] Corrupted RSDP!");
    }

    kmsg(logger, "OEM ID %s", _rsdp->oemid);
    kmsg(logger, "RSDT Address is %x", _rsdp->rsdt);
    kmsg(logger, "ACPI Version %u", _rsdp->version);

    _rsdt = (acpi::rsdt *) ((uint64_t) _rsdp->rsdt);
    if (_rsdp->version >= 2) {
        kmsg(logger, "XSDT Address is ", _rsdp->xsdt);
        kmsg(logger, "RSDP (ACPI V2) Checksum is %u", _xsdt_check());
        if ((_xsdt_check() % 0x100) != 0) {
            panic("[ACPI] Corrupted XSDT!");
        }

        use_xsdt = true;
        _xsdt = (acpi::xsdt *) _rsdp->xsdt;
    } else {
        if ((_rsdt_check() % 0x100) != 0) {
            panic("[ACPI] Corrupted RSDT! %u", _rsdt_check());
        }
    }

    _rsdt = memory::add_virt(_rsdt);
    _xsdt = memory::add_virt(_xsdt);
    _fadt = (fadt *) find_table("FACP", 0);
    if (((uint64_t) _fadt) - memory::x86::virtualBase >= vmm::limit_4g) {
        use_x_dsdt = true;
    }

    lai_set_acpi_revision(_rsdp->version);
}

void acpi::madt::init() {
    _madt = (madt::header *) acpi::table("APIC", 0);
    uint64_t table_size = _madt->table.length - sizeof(madt::header);
    uint64_t list = (uint64_t) _madt + sizeof(madt::header);
    uint64_t offset = 0;
    while ((list + offset) < (list + table_size)) {
        uint8_t *item = (uint8_t *) (list + offset);
        switch (item[0]) {
            case 0: {
                break;
            };

            case 1: {
                madt::ioapic *ioapic = (madt::ioapic *) item;
                kmsg(logger, "Found IOAPIC %u", ioapic->id);
                ioapics.push_back(ioapic);
                break;
            };

            case 2: {
                madt::iso *iso = (madt::iso *) item;
                kmsg(logger, "Found ISO %u", isos.size());
                isos.push_back(iso);
                break;
            };

            case 4: {
                madt::nmi *nmi = (madt::nmi *) item;
                kmsg(logger, "Found NMI %u", nmis.size());
                nmis.push_back(nmi);
                break;
            };

            default:
                kmsg(logger, "Unrecognized MADT Entry %u", item[0]);
                break;
        }

        offset = offset + item[1];
    }
}