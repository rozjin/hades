#ifndef EVTABLE_HPP
#define EVTABLE_HPP

#include <cstddef>

namespace evtable {
   constexpr size_t FUTEX_WAKE = 0x1;
   constexpr size_t KB_PRESS = 0x2;
   constexpr size_t PROCESS_STATUS_CHANGE = 0x3;
   constexpr size_t ARP_FIN = 0x4;
   constexpr size_t TIME_WAKE = 0x5;
   constexpr size_t NEW_MESSAGE = 0x6;
   constexpr size_t BLOCK_READ = 0x7;
   constexpr size_t BLOCK_WRITE = 0x8;
   constexpr size_t BLOCK_FIN = 0xA1;
   constexpr size_t SIGNAL = 0x9;
}

#endif