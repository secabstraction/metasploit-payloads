/*!
 * @file memory.h
 * @brief Declarations for memory interaction functionality
 */
#ifndef _METERPRETER_SOURCE_EXTENSION_ANTIVENIN_MEMORY_H
#define _METERPRETER_SOURCE_EXTENSION_ANTIVENIN_MEMORY_H

DWORD initialize_memory();
DWORD request_memory_search(Remote *remote, Packet *packet);
DWORD request_memory_dump_process(Remote *remote, Packet *packet);
DWORD request_memory_dump_segment(Remote *remote, Packet *packet);
DWORD request_memory_map_pages(Remote *remote, Packet *packet);

#endif
