/*!
 * @file threads.h
 * @brief Declarations for thread interaction functionality
 */
#ifndef _METERPRETER_SOURCE_EXTENSION_ANTIVENIN_THREADS_H
#define _METERPRETER_SOURCE_EXTENSION_ANTIVENIN_THREADS_H

DWORD initialize_threads();
DWORD request_thread_trace(Remote *remote, Packet *packet);
DWORD request_thread_kill(Remote *remote, Packet *packet);
DWORD request_thread_find_references(Remote *remote, Packet *packet);
DWORD request_thread_get_times(Remote *remote, Packet *packet);

#endif
