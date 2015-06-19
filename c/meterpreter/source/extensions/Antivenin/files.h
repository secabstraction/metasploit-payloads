 * @file files.h
 * @brief Declarations for file interaction functionality
 */
#ifndef _METERPRETER_SOURCE_EXTENSION_ANTIVENIN_FILES_H
#define _METERPRETER_SOURCE_EXTENSION_ANTIVENIN_FILES_H

DWORD initialize_file();
DWORD request_file_rawcopy(Remote *remote, Packet *packet);
DWORD request_file_get_hash(Remote *remote, Packet *packet);
DWORD request_file_find_hash(Remote *remote, Packet *packet);

#endif
