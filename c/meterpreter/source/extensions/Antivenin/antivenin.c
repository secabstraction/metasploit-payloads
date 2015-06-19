/*!
 * @file bare.c
 * @brief Entry point and intialisation functionality for the bare extention.
 */
#include "../../common/common.h"

#include "../../DelayLoadMetSrv/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

#include "thread.h"
#include "memory.h"
#include "file.h"



// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

/*! @brief List of commands that the antivenin API extension provides. */
Command customCommands[] =
{
	// custom commands go here
	COMMAND_REQ("antivenin_thread_trace", request_thread_trace),
	COMMAND_REQ("antivenin_thread_kill", request_thread_kill),
	COMMAND_REQ("antivenin_thread_find_references", request_thread_find_references), //NtQueryInformationThread > NT_TIB > Stackbase && StackLimit
	COMMAND_REQ("antivenin_thread_get_times", request_thread_get_times),
	COMMAND_REQ("antivenin_memory_search", request_memory_search),
	COMMAND_REQ("antivenin_memory_dump_process", request_memory_dump_process),
	COMMAND_REQ("antivenin_memory_dump_segment", request_memory_dump_segment),
	COMMAND_REQ("antivenin_memory_map_pages", request_memory_map_pages),
	COMMAND_REQ("antivenin_file_rawcopy", request_file_rawcopy),
	COMMAND_REQ("antivenin_file_get_hash", request_file_get_hash),
	COMMAND_REQ("antivenin_file_find_hash", request_file_find_hash),
	COMMAND_TERMINATOR
};

/*!
 * @brief Initialize the server extension
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	hMetSrv = remote->met_srv;

	command_register_all(customCommands);

	initialize_thread();
	initialize_memory();
	initialize_file();

	return ERROR_SUCCESS;
}

/*!
 * @brief Deinitialize the server extension
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	command_deregister_all(customCommands);

	return ERROR_SUCCESS;
}
