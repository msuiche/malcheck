#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct _FILE_INFORMATION_CHECK {
    WCHAR FullPath[MAX_PATH + 1];
    BOOLEAN IsPresentOnDisk;
    LARGE_INTEGER FileSize;
    WCHAR Md5Hash[32 + 1];
} FILE_INFORMATION_CHECK, *PFILE_INFORMATION_CHECK;

typedef struct _MALICIOUS_FILES {
    LPWSTR Path;
    ULONG FileSize;
    LPWSTR MD5;
} MALICIOUS_FILES, *PMALICIOUS_FILES;

BOOLEAN
GetFileInformationCheck(
    _In_ LPWSTR FullPath,
    _Out_ PFILE_INFORMATION_CHECK FileInfo
);

VOID
DumpFileInfo(
    _In_ PFILE_INFORMATION_CHECK FileInfo
);