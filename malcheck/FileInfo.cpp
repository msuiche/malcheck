#include "precomp.h"

HCRYPTPROV g_hProv = 0;
HCRYPTHASH g_hHash = 0;

#define VERBOSE_FILE_INFO 0

LPWSTR
GetExpandedPath(
    LPCWSTR Path
)
{
    DWORD CharCount;
    LPWSTR ExpandedPath;

    CharCount = ExpandEnvironmentStringsW(Path, NULL, 0);
    ExpandedPath = (LPWSTR)malloc(CharCount * sizeof(WCHAR));
    if (!ExpandedPath) return NULL;

    // NOTE: ExpandEnvironmentStrings is not identical
    // between Unix and Windows
    ExpandEnvironmentStringsW(Path, ExpandedPath, CharCount);
    if (wcschr(ExpandedPath, L'%')) {
        free(ExpandedPath);
        return NULL;
    }
    return ExpandedPath;
}

BOOLEAN
IsFilePresent(
    LPCWSTR File
)
{
    HANDLE FileHandle;

    FileHandle = CreateFileW(File, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

    if (FileHandle == INVALID_HANDLE_VALUE) {
        return FALSE;
    } else {
        CloseHandle(FileHandle);
        return TRUE;
    }
}

BOOLEAN
InitCrypt(
    VOID
) {
    DWORD dwStatus = ERROR_SUCCESS;

    // Get handle to the crypto provider
    if (!CryptAcquireContext(&g_hProv,
        NULL,
        NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT))
    {
        dwStatus = GetLastError();
        wprintf(L"CryptAcquireContext failed: %d\n", dwStatus);
        goto CleanUp;
    }

    if (!CryptCreateHash(g_hProv, CALG_MD5, 0, 0, &g_hHash))
    {
        dwStatus = GetLastError();
        wprintf(L"CryptAcquireContext failed: %d\n", dwStatus);
        CryptReleaseContext(g_hProv, 0);
        goto CleanUp;
    }

CleanUp:
    return (dwStatus == ERROR_SUCCESS) ? TRUE : FALSE;
}

VOID
DumpFileInfo(
    _In_ PFILE_INFORMATION_CHECK FileInfo
) {
    wprintf(L"[?] FileInfo->FullPath:        %s\n", FileInfo->FullPath);
    wprintf(L"[?] FileInfo->IsPresentOnDisk: %s\n", FileInfo->IsPresentOnDisk ? L"Present" : L"Not Present");
    wprintf(L"[?] FileInfo->FileSize:        0x%llx (%I64d)\n", FileInfo->FileSize.QuadPart, FileInfo->FileSize.QuadPart);
    wprintf(L"[?] FileInfo->Md5Hash:         %s\n", FileInfo->Md5Hash);
}

BOOLEAN
DestroyCrypt(
    VOID
) {
    CryptDestroyHash(g_hHash);
    CryptReleaseContext(g_hProv, 0);
    return TRUE;
}


BOOLEAN
GetFileInformationCheck(
    _In_ LPWSTR FullPath,
    _Out_ PFILE_INFORMATION_CHECK FileInfo
) {
    BOOLEAN Result = FALSE;
    BYTE Buffer[1024] = { 0 };
    BYTE rgbHash[16];
    DWORD cbHash = 0;

    if (!FullPath || !FileInfo) {
        wprintf(L"Error: invalid parameter.\n");
        return FALSE;
    }

    LPWSTR ExpandedPath = GetExpandedPath(FullPath);
    if (!ExpandedPath) {
        wprintf(L"Error: GetExpandedPath(FullPath = %s) failed.\n", FullPath);
        return FALSE;
    }

    wcscpy_s(FileInfo->FullPath, sizeof(FileInfo->FullPath), ExpandedPath);
    free(ExpandedPath);
    ExpandedPath = NULL;

    FileInfo->IsPresentOnDisk = FALSE;
    Result = TRUE;

    HANDLE FileHandle;

    FileHandle = CreateFileW(FileInfo->FullPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (FileHandle == INVALID_HANDLE_VALUE) {
        // wprintf(L"Error: CreateFileW(FullPath = %s) failed. (err = %d)\n", FullPath, GetLastError());
        goto CleanUp;
    }

    InitCrypt();

    BOOLEAN Ret = FALSE;
    FileInfo->IsPresentOnDisk = TRUE;
    FileInfo->FileSize.LowPart = GetFileSize(FileHandle, (LPDWORD)&FileInfo->FileSize.HighPart);

    size_t DataBufferSize = FileInfo->FileSize.LowPart;
    DWORD cbRead = 0;
    while (Ret = ReadFile(FileHandle, Buffer, sizeof(Buffer), &cbRead, NULL)) {
        if (cbRead == 0) break;

        if (!CryptHashData(g_hHash, Buffer, cbRead, 0)) {
            wprintf(L"CryptHashData failed: %d\n", GetLastError());
        }
    }

    cbHash = 16;
    if (CryptGetHashParam(g_hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        RtlZeroMemory(FileInfo->Md5Hash, sizeof(FileInfo->Md5Hash));

        for (UINT i = 0; i < cbHash; i++) {
            WCHAR tmp[8] = { 0 };
            swprintf_s(tmp, _countof(tmp), L"%02x", rgbHash[i]);
            wcscat_s(FileInfo->Md5Hash, (size_t)_countof(FileInfo->Md5Hash), tmp);
        }
    }
    else {
        wprintf(L"CryptGetHashParam failed: %d\n", GetLastError());
    }

    CloseHandle(FileHandle);

CleanUp:
    DestroyCrypt();

#if VERBOSE_FILE_INFO
    DumpFileInfo(FileInfo);
#endif

    return Result;
}