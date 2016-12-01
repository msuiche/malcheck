/*++

    Copyright (c) 2016, Matthieu Suiche
    Copyright (c) 2016, Comae Technologies FZE

    Module Name:

        main.cpp

    Abstract:
        https://www.fireeye.com/blog/threat-research/2016/11/fireeye_respondsto.html
        TODO: Pass JSON file as input signatures.

    Author:

        Matthieu Suiche (m) 1-Dec-2016

    Revision History:

--*/

#include "precomp.h"

MALICIOUS_FILES g_Shamoon2[] = {
    // https://www.fireeye.com/blog/threat-research/2016/11/fireeye_respondsto.html
    {L"%SYSTEMROOT%\\System32\\ntssrvr64.exe", 717312, NULL},
    {L"%SYSTEMROOT%\\System32\\ntssrvr32.exe", 1349632, NULL },
    {L"%SYSTEMROOT%\\System32\\ntssrvr32.bat", 160, L"10de241bb7028788a8f278e27a4e335f"},
    {L"%SYSTEMROOT%\\System32\\gpget.exe", 327680, L"c843046e54b755ec63ccb09d0a689674"},
    {L"%SYSTEMROOT%\\System32\\drdisk.sys", 31632, L"76c643ab29d497317085e5db8c799960"},
    {L"%SYSTEMROOT%\\System32\\key8854321.pub", 782, L"b5d2a4d8ba015f3e89ade820c5840639"},
    {L"%SYSTEMROOT%\\System32\\netinit.exe", 183808, L"ac4d91e919a3ef210a59acab0dbb9ab5"},
    {NULL, NULL, NULL }
};

ULONG
IsInfectedWithShamoon2(
    VOID
) {
    ULONG Matches = 0;

    for (ULONG i = 0; g_Shamoon2[i].Path; i += 1) {
        FILE_INFORMATION_CHECK Info = { 0 };
        if (GetFileInformationCheck(g_Shamoon2[i].Path, &Info)) {
            if ((g_Shamoon2[i].FileSize && (g_Shamoon2[i].FileSize == Info.FileSize.LowPart)) ||
                (g_Shamoon2[i].MD5 && (wcscmp(g_Shamoon2[i].MD5, Info.Md5Hash) == 0))) {
                Matches += 1;

                wprintf(L"[!] File detect: %s\n", Info.FullPath);

                DumpFileInfo(&Info);
            }
        }
    }

    return Matches;
}

int
wmain(
    ULONG argc,
    LPWSTR *argv) {

    LPWSTR FileName = NULL;
    FILE_INFORMATION_CHECK FileInfo = { 0 };

    wprintf(L"  MalCheck v0.1 - Simple portable utility to search for Shamoon2 artifacts\n"
            L"  Copyright (C) 2016, Matthieu Suiche <http://www.msuiche.net>\n"
            L"  Copyright (C) 2016, Comae Technologies FZE <http://www.comae.io>\n"
            L"      More information: support@comae.io\n\n");


#if 0
    // DEBUG

    if (argc >= 2) {
        FileName = argv[1];
    }

    if (FileName) {
        wprintf(L"argv[1] = %s\n", FileName);
        BOOLEAN Result = GetFileInformationCheck(FileName, &FileInfo);
    }
#endif

    ULONG Result = IsInfectedWithShamoon2();
    if (Result) {
        wprintf(L"[!] WARNING: Artifacts of Shamoon2 have been found. Please contact support@comae.io if your organization needs any assistance.\n");
    } else {
        wprintf(L"[+] No signs of Shamoon2 have been found.\n");
    }

    return Result ? TRUE : FALSE;
}