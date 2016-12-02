//
// Translation of string decoding routine used by Shamoon 2.0 droppers used against General Authority of Civil Aviation (GACA) in Saudi Arabia. Strings such as passwords, username etc.
// This can be used to identify similar categories or malwares from the same family.
//
// Translation done by Comae Technologies. www.comae.io / @comae.io
//

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

LPWSTR
Decode(LPBYTE InputStr, USHORT Delta)
{
    ULONG InputStrLen = wcslen((LPWSTR)InputStr);
    ULONG OutputStrLen = sizeof(WCHAR) * (InputStrLen + 1);
    LPWSTR OutputStr = (LPWSTR)malloc(OutputStrLen);
    wcsncpy_s(OutputStr, OutputStrLen / sizeof(WCHAR), (LPWSTR)InputStr, (InputStrLen + 1));
    ULONG Count = 0;
    if (InputStrLen) {
        do {
            OutputStr[Count++] += (USHORT)Delta;
        } while (Count < InputStrLen);
    }
    return OutputStr;
}

VOID
DecodeEx(
    LPBYTE Input
)
{
    LPWSTR Out = Decode(Input, -0x13);

    wprintf(L"\"%s\" -> \"%s\"\n", Input, Out);

    free(Out);
}

int main(
    int argc,
    char **argv
) {
#if 0
    .text:00404989                 push    0FFFFFFEDh; __int16
    .text:0040498B                 push    offset aZtvt; "ZTVT"
    .text:00404990                 mov     dword_42DFB0, esi
    .text:00404996                 call    decode_string
    .text:0040499B                 push    0FFFFFFEDh; __int16
    .text:0040499D                 push    offset aZtvttw; "ztvttw"
    .text:004049A2                 mov     dword_42DFB4, eax
    .text:004049A7                 call    decode_string
    .text:004049AC                 push    0FFFFFFEDh; __int16
    .text:004049AE                 push    offset aZzNy; "{zz|[Ny"
    .text:004049B3                 mov     dword_42DFB8, eax
    .text:004049B8                 call    decode_string
#endif

    DecodeEx((LPBYTE)"\x5a\x00\x54\x00\x56\x00\x54\x00\x13\x00"); // GACA
    DecodeEx((LPBYTE)"\x7a\x00\x76\x00\x74\x00\x74\x00\x77\x00\x80\x00\x7c\x00\x81\x00\x44\x00\x48\x00\x13\x00"); // gcaadmin15
    DecodeEx((LPBYTE)"\x7b\x00\x7a\x00\x7a\x00\x7c\x00\x5b\x00\x4e\x00\x79\x00\x89\x00\x44\x00\x44\x00\x45\x00\x45\x00\x13\x00");

    return FALSE;
}
