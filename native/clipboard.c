/* Strict bounded clipboard conversion. WinPR is already a pinned dependency.
 * No legacy codepage substitution, truncated surrogate or partial conversion
 * may be forwarded. Callers use output only when this function returns true. */
#include <winpr/crt.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define KEYBASH_CLIPBOARD_LIMIT 32768

static int keybash_clipboard_to_utf8(const BYTE* input, size_t length,
        char* output, size_t capacity, size_t* written) {
    WCHAR wide[KEYBASH_CLIPBOARD_LIMIT + 1];
    *written = 0;
    if (!input || !output || length < 2 || length % 2 ||
        length > sizeof(wide) || capacity < 1) return 0;
    size_t units = length / 2;
    for (size_t i = 0; i < units; i++) wide[i] = (WCHAR)(input[2*i] | ((UINT16)input[2*i+1] << 8));
    if (wide[units-1] != 0) return 0;
    for (size_t i = 0; i + 1 < units; i++) {
        UINT16 c = wide[i];
        if (!c) return 0;
        if (c >= 0xd800 && c <= 0xdbff) {
            if (i + 2 >= units || wide[i+1] < 0xdc00 || wide[i+1] > 0xdfff) return 0;
            i++;
        } else if (c >= 0xdc00 && c <= 0xdfff) return 0;
    }
    int size = WideCharToMultiByte(CP_UTF8, 0, wide, (int)units, output,
            (int)(capacity > KEYBASH_CLIPBOARD_LIMIT+1 ? KEYBASH_CLIPBOARD_LIMIT+1 : capacity), NULL, NULL);
    if (size < 1 || (size_t)size > capacity || size > KEYBASH_CLIPBOARD_LIMIT+1 || output[size-1] != 0) return 0;
    *written = (size_t)size - 1;
    return 1;
}

static int keybash_clipboard_from_utf8(const char* input, size_t length,
        BYTE* output, size_t capacity, size_t* written) {
    WCHAR wide[KEYBASH_CLIPBOARD_LIMIT + 1];
    char roundtrip[KEYBASH_CLIPBOARD_LIMIT + 1];
    *written = 0;
    if (!input || !output || length > KEYBASH_CLIPBOARD_LIMIT ||
        memchr(input, 0, length) || capacity < 2) return 0;
    int units = length ? MultiByteToWideChar(CP_UTF8, 0, input, (int)length,
            wide, KEYBASH_CLIPBOARD_LIMIT) : 0;
    if (units < 0 || units > KEYBASH_CLIPBOARD_LIMIT || (length && units < 1)) return 0;
    /* ICU-backed WinPR can replace malformed bytes. Exact roundtrip refuses
     * replacement, noncanonical UTF-8 and any otherwise lossy conversion. */
    int bytes = units ? WideCharToMultiByte(CP_UTF8, 0, wide, units, roundtrip,
            sizeof(roundtrip), NULL, NULL) : 0;
    if (bytes < 0 || (size_t)bytes != length || memcmp(input, roundtrip, length) ||
        ((size_t)units + 1) * 2 > capacity) return 0;
    wide[units] = 0;
    for (int i = 0; i <= units; i++) {
        output[2*i] = (BYTE)wide[i]; output[2*i+1] = (BYTE)(wide[i] >> 8);
    }
    *written = ((size_t)units + 1) * 2;
    return 1;
}
