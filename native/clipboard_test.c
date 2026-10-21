#include "clipboard.c"
#include <assert.h>
#include <stdlib.h>

int main(void) {
    static const char text[] = "Az\xc9\x99rbaycan \xf0\x9f\x94\x91\nline";
    static const BYTE golden[] = {'A',0,'z',0,0x59,2,'r',0,'b',0,'a',0,'y',0,'c',0,'a',0,'n',0,' ',0,0x3d,0xd8,0x11,0xdd,10,0,'l',0,'i',0,'n',0,'e',0,0,0};
    BYTE encoded[65538]; char decoded[32769]; size_t n = 0, m = 0;
    assert(keybash_clipboard_from_utf8(text, sizeof(text)-1, encoded, sizeof(encoded), &n));
    assert(n == sizeof(golden) && !memcmp(encoded, golden, n));
    assert(keybash_clipboard_from_terminated_utf8(text, sizeof(text), encoded, sizeof(encoded), &n));
    assert(n == sizeof(golden) && !memcmp(encoded, golden, n));
    assert(!keybash_clipboard_from_terminated_utf8(text, sizeof(text)-1, encoded, sizeof(encoded), &n));
    assert(!keybash_clipboard_from_terminated_utf8("a\0b\0", 4, encoded, sizeof(encoded), &n));
    assert(!keybash_clipboard_from_terminated_utf8("", 0, encoded, sizeof(encoded), &n));
    assert(keybash_clipboard_to_utf8(golden, sizeof(golden), decoded, sizeof(decoded), &m));
    assert(m == sizeof(text)-1 && !memcmp(text, decoded, sizeof(text)));
    const BYTE bad[][6] = {{0x3d,0xd8,0,0,0,0}, {0x11,0xdd,0,0,0,0}, {'a',0,0,0,'b',0}, {'a',0,'b',0,'c',0}};
    for (size_t i=0;i<sizeof(bad)/sizeof(bad[0]);i++) assert(!keybash_clipboard_to_utf8(bad[i], sizeof(bad[i]), decoded, sizeof(decoded), &m) && m==0);
    assert(!keybash_clipboard_to_utf8(golden, sizeof(golden)-1, decoded, sizeof(decoded), &m));
    assert(!keybash_clipboard_to_utf8(golden, sizeof(golden), decoded, 2, &m));
    for (size_t size=1;size<=4;size++) {
        static const char malformed[][4] = {{(char)0xff}, {(char)0xc0,(char)0xaf}, {(char)0xed,(char)0xa0,(char)0x80}, {(char)0xf4,(char)0x90,(char)0x80,(char)0x80}};
        assert(!keybash_clipboard_from_utf8(malformed[size-1], size, encoded, sizeof(encoded), &n) && n==0);
    }
    assert(!keybash_clipboard_from_utf8("a\0b", 3, encoded, sizeof(encoded), &n));
    assert(!keybash_clipboard_from_utf8(text, sizeof(text)-1, encoded, 2, &n));
    char* maximum = malloc(32769); assert(maximum); memset(maximum,'a',32769);
    assert(keybash_clipboard_from_utf8(maximum,32768,encoded,sizeof(encoded),&n) && n==65538);
    assert(keybash_clipboard_to_utf8(encoded,n,decoded,sizeof(decoded),&m) && m==32768);
    assert(!keybash_clipboard_from_utf8(maximum,32769,encoded,sizeof(encoded),&n));
    free(maximum);
    assert(keybash_clipboard_from_utf8("",0,encoded,sizeof(encoded),&n) && n==2);
    assert(keybash_clipboard_to_utf8(encoded,n,decoded,sizeof(decoded),&m) && m==0);
    return 0;
}
