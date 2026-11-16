#include "scale.c"
#include <assert.h>

int main(void) {
    static const int dpis[] = {96, 120, 144, 168, 192};
    static const uint32_t scales[] = {100, 125, 150, 175, 200};
    for (int i = 0; i < 5; i++) assert(keybash_desktop_scale(dpis[i]) == scales[i]);
    /* Anything but Windows' own scales is told as 100%. */
    static const int others[] = {0, -192, 95, 97, 100, 191, 193, 240, 288, 480, 2147483647};
    for (unsigned i = 0; i < sizeof(others)/sizeof(others[0]); i++) {
        assert(keybash_desktop_scale(others[i]) == 100);
        assert(keybash_millimetres(1920, others[i]) == 508);
    }
    assert(keybash_device_scale() == 100);
    /* A side's millimetres at its DPI, rounded to the nearest. */
    assert(keybash_millimetres(1024, 96) == 271 && keybash_millimetres(768, 96) == 203);
    assert(keybash_millimetres(1280, 96) == 339 && keybash_millimetres(720, 96) == 191);
    assert(keybash_millimetres(2880, 192) == 381 && keybash_millimetres(1800, 192) == 238);
    assert(keybash_millimetres(1280, 192) == 169 && keybash_millimetres(720, 192) == 95);
    assert(keybash_millimetres(3840, 192) == 508 && keybash_millimetres(2160, 192) == 286);
    assert(keybash_millimetres(1920, 96) == 508 && keybash_millimetres(2400, 120) == 508);
    assert(keybash_millimetres(2880, 144) == 508 && keybash_millimetres(3360, 168) == 508);
    /* Windows ignores a size under 10 mm or over 10000 mm: none is sent. */
    assert(keybash_millimetres(36, 96) == 10 && keybash_millimetres(35, 96) == 0);
    assert(keybash_millimetres(37797, 96) == 10000 && keybash_millimetres(37798, 96) == 0);
    assert(keybash_millimetres(0, 96) == 0 && keybash_millimetres(-1, 96) == 0);
    assert(keybash_millimetres(65535, 192) == 8670 && keybash_millimetres(65536, 192) == 0);
    return 0;
}
