/* The scale Windows draws a desktop at. Windows draws at a client's scale only
 * when the client says so, in the core data at connection and in every
 * display-control layout after it. Guacamole 1.6 uses its dpi argument for
 * sizes alone and sends neither, so a desktop opened at 192 DPI was drawn at
 * 100% in twice the pixels and looked half size on the page.
 *
 * Only Windows' own scales are told: 96, 120, 144, 168 and 192 DPI are 100,
 * 125, 150, 175 and 200%. Any other DPI is told as 96, FreeRDP's default. */
#include <stdint.h>

static inline int keybash_scale_dpi(int dpi) {
    switch (dpi) {
    case 120: case 144: case 168: case 192: return dpi;
    default: return 96;
    }
}

/* The desktop scale factor in percent, within the 100 to 500 Windows reads. */
static inline uint32_t keybash_desktop_scale(int dpi) {
    return (uint32_t)(keybash_scale_dpi(dpi) * 100 / 96);
}

/* The device scale factor is for Windows 8.1's store apps and must be 100, 140
 * or 180, or Windows ignores the desktop scale too. FreeRDP's own SDL client
 * sends 100 at every scale; so does this. */
static inline uint32_t keybash_device_scale(void) {
    return 100;
}

/* Millimetres one side of the desktop covers at that scale, rounded: what a
 * monitor of the same DPI reports, so the size and the scale agree. Windows
 * ignores a size outside 10 to 10000 mm; 0 says none. */
static inline uint32_t keybash_millimetres(int pixels, int dpi) {
    if (pixels <= 0 || pixels > 65535) return 0;
    uint32_t scaled = (uint32_t)keybash_scale_dpi(dpi);
    uint32_t mm = ((uint32_t)pixels * 254 + scaled * 5) / (scaled * 10);
    return mm >= 10 && mm <= 10000 ? mm : 0;
}
