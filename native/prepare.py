"""Apply narrow, checked integration patches to verified lab sources only."""
from pathlib import Path
import sys

freerdp, guac, identity_source = map(Path, sys.argv[1:])


def replace_once(path, old, new):
    text = path.read_text()
    if text.count(old) != 1:
        raise SystemExit(f"native patch anchor changed: {path.name}: {old[:70]!r}")
    path.write_text(text.replace(old, new))


# Synthetic fixture only: stock sample has NLA off. Its own CredSSP/NTLM
# verifies the ephemeral fixture SAM database, not a user's real account.
sample = freerdp / "server/Sample/sfreerdp.c"
sample_header = sample.with_suffix(".h")
replace_once(sample_header, "#include <freerdp/server/rdpsnd.h>", "#include <freerdp/server/rdpsnd.h>\n#include <freerdp/server/cliprdr.h>\n#include <freerdp/server/disp.h>\n#include <stdatomic.h>")
replace_once(sample_header, "EncomspServerContext* encomsp;", "EncomspServerContext* encomsp;\n\tCliprdrServerContext* kb_clip;\n\tDispServerContext* kb_disp;\n\tBOOL kb_caps_sent;\n\tatomic_uint_fast32_t kb_disp_id;\n\tatomic_int kb_disp_ready;\n\tatomic_uint_fast64_t kb_size;\n\tHANDLE kb_resize_event;")
(sample.parent / "keybash_workspace_fixture.h").write_bytes((identity_source.parent / "workspace_fixture.h").read_bytes())
replace_once(sample, '#include "sfreerdp.h"', '#include "sfreerdp.h"\n#include "keybash_workspace_fixture.h"')
replace_once(sample, "winpr_image_free(context->image, TRUE);", "kb_workspace_free(context);\n\t\twinpr_image_free(context->image, TRUE);")
replace_once(sample, "/* Dynamic Virtual Channels */", "if (!kb_workspace_start(client)) return FALSE;\n\t/* Dynamic Virtual Channels */")
replace_once(sample, "/* Handle dynamic virtual channel initializations */", "if (!kb_workspace_events(client)) break;\n\t\t/* Handle dynamic virtual channel initializations */")
replace_once(sample, "context->vcm = WTSOpenServerA((LPSTR)client->context);", "context->vcm = WTSOpenServerA((LPSTR)client->context);\n\tatomic_init(&context->kb_size,0);\n\tatomic_init(&context->kb_disp_id,0);\n\tatomic_init(&context->kb_disp_ready,0);\n\tcontext->kb_resize_event=CreateEvent(NULL,FALSE,FALSE,NULL);\n\tif (!context->kb_resize_event) goto fail;\n\tif (context->vcm) WTSVirtualChannelManagerSetDVCCreationCallback(context->vcm,kb_dvc_created,context);")
replace_once(sample, "handles[count++] = channelHandle;", "handles[count++] = channelHandle;\n\t\thandles[count++] = context->kb_resize_event;")
# The sample's main loop runs during negotiation too. Auto-opening drdynvc
# before MCS has joined it leaves FreeRDP's manager permanently INITIALIZED.
# Delay only this synthetic server's automatic open until activation/join.
replace_once(sample, 'WTSVirtualChannelManagerCheckFileDescriptor(context->vcm)',
             'WTSVirtualChannelManagerCheckFileDescriptorEx(context->vcm, context->activated && WTSVirtualChannelManagerIsChannelJoined(context->vcm, "drdynvc"))')
replace_once(sample, "client->GetEventHandles(client, &handles[count], 32 - count)", "client->GetEventHandles(client, &handles[count], 30 - count)")
replace_once(sample, "FreeRDP_RdpSecurity, TRUE", "FreeRDP_RdpSecurity, FALSE")
replace_once(sample, "FreeRDP_TlsSecurity, TRUE", "FreeRDP_TlsSecurity, FALSE")
replace_once(sample, "FreeRDP_NlaSecurity, FALSE", "FreeRDP_NlaSecurity, TRUE")
replace_once(sample, "instance->Open(instance, nullptr, (UINT16)port)", 'instance->Open(instance, "127.0.0.1", (UINT16)port)')
replace_once(sample, "if (!freerdp_settings_set_bool(settings, FreeRDP_NlaSecurity, TRUE))",
             'if (!freerdp_settings_set_string(settings, FreeRDP_NtlmSamFile, "/run/fixture/SAM") ||\n\t    !freerdp_settings_set_bool(settings, FreeRDP_NlaSecurity, TRUE))')
replace_once(sample, "static BOOL tf_peer_post_connect(freerdp_peer* client)\n{", "static BOOL tf_peer_post_connect(freerdp_peer* client)\n{\n\tputs(\"KB_AUTHENTICATED\"); fflush(stdout);")
# The sample server offers FreeRDP's client-sized pointer cache (128) instead of
# its server default (25), so the size both sides settle on is what the client
# asked for; PostConnect runs after the capabilities and prints it.
replace_once(sample, "\tif (!freerdp_settings_set_bool(settings, FreeRDP_ExtSecurity, FALSE))\n\t\tgoto fail;",
             "\tif (!freerdp_settings_set_bool(settings, FreeRDP_ExtSecurity, FALSE))\n\t\tgoto fail;\n\tif (!freerdp_settings_set_uint32(settings, FreeRDP_PointerCacheSize, 128) ||\n\t    !freerdp_settings_set_uint32(settings, FreeRDP_ColorPointerCacheSize, 128))\n\t\tgoto fail;")
replace_once(sample, "\tputs(\"KB_AUTHENTICATED\"); fflush(stdout);",
             "\tprintf(\"KB_CLIENT_POINTERS_%u_%u_%u\\n\", freerdp_settings_get_uint32(client->context->settings, FreeRDP_PointerCacheSize), freerdp_settings_get_uint32(client->context->settings, FreeRDP_ColorPointerCacheSize), freerdp_settings_get_uint32(client->context->settings, FreeRDP_LargePointerFlag)); fflush(stdout);\n\tputs(\"KB_AUTHENTICATED\"); fflush(stdout);")
# The scale and physical size the client's core data told the server.
replace_once(sample, "\tputs(\"KB_AUTHENTICATED\"); fflush(stdout);",
             "\tprintf(\"KB_CLIENT_SCALE_%u_%u_%u_%u\\n\", freerdp_settings_get_uint32(client->context->settings, FreeRDP_DesktopScaleFactor), freerdp_settings_get_uint32(client->context->settings, FreeRDP_DeviceScaleFactor), freerdp_settings_get_uint32(client->context->settings, FreeRDP_DesktopPhysicalWidth), freerdp_settings_get_uint32(client->context->settings, FreeRDP_DesktopPhysicalHeight)); fflush(stdout);\n\tputs(\"KB_AUTHENTICATED\"); fflush(stdout);")
replace_once(sample, "static BOOL tf_peer_keyboard_event(rdpInput* input, UINT16 flags, UINT8 code)\n{",
             "static BOOL tf_peer_keyboard_event(rdpInput* input, UINT16 flags, UINT8 code)\n{\n\tif (code == RDP_SCANCODE_KEY_A && !(flags & KBD_FLAGS_RELEASE)) { puts(\"KB_INPUT_A\"); fflush(stdout); }")
replace_once(sample, "static BOOL tf_peer_mouse_event(rdpInput* input, UINT16 flags, UINT16 x, UINT16 y)\n{",
             "static BOOL tf_peer_mouse_event(rdpInput* input, UINT16 flags, UINT16 x, UINT16 y)\n{\n\tputs(\"KB_INPUT_MOUSE\"); fflush(stdout);")

# Every native TLS certificate takes the application-managed OpenSSL path.
# No accepted-fingerprint fast path, automatic trust or blanket ignore remains.
rdp = guac / "src/protocols/rdp/rdp.c"
anchor = "static int guac_rdp_handle_events(guac_rdp_client* rdp_client) {"
callback = '''static int keybash_verify_x509(freerdp* instance, const BYTE* pem,
        size_t length, const char* hostname, UINT16 port, DWORD flags) {
    (void)instance; (void)hostname; (void)port;
    puts("KB_STAGE_IDENTITY"); fflush(stdout);
    if (flags != 0) return 0;
    return keybash_verify_identity((const char*)pem, length);
}

'''
# The lab exclusively builds the pinned FreeRDP 3 API.
replace_once(rdp, anchor, callback + anchor)
replace_once(rdp, '#include "rdp.h"', '#include "rdp.h"\n#include <freerdp/version.h>\n_Static_assert(FREERDP_VERSION_MAJOR == 3, "Keybash lab requires FreeRDP 3");\n#include "keybash_identity.c"')
(rdp.parent / "keybash_identity.c").write_bytes(identity_source.read_bytes())
# The pinned FreeRDP client initializes GDI in PostConnect (as its own X11
# client does), after transport/authentication state is established. Guacamole
# 1.6's older PreConnect placement stalls this build before any network dial.
rdp_text = rdp.read_text()
gdi_start = "    /* Init FreeRDP internal GDI implementation */"
gdi_end = "    GUAC_RDP_CONTEXT(instance)->update->altsec->FrameMarker = guac_rdp_gdi_frame_marker;"
if rdp_text.count(gdi_start) != 1 or rdp_text.count(gdi_end) != 1:
    raise SystemExit("native GDI lifecycle anchors changed")
start = rdp_text.index(gdi_start)
end = rdp_text.index(gdi_end, start) + len(gdi_end)
gdi_block = rdp_text[start:end]
replace_once(rdp, gdi_block, "    /* GDI and graphics handlers initialize in PostConnect. */")
replace_once(rdp, "    rdpGraphics* graphics = context->graphics;", "")
post_connect = '''static BOOL keybash_post_connect(freerdp* instance) {
    rdpContext* context = GUAC_RDP_CONTEXT(instance);
    rdpGraphics* graphics = context->graphics;
''' + gdi_block + '''
    puts("KB_STAGE_POST_READY"); fflush(stdout);
    return TRUE;
}

'''
replace_once(rdp, "static BOOL rdp_freerdp_pre_connect(freerdp* instance) {",
             post_connect + "static BOOL rdp_freerdp_pre_connect(freerdp* instance) {")
replace_once(rdp, "rdp_inst->PreConnect = rdp_freerdp_pre_connect;",
             "rdp_inst->PreConnect = rdp_freerdp_pre_connect;\n    rdp_inst->PostConnect = keybash_post_connect;")
replace_once(rdp, "/* Connection complete */", 'puts("KB_STAGE_CONNECTED"); fflush(stdout);\n    /* Connection complete */')
# A continuously-ready native handle must not starve display flushing/input.
# Preserve the first native event failure instead of overwriting it with the
# next wait result (also fixed by current upstream Guacamole).
replace_once(rdp, "        int connection_closing;\n        do {",
             "        int connection_closing = 0;\n        unsigned keybash_event_batch = 0;\n        do {")
replace_once(rdp, "            if (!guac_rdp_handle_events(rdp_client))\n                wait_result = -1;",
             "            if (!guac_rdp_handle_events(rdp_client)) {\n                wait_result = -1;\n                break;\n            }")
replace_once(rdp, "    pthread_mutex_unlock(&(rdp_client->message_lock));\n\n    return retval;",
             "    pthread_mutex_unlock(&(rdp_client->message_lock));\n    if (!retval) {\n        printf(\"KB_NATIVE_ERROR_%u_%u\\n\", freerdp_get_last_error(GUAC_RDP_CONTEXT(rdp_client->rdp_inst)), getChannelError(GUAC_RDP_CONTEXT(rdp_client->rdp_inst)));\n        fflush(stdout);\n    }\n\n    return retval;")
replace_once(rdp, "        } while (!connection_closing &&\n                (wait_result = rdp_guac_client_wait_for_events(client, 0)) > 0);",
             "        } while (!connection_closing && ++keybash_event_batch < 64 &&\n                (wait_result = rdp_guac_client_wait_for_events(client, 0)) > 0);")
for old, stage in [
    ("if (!freerdp_context_new(rdp_inst)) {", "CONTEXT"),
    ("if (!freerdp_connect(rdp_inst)) {", "NETWORK"),
    ("guac_rdp_push_settings(client, settings, instance);", "SETTINGS"),
    ("if (!gdi_init(instance, guac_rdp_get_native_pixel_format(FALSE)))", "GDI"),
    ("/* Set up pointer handling */", "GDI_READY"),
    ("static BOOL rdp_freerdp_load_channels(freerdp* instance) {", "CHANNELS"),
]:
    new = old + f'\n    puts("KB_STAGE_{stage}"); fflush(stdout);' if stage == "CHANNELS" else f'puts("KB_STAGE_{stage}"); fflush(stdout);\n    ' + old
    replace_once(rdp, old, new)
# Supplied credentials are immutable for this one-use session. Missing/rejected
# credentials must abort, never prompt, retry or switch authentication modes.
replace_once(rdp, '''    if (settings->resize_method == GUAC_RESIZE_DISPLAY_UPDATE)
        guac_rdp_disp_load_plugin(context);''', '''    if (settings->resize_method == GUAC_RESIZE_DISPLAY_UPDATE) {
        guac_rdp_disp_load_plugin(context);
        puts("KB_STAGE_DISP_SELECTED"); fflush(stdout);
    }''')
replace_once(rdp, '    /* Load plugin providing Dynamic Virtual Channel support, if required */', '''    if (freerdp_settings_get_bool(context->settings, FreeRDP_SupportDynamicChannels)) {
        puts("KB_STAGE_DVC_REQUESTED"); fflush(stdout);
    }
    /* Load plugin providing Dynamic Virtual Channel support, if required */''')
replace_once(rdp, '''        guac_client_log(client, GUAC_LOG_WARNING,
                "Failed to load drdynvc plugin.''', '''        puts("KB_STAGE_DVC_FAILED"); fflush(stdout);
        guac_client_log(client, GUAC_LOG_WARNING,
                "Failed to load drdynvc plugin.''')
rdp_text = rdp.read_text()
auth_start = "static BOOL rdp_freerdp_authenticate(freerdp* instance, char** username,"
if rdp_text.count(auth_start) != 1:
    raise SystemExit("native authentication anchor changed")
start = rdp_text.index(auth_start)
end = rdp_text.index("\n}\n", start) + len("\n}\n")
replace_once(rdp, rdp_text[start:end], '''static BOOL keybash_authentication_refusal(freerdp* instance, char** username,
        char** password, char** domain, rdp_auth_reason reason) {
    (void)instance; (void)username; (void)password; (void)domain; (void)reason;
    return FALSE;
}
''')
replace_once(rdp, "rdp_inst->Authenticate = rdp_freerdp_authenticate;",
             "rdp_inst->AuthenticateEx = keybash_authentication_refusal;")
replace_once(rdp, " *     Always TRUE.\n */\nstatic BOOL keybash_authentication_refusal",
             " *     FALSE: supplied credential changes and retries are forbidden.\n */\nstatic BOOL keybash_authentication_refusal")
replace_once(rdp, "rdp_inst->VerifyCertificateEx = rdp_freerdp_verify_certificate;",
             "rdp_inst->VerifyCertificateEx = rdp_freerdp_verify_certificate;\n    rdp_inst->VerifyX509Certificate = keybash_verify_x509;")
settings = guac / "src/protocols/rdp/settings.c"
# The classic bitmap path needs a negotiated codec: a server without the
# graphics pipeline (the synthetic peer) and Windows before the pipeline is up
# use it. Guacamole enables RemoteFX only together with the pipeline, and
# FreeRDP's default NSCodec is off, so enable NSCodec explicitly; this opens no
# virtual channel and changes no TLS/NLA policy.
# Guacamole turns on the legacy RemoteFX surface-bits codec together with the
# graphics pipeline, which FreeRDP 3's pipeline does not need (its capabilities
# come from the Gfx settings alone). A server without the pipeline then sent
# RemoteFX surface bits that ended the connection with the synthetic peer;
# such servers keep the NSCodec path below, tested in CI.
replace_once(settings, "        freerdp_settings_set_bool(rdp_settings, FreeRDP_SupportGraphicsPipeline, TRUE);\n        freerdp_settings_set_bool(rdp_settings, FreeRDP_RemoteFxCodec, TRUE);",
             "        freerdp_settings_set_bool(rdp_settings, FreeRDP_SupportGraphicsPipeline, TRUE);\n        /* Keybash: no legacy RemoteFX surface bits (native/prepare.py). */")
replace_once(settings, "freerdp_settings_set_bool(rdp_settings, FreeRDP_FrameMarkerCommandEnabled, TRUE);",
             "/* Classic bitmap path, for a server without the graphics pipeline. */\n    freerdp_settings_set_bool(rdp_settings, FreeRDP_NSCodec, TRUE);\n    freerdp_settings_set_bool(rdp_settings, FreeRDP_NSCodecAllowDynamicColorFidelity, FALSE);\n    freerdp_settings_set_bool(rdp_settings, FreeRDP_NSCodecAllowSubsampling, FALSE);\n    freerdp_settings_set_uint32(rdp_settings, FreeRDP_NSCodecColorLossLevel, 1);\n\n    freerdp_settings_set_bool(rdp_settings, FreeRDP_FrameMarkerCommandEnabled, TRUE);")
anchor = "freerdp_settings_set_bool(rdp_settings, FreeRDP_IgnoreCertificate, guac_settings->ignore_certificate);"
replace_once(settings, anchor, '''freerdp_settings_set_bool(rdp_settings, FreeRDP_IgnoreCertificate, FALSE);
    freerdp_settings_set_bool(rdp_settings, FreeRDP_AutoAcceptCertificate, FALSE);
    freerdp_settings_set_uint32(rdp_settings, FreeRDP_CookieMaxLength, 0);
    freerdp_settings_set_bool(rdp_settings, FreeRDP_ExternalCertificateManagement, TRUE);
    freerdp_settings_set_uint16(rdp_settings, FreeRDP_TLSMinVersion, 0x0303);
    freerdp_settings_set_string(rdp_settings, FreeRDP_AllowedTlsCiphers, "ECDHE+AESGCM:ECDHE+CHACHA20");''')
replace_once(settings, "freerdp_settings_set_bool(rdp_settings, FreeRDP_AutoAcceptCertificate, guac_settings->certificate_tofu);", "/* Automatic certificate trust is forbidden by the Keybash lab. */")
# guacd 1.6 keeps one browser buffer per pointer FreeRDP holds (pointer.c),
# freed with a dispose when the cache drops it, and leaves the cache at
# FreeRDP's 128 entries. FreeRDP applies the smaller of the client's and the
# server's cache sizes, so 32 here holds for any server; 129 pointers of up to
# 384 by 384 would outgrow the viewer's pixel budget. (FreeRDP 3.32 takes the
# server's large-pointer sizes whatever the client asks, so those stay, and the
# viewer's budget is sized for them.) The server only resends a pointer more
# often.
offscreen = "freerdp_settings_set_uint32(rdp_settings, FreeRDP_OffscreenSupportLevel, !guac_settings->disable_offscreen_caching);"
replace_once(settings, offscreen, offscreen + '''
    freerdp_settings_set_uint32(rdp_settings, FreeRDP_PointerCacheSize, 32);
    freerdp_settings_set_uint32(rdp_settings, FreeRDP_ColorPointerCacheSize, 32);''')
replace_once(settings, "if (guac_settings->certificate_fingerprints != NULL)\n        freerdp_settings_set_string(rdp_settings, FreeRDP_CertificateAcceptedFingerprints, \n                guac_strdup(guac_settings->certificate_fingerprints));", "/* The mandatory exact pin is checked in the native X509 callback. */")
# Windows draws at the desktop's DPI only when told it (native/scale.c): in
# the core data at connection and in every display-control layout. Guacamole
# 1.6 sends neither, so a 192 DPI desktop was drawn at 100% and looked half
# size. Both places take the scale from the same dpi argument.
(settings.parent / "keybash_scale.c").write_bytes((identity_source.parent / "scale.c").read_bytes())
replace_once(settings, '#include "resolution.h"', '#include "resolution.h"\n#include "keybash_scale.c"')
desktop_height = "freerdp_settings_set_uint32(rdp_settings, FreeRDP_DesktopHeight, guac_settings->height);"
replace_once(settings, desktop_height, desktop_height + '''
    freerdp_settings_set_uint32(rdp_settings, FreeRDP_DesktopScaleFactor, keybash_desktop_scale(guac_settings->resolution));
    freerdp_settings_set_uint32(rdp_settings, FreeRDP_DeviceScaleFactor, keybash_device_scale());
    freerdp_settings_set_uint32(rdp_settings, FreeRDP_DesktopPhysicalWidth, keybash_millimetres(guac_settings->width, guac_settings->resolution));
    freerdp_settings_set_uint32(rdp_settings, FreeRDP_DesktopPhysicalHeight, keybash_millimetres(guac_settings->height, guac_settings->resolution));''')
disp = guac / "src/protocols/rdp/channels/disp.c"
replace_once(disp, '#include "settings.h"', '#include "settings.h"\n#include "keybash_scale.c"')
replace_once(disp, '''            .PhysicalWidth = 0,
            .PhysicalHeight = 0,
            .Orientation = 0,
            .DesktopScaleFactor = 0,
            .DeviceScaleFactor = 0''', '''            .PhysicalWidth = keybash_millimetres(width, settings->resolution),
            .PhysicalHeight = keybash_millimetres(height, settings->resolution),
            .Orientation = 0,
            .DesktopScaleFactor = keybash_desktop_scale(settings->resolution),
            .DeviceScaleFactor = keybash_device_scale()''')

# Guacamole 1.6's common UTF-16 reader/writer handles only individual 16-bit
# units. Keep that upstream code untouched; the RDP Unicode clipboard path
# instead uses the existing pinned WinPR conversion API with strict bounds,
# surrogate validation and an exact UTF-8 roundtrip before forwarding.
clip = guac / "src/protocols/rdp/channels/cliprdr.c"
(clip.parent / "keybash_clipboard.c").write_bytes((identity_source.parent / "clipboard.c").read_bytes())
replace_once(clip, '#include "common/clipboard.h"', '#include "common/clipboard.h"\n#include "keybash_clipboard.c"')
# A clipboard request this client cannot answer gets the protocol's own failure
# response. Returning an error from a CLIPRDR callback makes FreeRDP close the
# channel and the whole connection, which ended desktops over one copy.
replace_once(clip, 'static UINT guac_rdp_cliprdr_format_data_request(CliprdrClientContext* cliprdr,', '''static UINT keybash_cliprdr_refuse(CliprdrClientContext* cliprdr, guac_rdp_client* rdp_client) {
    CLIPRDR_FORMAT_DATA_RESPONSE data_response = {
        .requestedFormatData = NULL,
#ifdef HAVE_CLIPRDR_HEADER
        .common = {
            .msgType = CB_FORMAT_DATA_RESPONSE,
            .msgFlags = CB_RESPONSE_FAIL,
            .dataLen = 0,
        }
#else
        .dataLen = 0,
        .msgFlags = CB_RESPONSE_FAIL
#endif
    };
    pthread_mutex_lock(&(rdp_client->message_lock));
    UINT result = cliprdr->ClientFormatDataResponse(cliprdr, &data_response);
    pthread_mutex_unlock(&(rdp_client->message_lock));
    return result;
}

static UINT guac_rdp_cliprdr_format_data_request(CliprdrClientContext* cliprdr,''')
replace_once(clip, '    const char* input = clipboard->clipboard->buffer;', '''    /* Native input and RDP callbacks can update this shared clipboard.
     * Convert an immutable bounded snapshot, never a changing buffer between
     * the required-size query and conversion. No content is logged. */
    char keybash_input[KEYBASH_CLIPBOARD_LIMIT + 1];
    pthread_mutex_lock(&(clipboard->clipboard->lock));
    int keybash_input_length = clipboard->clipboard->length;
    if (keybash_input_length < 0 || keybash_input_length > KEYBASH_CLIPBOARD_LIMIT + 1) {
        pthread_mutex_unlock(&(clipboard->clipboard->lock));
        return keybash_cliprdr_refuse(cliprdr, rdp_client);
    }
    if (keybash_input_length) memcpy(keybash_input, clipboard->clipboard->buffer, (size_t)keybash_input_length);
    else keybash_input[0] = 0;
    pthread_mutex_unlock(&(clipboard->clipboard->lock));
    const char* input = keybash_input;''')
replace_once(clip, '''            { .formatId = CF_TEXT },
            { .formatId = CF_UNICODETEXT }
        },
        .numFormats = 2''', '''            { .formatId = CF_UNICODETEXT }
        },
        .numFormats = 1''')
replace_once(clip, '''    /* Use Windows' CP-1252 if Unicode unavailable */
    if (guac_rdp_cliprdr_format_supported(format_list, CF_TEXT))
        return guac_rdp_cliprdr_send_format_data_request(cliprdr, CF_TEXT);''',
    '    /* Only Unicode text is supported; no lossy codepage fallback. */')
replace_once(clip, '    /* Map requested clipboard format to a guac_iconv writer */', '''    if (format_data_request->requestedFormatId != CF_UNICODETEXT) {
        guac_mem_free(output);
        return keybash_cliprdr_refuse(cliprdr, rdp_client);
    }
    /* Map requested clipboard format to a guac_iconv writer */''')
local = '''    guac_iconv(local_reader, &input, clipboard->clipboard->length,
            remote_writer, &output, GUAC_COMMON_CLIPBOARD_MAX_LENGTH);'''
replace_once(clip, local, '''    if (format_data_request->requestedFormatId == CF_UNICODETEXT) {
        size_t length = 0;
        if (!keybash_clipboard_from_terminated_utf8(input, (size_t)keybash_input_length,
                start, GUAC_COMMON_CLIPBOARD_MAX_LENGTH, &length)) {
            guac_mem_free(start);
            return keybash_cliprdr_refuse(cliprdr, rdp_client);
        }
        output = (char*)start + length;
    } else {
''' + local + '''
    }''')
remote = '''    if (guac_iconv(remote_reader, &input, data_len,
            GUAC_WRITE_UTF8, &output, sizeof(received_data))) {'''
replace_once(clip, remote, '''    if (clipboard->requested_format == CF_UNICODETEXT) {
        size_t length = 0;
        if (data_len < 0 || !keybash_clipboard_to_utf8((const BYTE*)input,
                (size_t)data_len, received_data, sizeof(received_data), &length)) {
            /* Text that cannot be passed is dropped. An error here would end
             * the whole desktop, which bounds nothing. No content is logged. */
            guac_client_log(client, GUAC_LOG_DEBUG, "Dropped remote clipboard text that could not be converted.");
            return CHANNEL_RC_OK;
        }
        guac_common_clipboard_reset(clipboard->clipboard, "text/plain");
        guac_common_clipboard_append(clipboard->clipboard, received_data, (int)length);
        guac_common_clipboard_send(clipboard->clipboard, client);
    }
    else ''' + remote.strip())

# After a resize FreeRDP gives guacd a new, zeroed framebuffer and guacd takes
# it as what the browser shows. Windows repaints only what it invalidates, so
# the rest stayed stale, showed the page, or turned black where guacd merged
# it into a neighbouring update. Once the connection is active again, ask
# Windows once for the whole desktop, as FreeRDP's own SDL client does.
gdi = guac / "src/protocols/rdp/gdi.c"
replace_once(gdi, '#include "settings.h"', '''#include "settings.h"

/* Keybash: set when the server resized the desktop; rdp.c then asks once for
 * a full repaint when the connection is active again. */
int keybash_refresh_pending = 0;''')
replace_once(gdi, '''    guac_client_log(client, GUAC_LOG_DEBUG, "Server resized display to %ix%i",
            gdi->width, gdi->height);''', '''    guac_client_log(client, GUAC_LOG_DEBUG, "Server resized display to %ix%i",
            gdi->width, gdi->height);
    keybash_refresh_pending = 1;''')
replace_once(rdp, '#include "keybash_identity.c"', '#include "keybash_identity.c"\nextern int keybash_refresh_pending;')
replace_once(rdp, '''        /* Notify display of any changes to the GDI that may have occurred
         * while handling events/messages */''', '''        /* Keybash: one full repaint after a resize, once active again. */
        if (keybash_refresh_pending && !connection_closing
                && freerdp_get_state(rdp_inst->context) == CONNECTION_STATE_ACTIVE) {
            keybash_refresh_pending = 0;
            rdpContext* keybash_context = rdp_inst->context;
            const RECTANGLE_16 keybash_all = { 0, 0,
                (UINT16) freerdp_settings_get_uint32(keybash_context->settings, FreeRDP_DesktopWidth),
                (UINT16) freerdp_settings_get_uint32(keybash_context->settings, FreeRDP_DesktopHeight) };
            pthread_mutex_lock(&(rdp_client->message_lock));
            if (keybash_context->update != NULL && keybash_context->update->RefreshRect != NULL)
                (void) keybash_context->update->RefreshRect(keybash_context, 1, &keybash_all);
            pthread_mutex_unlock(&(rdp_client->message_lock));
        }

        /* Notify display of any changes to the GDI that may have occurred
         * while handling events/messages */''')
# The synthetic peer prints the first area a client asks it to repaint.
replace_once(sample, '\tWLog_DBG(TAG, "Client requested to refresh:");',
             '\tif (count > 0) { printf("KB_REFRESH_RECT_%u_%u_%u_%u\\n", areas[0].left, areas[0].top, areas[0].right, areas[0].bottom); fflush(stdout); }\n\tWLog_DBG(TAG, "Client requested to refresh:");')

# guacd started one display worker per online processor, and ignored a thread
# it could not create, later joining it. A few workers are enough for one
# desktop, keep the open image streams within the viewer's count and the
# threads within the worker's RLIMIT_NPROC on large hosts; only created
# threads are counted, and a desktop with none ends.
display = guac / "src/libguac/display.c"
replace_once(display, '#include <unistd.h>', '#include <unistd.h>\n#include <stdlib.h>\n\n/* Keybash: display workers per desktop at most (native/prepare.py). */\n#define KEYBASH_DISPLAY_WORKERS 4')
replace_once(display, '    display->worker_thread_count = cpu_count * GUAC_DISPLAY_CPU_THREAD_FACTOR;\n',
             '    display->worker_thread_count = cpu_count * GUAC_DISPLAY_CPU_THREAD_FACTOR;\n    if (display->worker_thread_count > KEYBASH_DISPLAY_WORKERS)\n        display->worker_thread_count = KEYBASH_DISPLAY_WORKERS;\n')
replace_once(display, '''    for (int i = 0; i < display->worker_thread_count; i++)
        pthread_create(&(display->worker_threads[i]), NULL, guac_display_worker_thread, display);''', '''    int keybash_workers = 0;
    while (keybash_workers < display->worker_thread_count
            && pthread_create(&(display->worker_threads[keybash_workers]), NULL, guac_display_worker_thread, display) == 0)
        keybash_workers++;
    display->worker_thread_count = keybash_workers;
    if (keybash_workers == 0) {
        guac_client_log(client, GUAC_LOG_ERROR, "No display worker thread could be started.");
        abort();
    }''')

# A removed layer's last-frame buffer went back to guacd's pool without a
# dispose, so the browser kept its canvas and the viewer counted its pixels
# for the rest of the session: pointers FreeRDP's cache dropped accumulated.
layers = guac / "src/libguac/display-layer-list.c"
replace_once(layers, '#include "guacamole/mem.h"', '#include "guacamole/mem.h"\n#include "guacamole/protocol.h"')
replace_once(layers, '''    guac_client* client = display->client;
    guac_client_free_buffer(client, display_layer->last_frame_buffer);''', '''    guac_client* client = display->client;
    guac_protocol_send_dispose(client->socket, display_layer->last_frame_buffer);
    guac_client_free_buffer(client, display_layer->last_frame_buffer);''')

# The gateway decodes every image and writes it again, so guacd's default
# compression (zlib level 6; for more than 256 colours Cairo's writer with
# adaptive filters) bought nothing but CPU on the local socket. Palette tiles
# use the fastest level; opaque truecolour tiles get a direct libpng writer
# with the fastest level and the one Sub filter. Transparent layers (the
# pointer) keep Cairo's writer.
encode = guac / "src/libguac/encode-png.c"
replace_once(encode, '''    png_set_write_fn(png, &write_state,
            guac_png_write_handler,
            guac_png_flush_handler);''', '''    png_set_write_fn(png, &write_state,
            guac_png_write_handler,
            guac_png_flush_handler);
    png_set_compression_level(png, 1);''')
replace_once(encode, '''    /* If not possible, resort to Cairo PNG writer */
    if (palette == NULL)
        return guac_png_cairo_write(socket, stream, surface);''', '''    /* Keybash: if not possible, write truecolour directly (prepare.py) */
    if (palette == NULL)
        return keybash_png_rgb_write(socket, stream, surface);''')
replace_once(encode, '''int guac_png_write(guac_socket* socket, guac_stream* stream,
        cairo_surface_t* surface) {''', '''/* Keybash (native/prepare.py): an opaque truecolour surface as 8-bit RGB,
 * the fastest zlib level and the one Sub filter. */
static int keybash_png_rgb_write(guac_socket* socket, guac_stream* stream,
        cairo_surface_t* surface) {

    int width = cairo_image_surface_get_width(surface);
    int height = cairo_image_surface_get_height(surface);
    int stride = cairo_image_surface_get_stride(surface);
    unsigned char* data = cairo_image_surface_get_data(surface);
    guac_png_write_state write_state;

    png_structp png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png) {
        guac_error = GUAC_STATUS_INTERNAL_ERROR;
        guac_error_message = "libpng failed to create write structure";
        return -1;
    }
    png_infop png_info = png_create_info_struct(png);
    if (!png_info) {
        png_destroy_write_struct(&png, NULL);
        guac_error = GUAC_STATUS_INTERNAL_ERROR;
        guac_error_message = "libpng failed to create info structure";
        return -1;
    }
    png_byte* row = (png_byte*) guac_mem_alloc(width, 3);
    if (setjmp(png_jmpbuf(png))) {
        png_destroy_write_struct(&png, &png_info);
        guac_mem_free(row);
        guac_error = GUAC_STATUS_IO_ERROR;
        guac_error_message = "libpng output error";
        return -1;
    }

    write_state.socket = socket;
    write_state.stream = stream;
    write_state.buffer_size = 0;
    png_set_write_fn(png, &write_state, guac_png_write_handler, guac_png_flush_handler);
    png_set_compression_level(png, 1);
    png_set_filter(png, PNG_FILTER_TYPE_BASE, PNG_FILTER_SUB);
    png_set_IHDR(png, png_info, width, height, 8, PNG_COLOR_TYPE_RGB,
            PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
    png_write_info(png, png_info);
    for (int y = 0; y < height; y++) {
        const uint32_t* source = (const uint32_t*) (data + (size_t) y * stride);
        for (int x = 0; x < width; x++) {
            row[3*x]     = (source[x] >> 16) & 0xFF;
            row[3*x + 1] = (source[x] >> 8) & 0xFF;
            row[3*x + 2] = source[x] & 0xFF;
        }
        png_write_row(png, row);
    }
    png_write_end(png, NULL);
    png_destroy_write_struct(&png, &png_info);
    guac_mem_free(row);

    guac_png_flush_data(&write_state);
    return 0;

}

int guac_png_write(guac_socket* socket, guac_stream* stream,
        cairo_surface_t* surface) {''')
