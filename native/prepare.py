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
replace_once(sample, "FreeRDP_RdpSecurity, TRUE", "FreeRDP_RdpSecurity, FALSE")
replace_once(sample, "FreeRDP_TlsSecurity, TRUE", "FreeRDP_TlsSecurity, FALSE")
replace_once(sample, "FreeRDP_NlaSecurity, FALSE", "FreeRDP_NlaSecurity, TRUE")
replace_once(sample, "instance->Open(instance, nullptr, (UINT16)port)", 'instance->Open(instance, "127.0.0.1", (UINT16)port)')
replace_once(sample, "if (!freerdp_settings_set_bool(settings, FreeRDP_NlaSecurity, TRUE))",
             'if (!freerdp_settings_set_string(settings, FreeRDP_NtlmSamFile, "/run/fixture/SAM") ||\n\t    !freerdp_settings_set_bool(settings, FreeRDP_NlaSecurity, TRUE))')
replace_once(sample, "static BOOL tf_peer_post_connect(freerdp_peer* client)\n{", "static BOOL tf_peer_post_connect(freerdp_peer* client)\n{\n\tputs(\"KB_AUTHENTICATED\"); fflush(stdout);")

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
# The sample peer requires a negotiated classic bitmap codec. Guacamole only
# enables RemoteFX together with its disabled dynamic graphics pipeline, while
# FreeRDP's default NSCodec is off. Enable the classic lossless NSCodec path
# explicitly; this does not open a virtual channel or change TLS/NLA policy.
replace_once(settings, "/* Always request frame markers */",
             "/* Fixed classic bitmap path; dynamic graphics remains disabled. */\n    freerdp_settings_set_bool(rdp_settings, FreeRDP_NSCodec, TRUE);\n    freerdp_settings_set_bool(rdp_settings, FreeRDP_NSCodecAllowDynamicColorFidelity, FALSE);\n    freerdp_settings_set_bool(rdp_settings, FreeRDP_NSCodecAllowSubsampling, FALSE);\n    freerdp_settings_set_uint32(rdp_settings, FreeRDP_NSCodecColorLossLevel, 0);\n\n    /* Always request frame markers */")
anchor = "freerdp_settings_set_bool(rdp_settings, FreeRDP_IgnoreCertificate, guac_settings->ignore_certificate);"
replace_once(settings, anchor, '''freerdp_settings_set_bool(rdp_settings, FreeRDP_IgnoreCertificate, FALSE);
    freerdp_settings_set_bool(rdp_settings, FreeRDP_AutoAcceptCertificate, FALSE);
    freerdp_settings_set_uint32(rdp_settings, FreeRDP_CookieMaxLength, 0);
    freerdp_settings_set_bool(rdp_settings, FreeRDP_ExternalCertificateManagement, TRUE);
    freerdp_settings_set_uint16(rdp_settings, FreeRDP_TLSMinVersion, 0x0303);
    freerdp_settings_set_string(rdp_settings, FreeRDP_AllowedTlsCiphers, "ECDHE+AESGCM:ECDHE+CHACHA20");''')
replace_once(settings, "freerdp_settings_set_bool(rdp_settings, FreeRDP_AutoAcceptCertificate, guac_settings->certificate_tofu);", "/* Automatic certificate trust is forbidden by the Keybash lab. */")
replace_once(settings, "if (guac_settings->certificate_fingerprints != NULL)\n        freerdp_settings_set_string(rdp_settings, FreeRDP_CertificateAcceptedFingerprints, \n                guac_strdup(guac_settings->certificate_fingerprints));", "/* The mandatory exact pin is checked in the native X509 callback. */")
