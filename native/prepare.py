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
    if (flags != 0) return 0;
    return keybash_verify_identity((const char*)pem, length);
}

'''
# The lab exclusively builds the pinned FreeRDP 3 API.
replace_once(rdp, anchor, callback + anchor)
replace_once(rdp, '#include "rdp.h"', '#include "rdp.h"\n#include <freerdp/version.h>\n_Static_assert(FREERDP_VERSION_MAJOR == 3, "Keybash lab requires FreeRDP 3");\n#include "keybash_identity.c"')
(rdp.parent / "keybash_identity.c").write_bytes(identity_source.read_bytes())
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
anchor = "freerdp_settings_set_bool(rdp_settings, FreeRDP_IgnoreCertificate, guac_settings->ignore_certificate);"
replace_once(settings, anchor, '''freerdp_settings_set_bool(rdp_settings, FreeRDP_IgnoreCertificate, FALSE);
    freerdp_settings_set_bool(rdp_settings, FreeRDP_AutoAcceptCertificate, FALSE);
    freerdp_settings_set_uint32(rdp_settings, FreeRDP_CookieMaxLength, 0);
    freerdp_settings_set_bool(rdp_settings, FreeRDP_ExternalCertificateManagement, TRUE);
    freerdp_settings_set_uint16(rdp_settings, FreeRDP_TLSMinVersion, 0x0303);
    freerdp_settings_set_string(rdp_settings, FreeRDP_AllowedTlsCiphers, "ECDHE+AESGCM:ECDHE+CHACHA20");''')
replace_once(settings, "freerdp_settings_set_bool(rdp_settings, FreeRDP_AutoAcceptCertificate, guac_settings->certificate_tofu);", "/* Automatic certificate trust is forbidden by the Keybash lab. */")
replace_once(settings, "if (guac_settings->certificate_fingerprints != NULL)\n        freerdp_settings_set_string(rdp_settings, FreeRDP_CertificateAcceptedFingerprints, \n                guac_strdup(guac_settings->certificate_fingerprints));", "/* The mandatory exact pin is checked in the native X509 callback. */")
