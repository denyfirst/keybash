/* Keybash native RDP lab: OpenSSL identity checks on the worker's own TLS.
 * No credential handling or certificate-ignore/TOFU fallback. */
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>

int keybash_verify_identity(const char* pem, size_t length) {
    int accepted = 0;
    char name[254] = {0};
    unsigned char actual_hash[EVP_MAX_MD_SIZE], approved_hash[EVP_MAX_MD_SIZE];
    unsigned int actual_size = 0, approved_size = 0;
    FILE* file = NULL;
    BIO* input = NULL;
    X509 *actual = NULL, *approved = NULL;
    X509_STORE* roots = NULL;
    X509_STORE_CTX* verify = NULL;
    EVP_PKEY* public_key = NULL;

    if (!pem || length == 0 || length > 65536) goto done;
    input = BIO_new_mem_buf(pem, (int)length);
    if (!input || !(actual = PEM_read_bio_X509(input, NULL, NULL, NULL))) goto done;
    file = fopen("/run/keybash/approved.pem", "rb");
    if (!file) goto done;
    approved = PEM_read_X509(file, NULL, NULL, NULL);
    fclose(file); file = NULL;
    if (!approved) goto done;
    file = fopen("/run/keybash/name", "rb");
    if (!file) goto done;
    size_t size = fread(name, 1, sizeof(name) - 1, file);
    int tail = fgetc(file);
    fclose(file); file = NULL;
    if (size == 0 || tail != EOF || strlen(name) != size) goto done;
    for (size_t i = 0; i < size; i++) {
        if (!((name[i] >= 'a' && name[i] <= 'z') || (name[i] >= '0' && name[i] <= '9') || name[i] == '.' || name[i] == '-')) goto done;
    }
    if (X509_check_ca(actual) != 0 ||
        !X509_digest(actual, EVP_sha256(), actual_hash, &actual_size) ||
        !X509_digest(approved, EVP_sha256(), approved_hash, &approved_size) ||
        actual_size != 32 || approved_size != 32 ||
        CRYPTO_memcmp(actual_hash, approved_hash, 32) != 0) goto done;
    if (X509_get_ext_by_NID(actual, NID_key_usage, -1) < 0 ||
        X509_get_ext_by_NID(actual, NID_ext_key_usage, -1) < 0 ||
        !(X509_get_key_usage(actual) & KU_DIGITAL_SIGNATURE) ||
        !(X509_get_extended_key_usage(actual) & XKU_SSL_SERVER)) goto done;
    public_key = X509_get_pubkey(actual);
    if (!public_key) goto done;
    int type = EVP_PKEY_base_id(public_key);
    int bits = EVP_PKEY_bits(public_key);
    if (!((type == EVP_PKEY_RSA && bits >= 2048) ||
          (type == EVP_PKEY_EC && bits >= 256) || type == EVP_PKEY_ED25519)) goto done;

    roots = X509_STORE_new();
    verify = X509_STORE_CTX_new();
    if (!roots || !verify || !X509_STORE_add_cert(roots, approved) ||
        !X509_STORE_CTX_init(verify, roots, actual, NULL)) goto done;
    X509_VERIFY_PARAM* params = X509_STORE_CTX_get0_param(verify);
    if (!params || !X509_VERIFY_PARAM_set1_host(params, name, size) ||
        !X509_VERIFY_PARAM_set_purpose(params, X509_PURPOSE_SSL_SERVER) ||
        !X509_VERIFY_PARAM_set_flags(params, X509_V_FLAG_PARTIAL_CHAIN)) goto done;
    X509_VERIFY_PARAM_set_hostflags(params, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT | X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    X509_VERIFY_PARAM_set_auth_level(params, 2);
    accepted = X509_verify_cert(verify) == 1;
done:
    if (file) fclose(file);
    X509_STORE_CTX_free(verify);
    EVP_PKEY_free(public_key);
    X509_STORE_free(roots);
    X509_free(approved);
    X509_free(actual);
    BIO_free(input);
    return accepted;
}
