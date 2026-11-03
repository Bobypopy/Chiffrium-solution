#include <openssl/evp.h>

int encrypt(EVP_CIPHER_CTX *ctx, unsigned char *key, unsigned char *iv) {
    return EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv);
}

int digest(EVP_MD_CTX *ctx) {
    return EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
}
