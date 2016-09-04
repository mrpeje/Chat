#include "Crypto.hpp"
 
using namespace std;
 
EVP_PKEY* Crypto::localKeypair;
 
Crypto::Crypto() {
    localKeypair  = NULL;
    remotePubKey  = NULL;
 
    #ifdef PSUEDO_CLIENT
        genTestClientKey();
    #endif
 
    init();
}
 
Crypto::Crypto(unsigned char *remotePubKey, size_t remotePubKeyLen) {
    localKeypair        = NULL;
    this->remotePubKey  = NULL;
 
    setRemotePubKey(remotePubKey, remotePubKeyLen);
    init();
}
 
Crypto::~Crypto() {
    EVP_PKEY_free(remotePubKey);
 
    EVP_CIPHER_CTX_cleanup(rsaEncryptCtx);
    EVP_CIPHER_CTX_cleanup(rsaDecryptCtx);
 
    free(rsaEncryptCtx);
    free(rsaDecryptCtx);
}

int Crypto::rsaEncrypt( const unsigned char *msg,
                        size_t msgLen,
                        unsigned char **encMsg,
                        unsigned char **ek,
                        size_t *ekl,
                        unsigned char **iv,
                        size_t *ivl )
{
    size_t encMsgLen = 0;
    size_t blockLen  = 0;
 
    *ek = (unsigned char*)malloc(EVP_PKEY_size(remotePubKey));
    *iv = (unsigned char*)malloc(EVP_MAX_IV_LENGTH);
    if(*ek == NULL || *iv == NULL) return FAILURE;
    *ivl = EVP_MAX_IV_LENGTH;
 
    *encMsg = (unsigned char*)malloc(msgLen + EVP_MAX_IV_LENGTH);
    if(encMsg == NULL) return FAILURE;
 
    if(!EVP_SealInit(rsaEncryptCtx, EVP_aes_256_cbc(), ek, (int*)ekl, *iv, &remotePubKey, 1)) {
        return FAILURE;
    }
 
    if(!EVP_SealUpdate(rsaEncryptCtx, *encMsg + encMsgLen, (int*)&blockLen, (const unsigned char*)msg, (int)msgLen)) {
        return FAILURE;
    }
    encMsgLen += blockLen;
 
    if(!EVP_SealFinal(rsaEncryptCtx, *encMsg + encMsgLen, (int*)&blockLen)) {
        return FAILURE;
    }
    encMsgLen += blockLen;
 
    EVP_CIPHER_CTX_cleanup(rsaEncryptCtx);
 
    return (int)encMsgLen;
}
 
int Crypto::rsaDecrypt(unsigned char *encMsg, size_t encMsgLen, unsigned char *ek, size_t ekl, unsigned char *iv, size_t ivl, unsigned char **decMsg) {
    size_t decLen   = 0;
    size_t blockLen = 0;
    EVP_PKEY *key;
 
    *decMsg = (unsigned char*)malloc(encMsgLen + ivl);
    if(decMsg == NULL) return FAILURE;
 
    #ifdef PSUEDO_CLIENT
        key = remotePubKey;
    #else
        key = localKeypair;
    #endif
 
    if(!EVP_OpenInit(rsaDecryptCtx, EVP_aes_256_cbc(), ek, ekl, iv, key)) {
        return FAILURE;
    }
 
    if(!EVP_OpenUpdate(rsaDecryptCtx, (unsigned char*)*decMsg + decLen, (int*)&blockLen, encMsg, (int)encMsgLen)) {
        return FAILURE;
    }
    decLen += blockLen;
 
    if(!EVP_OpenFinal(rsaDecryptCtx, (unsigned char*)*decMsg + decLen, (int*)&blockLen)) {
        return FAILURE;
    }
    decLen += blockLen;
  
    EVP_CIPHER_CTX_cleanup(rsaDecryptCtx);
 
    return (int)decLen;
}
 
int Crypto::writeKeyToFile(FILE *fd, int key) {
    switch(key) {
        case KEY_SERVER_PRI:
            if(!PEM_write_PrivateKey(fd, localKeypair, NULL, NULL, 0, 0, NULL)) {
                return FAILURE;
            }
            break;

        case KEY_SERVER_PUB:
            if(!PEM_write_PUBKEY(fd, localKeypair)) {
                return FAILURE;
            }
            break;

        case KEY_CLIENT_PUB:
            if(!PEM_write_PUBKEY(fd, remotePubKey)) {
                return FAILURE;
            }
            break;

        default:
            return FAILURE;
    }
 
    return SUCCESS;
}
 
int Crypto::getRemotePubKey(unsigned char **pubKey) {
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, remotePubKey);
 
    int pubKeyLen = BIO_pending(bio);
    *pubKey = (unsigned char*)malloc(pubKeyLen);
    if(pubKey == NULL) return FAILURE;
 
    BIO_read(bio, *pubKey, pubKeyLen);
 
    // Insert the NUL terminator
    (*pubKey)[pubKeyLen-1] = '\0';
 
    BIO_free_all(bio);
 
    return pubKeyLen;
}
 
int Crypto::setRemotePubKey(unsigned char* pubKey, size_t pubKeyLen) {
    //BIO *bio = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new(BIO_s_mem());
    if(BIO_write(bio, pubKey, pubKeyLen) != (int)pubKeyLen) {
        return FAILURE;
    }
 
    RSA *_pubKey = (RSA*)malloc(sizeof(RSA));
    if(_pubKey == NULL) return FAILURE;
 
    PEM_read_bio_PUBKEY(bio, &remotePubKey, NULL, NULL);
 
    BIO_free_all(bio);
 
    return SUCCESS;
}
 
int Crypto::getLocalPubKey(unsigned char** pubKey) {
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, localKeypair);
 
    int pubKeyLen = BIO_pending(bio);
    *pubKey = (unsigned char*)malloc(pubKeyLen);
    if(pubKey == NULL) return FAILURE;
 
    BIO_read(bio, *pubKey, pubKeyLen);
 
    // Insert the NUL terminator
    (*pubKey)[pubKeyLen-1] = '\0';
 
    BIO_free_all(bio);
 
    return pubKeyLen;
}
 
int Crypto::getLocalPriKey(unsigned char **priKey) {
    BIO *bio = BIO_new(BIO_s_mem());
 
    PEM_write_bio_PrivateKey(bio, localKeypair, NULL, NULL, 0, 0, NULL);
 
    int priKeyLen = BIO_pending(bio);
    *priKey = (unsigned char*)malloc(priKeyLen + 1);
    if(priKey == NULL) return FAILURE;
 
    BIO_read(bio, *priKey, priKeyLen);
 
    // Insert the NUL terminator
    (*priKey)[priKeyLen] = '\0';
 
    BIO_free_all(bio);
 
    return priKeyLen;
}
 

int Crypto::init()
{
    // Initalize contexts
    rsaEncryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX)); 
    rsaDecryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
 
    // Always a good idea to check if malloc failed
    if(rsaEncryptCtx == NULL || rsaDecryptCtx == NULL)
        return FAILURE;

 
    // Init these here to make valgrind happy
    EVP_CIPHER_CTX_init(rsaEncryptCtx);
    EVP_CIPHER_CTX_init(rsaDecryptCtx);

 
    // Init RSA
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
 
    if(EVP_PKEY_keygen_init(ctx) <= 0)
        return FAILURE;
 
    if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEYLEN) <= 0)
        return FAILURE;
 
    if(EVP_PKEY_keygen(ctx, &localKeypair) <= 0)
        return FAILURE;
 
    EVP_PKEY_CTX_free(ctx);
 
    return SUCCESS;
}
 
int Crypto::genTestClientKey() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
 
    if(EVP_PKEY_keygen_init(ctx) <= 0) {
        return FAILURE;
    }
 
    if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEYLEN) <= 0) {
        return FAILURE;
    }
 
    if(EVP_PKEY_keygen(ctx, &remotePubKey) <= 0) {
        return FAILURE;
    }
 
    EVP_PKEY_CTX_free(ctx);
 
    return SUCCESS;
}
