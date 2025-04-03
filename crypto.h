#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h> //fix rand warning
//////////////MACROS////////////////////////////////////////////////////////////
#define MIN(a,b)                (((a)<(b))?(a):(b))
#define MAX(a,b)                (((a)>(b))?(a):(b))
#define CIPHER_MAX_LEN          256
#define VI_MAX_LEN              12
#define KEY_MAX_LEN             16
////////////////////////////////////////////////////////////////////////////////
//////////////GLOBALS///////////////////////////////////////////////////////////
char *pri_key = NULL;
char *pub_key = NULL;
//char ciphertext_iv[CIPHER_MAX_LEN + VI_MAX_LEN] = {0};
////////////////////////////////////////////////////////////////////////////////

void handleErrors(const char * msg, const char * function) 
{
    printf("[%s]Error : %s \n", function, msg);
    exit(-1);
}


int generate_key_pair()
{
   const int kBits = 2048;
   // Use 65537
   const unsigned long kExp = 65537;

   // Use modern OpenSSL APIs
   EVP_PKEY *pkey = EVP_PKEY_new();
   if (!pkey) handleErrors("failed to create new pair key", __func__);

   EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
   if (!ctx) handleErrors("failed to create new id ctx", __func__);

   EVP_PKEY_keygen_init(ctx);
   EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, kBits);
   EVP_PKEY_keygen(ctx, &pkey);

   // Create BIO buffers
   BIO *pri_bio = BIO_new(BIO_s_mem());
   BIO *pub_bio = BIO_new(BIO_s_mem());
   
   if (!pri_bio || !pub_bio) {
       fprintf(stderr, "Failed to create BIO buffers\n");
       if (pri_bio) BIO_free(pri_bio);
       if (pub_bio) BIO_free(pub_bio);
       EVP_PKEY_CTX_free(ctx);
       EVP_PKEY_free(pkey);
       return 1;
   }

   // Write keys to BIO
   if (!PEM_write_bio_PrivateKey(pri_bio, pkey, NULL, NULL, 0, NULL, NULL) ||
       !PEM_write_bio_PUBKEY(pub_bio, pkey)) {
       fprintf(stderr, "Failed to write keys to BIO\n");
       BIO_free(pri_bio);
       BIO_free(pub_bio);
       EVP_PKEY_CTX_free(ctx);
       EVP_PKEY_free(pkey);
       return 1;
   }

   // Get lengths
   int pri_len = BIO_pending(pri_bio);
   int pub_len = BIO_pending(pub_bio);

   // Allocate memory for buffers (freed by caller) -> allocating as globals instead
   pri_key = (char *)malloc(pri_len + 1);
   pub_key = (char *)malloc(pub_len + 1);
   
   // Read BIO into buffers
   BIO_read(pri_bio, pri_key, pri_len);
   BIO_read(pub_bio, pub_key, pub_len);

   // Null-terminate the buffers
   pri_key[pri_len] = '\0';
   pub_key[pub_len] = '\0';

   // Print the keys
   //printf("Private Key:\n%s\n", pri_key);
   //printf("Public Key:\n%s\n", pub_key);

   // Free OpenSSL resources
   BIO_free(pri_bio);
   BIO_free(pub_bio);
   EVP_PKEY_CTX_free(ctx);
   EVP_PKEY_free(pkey);
}


// Function to encrypt data using RSA public key
int encrypt_symetric_key_with_public_key(char *public_key, const unsigned char *data, int data_len, unsigned char *encrypted) 
{
    if (!public_key || !data || !encrypted) handleErrors("NULL pointer", __func__);
    BIO *bio = BIO_new_mem_buf(public_key, -1);
    if (!bio) handleErrors("failed to bio", __func__);

    // Use modern PEM read function for EVP_PKEY
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) handleErrors("failed to read public key", __func__);

    // Create encryption context
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) handleErrors("failed to create decryption ctx", __func__);

    EVP_PKEY_encrypt_init(ctx);
    // Set padding mode - OAEP is more secure
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    // Determine output buffer size
    size_t outlen;
    EVP_PKEY_encrypt(ctx, NULL, &outlen, data, data_len);
    // Perform actual encryption
    EVP_PKEY_encrypt(ctx, encrypted, &outlen, data, data_len);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    //printf("encrypted = %s \n", encrypted);
    return outlen;
}

void encrypt_data_with_symetric_key(const unsigned char * S_key, const unsigned char * iv, unsigned char * message, unsigned char * encrypted_msg) 
{
    if (!S_key || !iv || !message) handleErrors("NULL pointer", __func__);
    int len, ciphertext_len;
    unsigned char ciphertext[CIPHER_MAX_LEN] = {0};

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors("failed to create decryption ctx", __func__);

    // Encryption
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, S_key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, message, sizeof(ciphertext));
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    //ciphertext[ciphertext_len] = '\0';

    //copy the iv from the first 16 bytes
    memcpy(encrypted_msg, iv, VI_MAX_LEN);
    memcpy(encrypted_msg + VI_MAX_LEN , ciphertext, sizeof(ciphertext));

    // printf("Ciphertext: ");
    // for (int i = 0; i < sizeof(ciphertext_iv); i++) printf("%02x", ciphertext_iv[i]);
    
    // printf("\n");
}

void decrypt_data_with_symetric_key(const unsigned char * S_key, char * encrypted_message, char * decrypted_message) 
{
    if (!S_key || !encrypted_message || !decrypted_message) handleErrors("NULL pointer", __func__);
    int len, decrypted_len = 0;
    unsigned char decryptedtext[CIPHER_MAX_LEN] = {0};
    unsigned char cipher_text[CIPHER_MAX_LEN] = {0};
    const unsigned char iv[VI_MAX_LEN] = {0};

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors("failed to create decryption ctx", __func__);

    //Extract the first 16 bytes for iv
    memcpy((void *)iv, encrypted_message, VI_MAX_LEN);
    //Extract the ciphered text
    memcpy(cipher_text, encrypted_message + VI_MAX_LEN, sizeof(cipher_text));

    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, S_key, iv);
    EVP_DecryptUpdate(ctx, decryptedtext, &len, cipher_text, sizeof(cipher_text));
    decrypted_len = len;
    EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len);
    decrypted_len += len;
    //printf("decrypted_len  = %d \n", decrypted_len);
    decryptedtext[decrypted_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);

    //fill output buffer
    memcpy(decrypted_message, decryptedtext, decrypted_len);
    //printf("Decrypted: %s\n", decrypted_message);
}

// Function to decrypt data using RSA private key
int decrypt_symetric_key_with_private_key(char *private_key_buffer, unsigned char *encrypted_data, int encrypted_len, unsigned char *decrypted) 
{
    if (!private_key_buffer || !encrypted_data || !decrypted) handleErrors("NULL pointer", __func__);
    size_t outlen;
    // Create BIO from memory buffer
    BIO *bio = BIO_new_mem_buf(private_key_buffer, -1);
    if (!bio) handleErrors("failed to create bio", __func__);

    // Read private key from BIO
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) handleErrors("failed to read private key", __func__);

    // Create decryption context
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) handleErrors("failed to create decryption ctx", __func__);

    // Initialize decryption operation
    if (EVP_PKEY_decrypt_init(ctx) <= 0) 
    {
        handleErrors("decrypt init failed", __func__);
    }
    if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA) 
    {
        handleErrors("key is not RSA", __func__);
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        handleErrors("padding set failed", __func__);
    }   
    //Get output length
    EVP_PKEY_decrypt(ctx, NULL, &outlen, encrypted_data, encrypted_len);
    //Actual decryption
    EVP_PKEY_decrypt(ctx, decrypted, &outlen, encrypted_data, encrypted_len);
    // Clean up
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return outlen;
}