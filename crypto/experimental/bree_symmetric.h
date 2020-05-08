#ifndef BREE_SYMMETRIC_H
#define BREE_SYMMETRIC_H
#include <cstddef>
#include <stdint.h>
namespace bree
{
namespace experimental
{
typedef uint8_t bree256_nonce[12];
typedef uint8_t bree256_key[32];

struct bree256_keys{
bree256_key m_shared_key;
bree256_key m_hash_key1;
bree256_key m_hash_key2;
};
void bree256_keys_init(bree256_keys*a_keys,bree256_key a_shared_key);
void bree256_do_encrypt_message(const unsigned char*a_plainText,size_t a_textSize,
                        bree256_keys*a_keys,
                        bree256_nonce a_iv,unsigned char*a_out);
size_t bree256_do_decrypt_message(const unsigned char* a_encryptedText,size_t a_textSize,
                          bree256_keys*a_keys,bree256_nonce a_nonce,unsigned char*a_out);
void bree256_do_encrypt_message(const unsigned char*a_plainText,size_t a_textSize,
                        bree256_key a_shared_key,bree256_key a_hash_key1,bree256_key a_hash_key2,
                        bree256_nonce a_nonce,unsigned char*a_out);
size_t bree256_do_decrypt_message(const unsigned char* a_encryptedText,size_t a_textSize,
                          bree256_key a_shared_key,bree256_key a_hash_key1,bree256_key a_hash_key2,
                          bree256_nonce a_nonce,unsigned char*a_out);
void bree256_do_encrypt_message(const unsigned char*a_plainText,size_t a_textSize,bree256_key a_shared_key,bree256_nonce a_nonce,unsigned char*a_out);
size_t bree256_do_decrypt_message(const unsigned char*a_encryptedText,size_t a_textSize,bree256_key a_shared_key,bree256_nonce a_nonce,unsigned char*a_out);
void bree256_do_encrypt(const unsigned char*a_plainText,size_t a_textSize,bree256_key a_key,bree256_nonce a_nonce,unsigned char*a_out);
void bree256_do_decrypt(const unsigned char*a_encryptedText,size_t a_textSize,bree256_key a_key,bree256_nonce a_nonce,unsigned char*a_out);
}/// experimental
}/// bree
#endif // BREE_SYMMETRIC_H
