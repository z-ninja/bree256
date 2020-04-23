/**########################################################################
  MIT License

Copyright (c) 2020 zninja

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
##########################################################################*/

#include <crypto/experimental/bree_symmetric.h>
#include <crypto/hash/sha256.h>
#include <string.h>
#include <stdio.h>
#include <iostream>
namespace bree
{
namespace experimental
{
#define NONCE_KEY_BLOCK_ROUND(l_nonce,l_key)\
l_nonce[0] += l_key[0];\
l_nonce[1] += l_key[1];\
l_nonce[2] += l_key[2];\
l_nonce[3] += l_key[3];\
l_nonce[4] += l_key[4];\
l_nonce[5] += l_key[5];\
l_nonce[6] += l_key[6];\
l_nonce[7] += l_key[7];\
l_nonce[8] += l_key[8];\
l_nonce[9] += l_key[9];\
l_nonce[10] += l_key[10];\
l_nonce[11] += l_key[11];\
l_nonce[0] += l_key[12];\
l_nonce[1] += l_key[13];\
l_nonce[2] += l_key[14];\
l_nonce[3] += l_key[15];\
l_nonce[4] += l_key[16];\
l_nonce[5] += l_key[17];\
l_nonce[6] += l_key[18];\
l_nonce[7] += l_key[19];\
l_nonce[8] += l_key[20];\
l_nonce[9] += l_key[21];\
l_nonce[10] += l_key[22];\
l_nonce[11] += l_key[23];\
l_nonce[0] += l_key[24];\
l_nonce[1] += l_key[25];\
l_nonce[2] += l_key[26];\
l_nonce[3] += l_key[27];\
l_nonce[4] += l_key[28];\
l_nonce[5] += l_key[29];\
l_nonce[6] += l_key[30];\
l_nonce[7] += l_key[31];\
l_nonce[8] += l_key[0];\
l_nonce[9] += l_key[1];\
l_nonce[10] += l_key[2];\
l_nonce[11] += l_key[3];


#define KEY_SUM(l_key_t,a_key)\
l_key_t+=a_key[0];\
l_key_t+=a_key[1];\
l_key_t+=a_key[2];\
l_key_t+=a_key[3];\
l_key_t+=a_key[4];\
l_key_t+=a_key[5];\
l_key_t+=a_key[6];\
l_key_t+=a_key[7];\
l_key_t+=a_key[8];\
l_key_t+=a_key[9];\
l_key_t+=a_key[10];\
l_key_t+=a_key[11];\
l_key_t+=a_key[12];\
l_key_t+=a_key[13];\
l_key_t+=a_key[14];\
l_key_t+=a_key[15];\
l_key_t+=a_key[16];\
l_key_t+=a_key[17];\
l_key_t+=a_key[18];\
l_key_t+=a_key[19];\
l_key_t+=a_key[20];\
l_key_t+=a_key[21];\
l_key_t+=a_key[22];\
l_key_t+=a_key[23];\
l_key_t+=a_key[24];\
l_key_t+=a_key[25];\
l_key_t+=a_key[26];\
l_key_t+=a_key[27];\
l_key_t+=a_key[28];\
l_key_t+=a_key[29];\
l_key_t+=a_key[30];\
l_key_t+=a_key[31];

#define KEY_L_INIT(l_key,a_key)\
l_key[0]=a_key[0];\
l_key[1]=a_key[1];\
l_key[2]=a_key[2];\
l_key[3]=a_key[3];\
l_key[4]=a_key[4];\
l_key[5]=a_key[5];\
l_key[6]=a_key[6];\
l_key[7]=a_key[7];\
l_key[8]=a_key[8];\
l_key[9]=a_key[9];\
l_key[10]=a_key[10];\
l_key[11]=a_key[11];\
l_key[12]=a_key[12];\
l_key[13]=a_key[13];\
l_key[14]=a_key[14];\
l_key[15]=a_key[15];\
l_key[16]=a_key[16];\
l_key[17]=a_key[17];\
l_key[18]=a_key[18];\
l_key[19]=a_key[19];\
l_key[20]=a_key[20];\
l_key[21]=a_key[21];\
l_key[22]=a_key[22];\
l_key[23]=a_key[23];\
l_key[24]=a_key[24];\
l_key[25]=a_key[25];\
l_key[26]=a_key[26];\
l_key[27]=a_key[27];\
l_key[28]=a_key[28];\
l_key[29]=a_key[29];\
l_key[30]=a_key[30];\
l_key[31]=a_key[31];

#define NONCE_L_INIT(l_nonce,a_nonce)\
l_nonce[0]=a_nonce[0];\
l_nonce[1]=a_nonce[1];\
l_nonce[2]=a_nonce[2];\
l_nonce[3]=a_nonce[3];\
l_nonce[4]=a_nonce[4];\
l_nonce[5]=a_nonce[5];\
l_nonce[6]=a_nonce[6];\
l_nonce[7]=a_nonce[7];\
l_nonce[8]=a_nonce[8];\
l_nonce[9]=a_nonce[9];\
l_nonce[10]=a_nonce[10];\
l_nonce[11]=a_nonce[11];
void bree256_keys_init(bree256_keys*a_keys,bree256_key a_shared_key)
{

    KEY_L_INIT(a_keys->m_shared_key,a_shared_key);
    sha256_ctx l_ctx;
    sha256_init( &l_ctx );
    sha256_update( &l_ctx, a_keys->m_shared_key, 32 );
    sha256_finalize( &l_ctx, a_keys->m_hash_key1 );
    sha256_init( &l_ctx );
    sha256_update( &l_ctx, a_keys->m_hash_key1, 32 );
    sha256_finalize( &l_ctx, a_keys->m_hash_key2 );

}
void bree256_do_encrypt_message(const unsigned char*a_plainText,size_t a_textSize,
                                bree256_keys*a_keys,
                                bree256_nonce a_nonce,unsigned char*a_out)
{
    sha256_hash checksum_hash;
    bree256_do_encrypt(a_plainText,a_textSize,a_keys->m_hash_key1,a_nonce,a_out);
    size_t l_index = a_textSize>=16?a_textSize-16:0;
    size_t l_size = a_textSize-l_index;
    sha256_ctx ctx;
    sha256_init( &ctx );
    sha256_update( &ctx, a_keys->m_shared_key, 32 );
    sha256_update( &ctx, a_plainText+l_index, l_size );
    if(l_index > 0)
    {
        sha256_update( &ctx, a_plainText, l_size );
    }
    sha256_finalize( &ctx, checksum_hash );
    memcpy(a_out+a_textSize, checksum_hash,32);
    bree256_do_encrypt(a_out+a_textSize,32,a_keys->m_hash_key2,a_nonce,a_out+a_textSize);
}
size_t bree256_do_decrypt_message(const unsigned char* a_encryptedText,size_t a_textSize,
                                  bree256_keys*a_keys,bree256_nonce a_nonce,unsigned char*a_out)
{
    sha256_hash key_hash;
    sha256_hash checksum_hash;
    bree256_do_decrypt(a_encryptedText+a_textSize-32,32,a_keys->m_hash_key2,a_nonce,key_hash);
    size_t l_index = (a_textSize-32)>=16?a_textSize-48:0;
    size_t l_size = (a_textSize-32)-l_index;
    bree256_do_decrypt(a_encryptedText,a_textSize-32,a_keys->m_hash_key1,a_nonce,a_out);
    sha256_ctx l_ctx;
    sha256_init( &l_ctx );
    sha256_update( &l_ctx, a_keys->m_shared_key, 32 );
    sha256_update( &l_ctx, a_out+l_index, l_size );
    if(l_index > 0)
    {
        sha256_update( &l_ctx, a_out, l_size );
    }
    sha256_finalize( &l_ctx, checksum_hash );

    for(size_t i=0; i<32; i++)
    {
        if(checksum_hash[i]!= key_hash[i])
        {
            return 0;
        }
    }
    return a_textSize-32;
}
void bree256_do_encrypt_message(const unsigned char*a_plainText,size_t a_textSize,
                                bree256_key a_shared_key,bree256_key a_hash_key1,bree256_key a_hash_key2,
                                bree256_nonce a_nonce,unsigned char*a_out)
{

    sha256_hash checksum_hash;
    bree256_do_encrypt(a_plainText,a_textSize,a_hash_key1,a_nonce,a_out);
    size_t l_index = a_textSize>=32?a_textSize-32:0;
    size_t l_size = a_textSize-l_index;
    sha256_ctx ctx;
    sha256_init( &ctx );
    sha256_update( &ctx, a_shared_key, 32 );
    sha256_update( &ctx, a_plainText+l_index, l_size );
    if(l_index > 0)
    {
        sha256_update( &ctx, a_plainText, l_size );
    }
    sha256_finalize( &ctx, checksum_hash );
    memcpy(a_out+a_textSize, checksum_hash,32);
    bree256_do_encrypt(a_out+a_textSize,32,a_hash_key2,a_nonce,a_out+a_textSize);
}
size_t bree256_do_decrypt_message(const unsigned char* a_encryptedText,size_t a_textSize,
                                  bree256_key a_shared_key,bree256_key a_hash_key1,bree256_key a_hash_key2,
                                  bree256_nonce a_nonce,unsigned char*a_out)
{
    sha256_hash key_hash;
    sha256_hash checksum_hash;
    bree256_do_decrypt(a_encryptedText+a_textSize-32,32,a_hash_key2,a_nonce,key_hash);
    size_t l_index = (a_textSize-32)>=32?a_textSize-64:0;
    size_t l_size = (a_textSize-32)-l_index;
    bree256_do_decrypt(a_encryptedText,a_textSize-32,a_hash_key1,a_nonce,a_out);
    sha256_ctx l_ctx;
    sha256_init( &l_ctx );
    sha256_update( &l_ctx, a_shared_key, 32 );
    sha256_update( &l_ctx, a_out+l_index, l_size );
    if(l_index > 0)
    {
        sha256_update( &l_ctx, a_out, l_size );
    }
    sha256_finalize( &l_ctx, checksum_hash );

    for(size_t i=0; i<32; i++)
    {
        if(checksum_hash[i]!= key_hash[i])
        {
            return 0;
        }
    }
    return a_textSize-32;
}
void bree256_do_encrypt_message(const unsigned char*a_plainText,size_t a_textSize,bree256_key a_shared_key,bree256_nonce a_nonce,unsigned char*a_out)
{
    if(a_textSize <= 0)
    {
        return;
    }
    sha256_hash l_hash_key1;
    sha256_hash l_hash_key2;
    sha256_ctx l_ctx;
    sha256_init( &l_ctx );
    sha256_update( &l_ctx, a_shared_key, 32 );
    sha256_finalize( &l_ctx, l_hash_key1 );
    sha256_init( &l_ctx );
    sha256_update( &l_ctx, l_hash_key1, 32 );
    sha256_finalize( &l_ctx, l_hash_key2 );
    bree256_do_encrypt_message(a_plainText,a_textSize,a_shared_key,l_hash_key1,l_hash_key2,a_nonce,a_out);
}

size_t bree256_do_decrypt_message(const unsigned char* a_encryptedText,size_t a_textSize,bree256_key a_shared_key,bree256_nonce a_nonce,unsigned char*a_out)
{
    if(a_textSize <=32)
    {
        return 0;
    }
    sha256_hash l_hash_key1;
    sha256_hash l_hash_key2;
    sha256_ctx l_ctx;
    sha256_init( &l_ctx );
    sha256_update( &l_ctx, a_shared_key, 32 );
    sha256_finalize( &l_ctx, l_hash_key1 );
    sha256_init( &l_ctx );
    sha256_update( &l_ctx, l_hash_key1, 32 );
    sha256_finalize( &l_ctx, l_hash_key2 );
    return bree256_do_decrypt_message(a_encryptedText,a_textSize,a_shared_key,l_hash_key1,l_hash_key2,a_nonce,a_out);
}
#define NONCE_SUM(l_nonce_sum,l_nonce)\
l_nonce_sum+=l_nonce[0];\
l_nonce_sum+=l_nonce[1];\
l_nonce_sum+=l_nonce[2];\
l_nonce_sum+=l_nonce[3];\
l_nonce_sum+=l_nonce[4];\
l_nonce_sum+=l_nonce[5];\
l_nonce_sum+=l_nonce[6];\
l_nonce_sum+=l_nonce[7];\
l_nonce_sum+=l_nonce[8];\
l_nonce_sum+=l_nonce[9];\
l_nonce_sum+=l_nonce[10];\
l_nonce_sum+=l_nonce[11];\

void bree256_do_encrypt(const unsigned char*a_plainText,size_t a_textSize,bree256_key a_key,bree256_nonce a_nonce,unsigned char*a_out)
{
    bree256_nonce l_nonce;
    bree256_key l_key;
    uint8_t l_key_sum = 0;
    uint8_t l_nonce_sum = 0;


    NONCE_L_INIT(l_nonce,a_nonce)
    KEY_L_INIT(l_key,a_key)
    KEY_SUM(l_key_sum,a_key)
    NONCE_KEY_BLOCK_ROUND(l_nonce,l_key)
    NONCE_SUM(l_nonce_sum,l_nonce);
    for(int i=a_textSize-1; i>=0; i--)
    {
        /*if((i % 4)==0)
        {
            NONCE_KEY_BLOCK_ROUND(l_nonce,l_key)
        }*/
        a_out[i] = a_plainText[i]+(l_key_sum+l_nonce_sum+l_key[i%32]+l_nonce[i%12]);
        l_key[i%32]+=a_out[i]+l_nonce[11]+l_nonce_sum;
        NONCE_KEY_BLOCK_ROUND(l_nonce,l_key)
    }
}



void bree256_do_decrypt(const unsigned char* a_encryptedText,size_t a_textSize,bree256_key a_key,bree256_nonce a_nonce,unsigned char*a_out)
{
    bree256_nonce l_nonce;
    bree256_key l_key;
    uint8_t l_key_sum = 0;
    uint8_t l_nonce_sum = 0;
    NONCE_L_INIT(l_nonce,a_nonce)
    KEY_L_INIT(l_key,a_key)
    KEY_SUM(l_key_sum,a_key)
    NONCE_KEY_BLOCK_ROUND(l_nonce,l_key)
    NONCE_SUM(l_nonce_sum,l_nonce);
    for(int i=a_textSize-1; i>=0; i--)
    {
       /* if((i % 4)==0)
        {
            NONCE_KEY_BLOCK_ROUND(l_nonce,l_key)
        }*/
        a_out[i] = a_encryptedText[i]-(l_key_sum+l_nonce_sum+l_key[i%32]+l_nonce[i%12]);
        l_key[i%32]+=a_encryptedText[i]+l_nonce[11]+l_nonce_sum;
        NONCE_KEY_BLOCK_ROUND(l_nonce,l_key)
    }
}


}/// experimental
}/// bree
