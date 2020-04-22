#include <iostream>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <chrono>
#include <string>/// isascii  for windows is probably other header like ctypes.h maybe

#include <crypto/experimental/bree_symmetric.h>
#include <crypto/hash/sha256.h>

#define g_size_of_data 1024*10
void HexDump(const unsigned char* buf, size_t buf_len);
void AE_test_encrypt(bree::experimental::bree256_keys*a_keys,const unsigned char*a_text,unsigned char*a_encrypted_out,bree::experimental::bree256_nonce a_nonce,int a_operatons_count);
void AE_test_decrypt(bree::experimental::bree256_keys*a_keys,const  unsigned char*a_encrypted_out,unsigned char*decrypted_out,bree::experimental::bree256_nonce a_nonce,int a_operatons_count);

void test_encrypt(bree::experimental::bree256_key a_key,const unsigned char*a_text,unsigned char*a_encrypted_out, bree::experimental::bree256_nonce a_nonce,int a_operatons_count);
void test_decrypt(bree::experimental::bree256_key a_key,const  unsigned char*a_encrypted_out,unsigned char*decrypted_out, bree::experimental::bree256_nonce a_nonce,int a_operatons_count);

/*
void test_encrypt(const unsigned char*a_key,const unsigned char*a_text,unsigned char*a_encrypted_out,const  unsigned char a_iv[12],int a_operatons_count);
void test_decrypt(const unsigned char*a_key,const  unsigned char*a_encrypted_out,unsigned char*decrypted_out,const  unsigned char a_iv[12],int a_operatons_count);
*/
template <typename TimeT = std::chrono::milliseconds> struct measure
{
    template <typename F, typename... Args> static typename TimeT::rep begin(F &&func, Args &&... args)
    {
        auto start = std::chrono::steady_clock::now();
        std::forward<decltype(func)>(func)(std::forward<Args>(args)...);
        auto duration = std::chrono::duration_cast<TimeT>(std::chrono::steady_clock::now() - start);
        return duration.count();
    }
};
void example_invalidating_print_test()
{
    std::cout << std::endl << "NEW TEST BEGIN" << std::endl << std::endl;
    std::cout << "Simple example view of data decryption/encryption WITH MODIFIED ENCRYPTED DATA" << std::endl;
    std::cout << "If you change at least one bit on cipher text, by decrypting you will not been able to decrypt rest of the data" <<std::endl;
    std::cout << "Btw, AE mode is designed to detect such changes, so it can validate if data are modified or not" << std::endl;
    std::cout << "But regular decryption is not able to say if decryption is successful or not" << std::endl;
    std::cout << "This test will show output of decrypted data after one byte is modified, if decrypted data does not match the original data, test is successful" << std::endl;
    unsigned char l_text[128];
    for(int u=0; u<128; u++)
    {
        l_text[u] = '0';
    }
    bree::experimental::bree256_nonce l_nonce = {'1','2','3','4','5','6','7','8','9','0','1','2'};
    bree::experimental::bree256_key l_key = {'1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8','9','0','1','2'};
    unsigned char l_encrypted_out[128];
    unsigned char l_decrypted_out[128];
    std::cout << "Encrypting data:" << std::endl;
    HexDump(l_text,128);
    std::cout << std::endl;
    std::cout << "With key:" << std::endl;
    HexDump(l_key,32);
    std::cout << std::endl;
    std::cout << "End nonce: " << std::endl;
    HexDump(l_nonce,12);
    std::cout << std::endl;
    std::cout << "Encrypting.." << std::endl;
    bree::experimental::bree256_do_encrypt(l_text,128,l_key,l_nonce,l_encrypted_out);
    std::cout << "Encrypted data view: " << std::endl;
    HexDump(l_encrypted_out,128);
    std::cout << std::endl;
    std::cout << "modifying byte at position 57 from ";
    printf("hex value %02x to %02x", l_encrypted_out[57],0x35 );
    std::cout << std::endl;
    l_encrypted_out[57] = 0x35;
    std::cout << "Decrypting..." << std::endl;
    bree::experimental::bree256_do_decrypt(l_encrypted_out,128,l_key,l_nonce,l_decrypted_out);
    std::cout << "Decrypted data view" << std::endl;
    HexDump(l_decrypted_out,128);
    std::cout << std::endl;
    if(0 == memcmp((char*) l_text, (char*) l_decrypted_out, 128))
    {
        std::cout << "ENCRYPTION/DECRYPTION TEST WITH INVALIDATED BYTE TEST FAILED" << std::endl;
    }
    else
    {
        std::cout << "ENCRYPTION/DECRYPTION TEST WITH INVALIDATED BYTE PASSED" << std::endl;
    }
    std::cout << std::endl;
    std::cout << "NEW TEST END" << std::endl;
}
#define simple_encryption_text_size 10
void example_print_test()
{
    std::cout << std::endl << "NEW TEST BEGIN" << std::endl << std::endl;
    std::cout << "Simple example view of data decryption/encryption" << std::endl;
    unsigned char l_text[simple_encryption_text_size];
    for(int u=0; u<simple_encryption_text_size; u++)
    {
        l_text[u] = 'a';
    }
    bree::experimental::bree256_nonce l_nonce = {200,200,200,200,200,200,200,200,200,200,200,200};
    bree::experimental::bree256_key l_key = {200,200,200,200,200,200,200,200,200,200,200,200,200,200,200,200
                                             ,200,200,200,200,200,200,200,200,200,200,200,200,200,200,200,200
                                            };
    unsigned char l_encrypted_out[simple_encryption_text_size];
    unsigned char l_decrypted_out[simple_encryption_text_size];
    std::cout << "Encrypting data:" << std::endl;
    HexDump(l_text,simple_encryption_text_size);
    std::cout << std::endl;
    std::cout << "With key:" << std::endl;
    HexDump(l_key,32);
    std::cout << std::endl;
    std::cout << "End nonce: " << std::endl;
    HexDump(l_nonce,12);
    std::cout << std::endl;
    std::cout << "Encrypting.." << std::endl;
    bree::experimental::bree256_do_encrypt(l_text,simple_encryption_text_size,l_key,l_nonce,l_encrypted_out);
    std::cout << "Encrypted data view: " << std::endl;
    HexDump(l_encrypted_out,simple_encryption_text_size);
    std::cout << std::endl;
    std::cout << "Decrypting..." << std::endl;
    bree::experimental::bree256_do_decrypt(l_encrypted_out,simple_encryption_text_size,l_key,l_nonce,l_decrypted_out);
    std::cout << "Decrypted data view" << std::endl;
    HexDump(l_decrypted_out,simple_encryption_text_size);
    std::cout << std::endl;
    if(0 == memcmp((char*) l_text, (char*) l_decrypted_out, simple_encryption_text_size))
    {
        std::cout << "ENCRYPTION/DECRYPTION TEST PASSED" << std::endl;
    }
    else
    {
        std::cout << "ENCRYPTION/DECRYPTION TEST FAILED" << std::endl;
    }
    std::cout << "NEW TEST END" << std::endl;
    std::cout << std::endl;
}

void detecting_message_modification_test()
{
    std::cout << std::endl << "NEW TEST BEGIN" << std::endl << std::endl;
    std::cout << "Detecting integrity of modified text cipher" << std::endl;
    std::cout << "in this test we will modify byte at index 80 of 128 bytes of data size " << std::endl;
    std::cout << "real size of cipher text will be 128+32  128= data size + 32=checksum size" << std::endl;
    unsigned char l_text[128];
    for(int u=0; u<128; u++)
    {
        l_text[u] = 'f';
    }
    bree::experimental::bree256_nonce l_nonce = {'1','2','3','4','5','6','7','8','9','0','1','2'};
    bree::experimental::bree256_key l_key = {'1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8','9','0','1','2'};
    bree::experimental::bree256_keys l_keys;
    bree::experimental::bree256_keys_init(&l_keys,l_key);
    unsigned char l_encrypted_out[128+32]; /// checksum field size 32 bytes
    unsigned char l_decrypted_out[128];
    std::cout << "Encrypting data:" << std::endl;
    HexDump(l_text,128);
    std::cout << std::endl;
    std::cout << "With key:" << std::endl;
    HexDump(l_key,32);
    std::cout << std::endl;
    std::cout << "End nonce: " << std::endl;
    HexDump(l_nonce,12);
    std::cout << std::endl;
    std::cout << "Encrypting.." << std::endl;
    bree::experimental::bree256_do_encrypt_message(l_text,128,&l_keys,l_nonce,l_encrypted_out);
    std::cout << "Encrypted data view: " << std::endl;
    HexDump(l_encrypted_out,128+32);
    std::cout << std::endl;
    std::cout << "modifying byte at position 80 from ";
    printf("hex value %02x to %02x", l_encrypted_out[80],0x77 );
    std::cout << std::endl;
    l_encrypted_out[80] = 0x77;
    std::cout << "Decrypting..." << std::endl;
    bool ret = bree::experimental::bree256_do_decrypt_message(l_encrypted_out,128+32,&l_keys,l_nonce,l_decrypted_out);
    std::cout << "Decrypted data view: " << std::endl;
    HexDump(l_decrypted_out,128);
    std::cout << std::endl;
    std::cout << std::endl;

    if(!ret)
    {
        if(0 == memcmp((char*) l_text, (char*) l_decrypted_out, 128))
        {
            std::cout << "MODIFICATION OF MESSAGE DETECTED, BUT DECRYPTED DATA ARE SAME AS ORIGINAL, TEST FAILED" << std::endl;
        }
        else
        {
            std::cout << "MODIFICATION OF MESSAGE DETECTED, TEST PASSED" << std::endl;
        }
    }
    else
    {
        std::cout << "MODIFICATION OF MESSAGE NOT DETECTED, TEST FAILED" << std::endl;
    }
    std::cout << "NEW TEST END" << std::endl;
    std::cout << std::endl;
}

void AE_message_test()
{
    std::cout << std::endl << "NEW TEST BEGIN" << std::endl << std::endl;
    std::cout << "in this test we will show AE message print " << std::endl;
    std::cout << "real size of cipher text will be 128+32  128= data size + 32=checksum size" << std::endl;
    unsigned char l_text[128];
    for(int u=0; u<128; u++)
    {
        l_text[u] = 'f';
    }
    bree::experimental::bree256_nonce l_nonce = {'1','2','3','4','5','6','7','8','9','0','1','2'};
    bree::experimental::bree256_key l_key = {'1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8','9','0','1','2'};
    bree::experimental::bree256_keys l_keys;
    bree::experimental::bree256_keys_init(&l_keys,l_key);
    unsigned char l_encrypted_out[128+32]; /// checksum field size 32 bytes
    unsigned char l_decrypted_out[128];
    std::cout << "Encrypting data:" << std::endl;
    HexDump(l_text,128);
    std::cout << std::endl;
    std::cout << "With key:" << std::endl;
    HexDump(l_key,32);
    std::cout << std::endl;
    std::cout << "End nonce: " << std::endl;
    HexDump(l_nonce,12);
    std::cout << std::endl;
    std::cout << "Encrypting.." << std::endl;
    bree::experimental::bree256_do_encrypt_message(l_text,128,&l_keys,l_nonce,l_encrypted_out);
    std::cout << "Encrypted data view: " << std::endl;
    HexDump(l_encrypted_out,128+32);
    std::cout << std::endl;
    std::cout << "Decrypting..." << std::endl;
    bool ret = bree::experimental::bree256_do_decrypt_message(l_encrypted_out,128+32,&l_keys,l_nonce,l_decrypted_out);
    std::cout << "Decrypted data view: " << std::endl;
    HexDump(l_decrypted_out,128);
    std::cout << std::endl;
    std::cout << std::endl;

    if(ret)
    {
        if(0 == memcmp((char*) l_text, (char*) l_decrypted_out, 128))
        {
            std::cout << "AE MESSAGE ENCRYPT/DECRYPT TEST, TEST PASSED" << std::endl;
        }
        else
        {
            std::cout << "AE MESSAGE ENCRYPT/DECRYPT TEST decrypted and plain text data does not match, TEST FAILED" << std::endl;
        }
    }
    else
    {
        std::cout << "AE MESSAGE ENCRYPT/DECRYPT TEST message modification detected, TEST FAILED" << std::endl;
    }
    std::cout << "NEW TEST END" << std::endl;
    std::cout << std::endl;
}
void traffic_test()
{
    std::cout << std::endl << "NEW TEST BEGIN" << std::endl << std::endl;
    unsigned char l_text[g_size_of_data];
    uint8_t i=0;
    for(int u=0; u<g_size_of_data; u++)
    {
        l_text[u] = i;
        i++;
    }
    unsigned char l_encrypted_out[g_size_of_data+32];
    unsigned char l_decrypted_out[g_size_of_data];
    bree::experimental::bree256_nonce l_nonce = {'1','2','3','4','5','6','7','8','9','0','1','2'};
    bree::experimental::bree256_key l_key = {'1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8','9','0','1','2'};
    const int l_operatons_count = 1024*103;
    bree::experimental::bree256_keys l_keys;
    bree::experimental::bree256_keys_init(&l_keys,l_key);
    double l_total_data_size =  ((double)(g_size_of_data*l_operatons_count) / (1024.0*1024.0));
    std::cout << "Traffic test 1 of AE(Authenticated Encryption) began with " << l_operatons_count << " operations and " << g_size_of_data  <<
              " bytes per operation to (encrypt or decrypt)" << std::endl<<
              "total data size to process per test method: " << l_total_data_size << " MB estimated time about few seconds" <<
              std::endl << std::endl;
    unsigned long l_count = measure<std::chrono::milliseconds>::begin(AE_test_encrypt,&l_keys,l_text,l_encrypted_out,l_nonce,l_operatons_count);
    std::cout << "Encryption test time: " <<
              l_count << " milliseconds, " << (l_total_data_size/ l_count)*1000.0 << " MB/per second on one cpu core" << std::endl;
    l_count = measure<std::chrono::milliseconds>::begin(AE_test_decrypt,&l_keys,l_encrypted_out,l_decrypted_out,l_nonce,l_operatons_count);
    std::cout << "Decryption test time: " <<
              l_count << " milliseconds, " << (l_total_data_size/ l_count)*1000.0 << " MB/per second on one cpu core" << std::endl;
    std::cout << "Traffic test 1 end" << std::endl << std::endl;

    std::cout << "Traffic test 2 of encryption without message integrity check began with " << l_operatons_count << " operations and " << g_size_of_data  << " bytes per operation to (encrypt or decrypt)" << std::endl <<
              "total data size to process per test method: " << l_total_data_size << " MB estimated time shorter then last test" <<
              std::endl << std::endl;
    l_count = measure<std::chrono::milliseconds>::begin(test_encrypt,l_keys.m_shared_key,l_text,l_encrypted_out,l_nonce,l_operatons_count);
    std::cout << "Encryption test time: " << l_count
              << " milliseconds, " << (l_total_data_size/ l_count)*1000.0 << " MB/per second on one cpu core" << std::endl;
    l_count = measure<std::chrono::milliseconds>::begin(test_decrypt,l_keys.m_shared_key,l_encrypted_out,l_decrypted_out,l_nonce,l_operatons_count);
    std::cout << "Decryption test time: " <<
              l_count << " milliseconds, " << (l_total_data_size/ l_count)*1000.0 << " MB/per second on one cpu core" << std::endl;
    std::cout << "Traffic test 2 end" << std::endl << std::endl;
    std::cout << "NEW TEST END" << std::endl;
    std::cout << std::endl;
}





void AE_test_encrypt(bree::experimental::bree256_keys*a_keys,const unsigned char*a_text,unsigned char*a_encrypted_out, bree::experimental::bree256_nonce a_nonce,int a_operatons_count)
{

    for(int i = 0; i<a_operatons_count; i++)
    {
        bree::experimental::bree256_do_encrypt_message(a_text,g_size_of_data,a_keys,a_nonce,a_encrypted_out);
    }
}

void AE_test_decrypt(bree::experimental::bree256_keys*a_keys,const unsigned char*a_encrypted_out,unsigned char*decrypted_out, bree::experimental::bree256_nonce a_nonce,int a_operatons_count)
{
    for(int i = 0; i<a_operatons_count; i++)
    {
        if(!bree::experimental::bree256_do_decrypt_message(a_encrypted_out,g_size_of_data+32,a_keys,a_nonce,decrypted_out))
        {
            std::cout << "fail do decrypt" << std::endl;
            break;
        }
    }
}

void test_encrypt(bree::experimental::bree256_key a_key,const unsigned char*a_text,unsigned char*a_encrypted_out, bree::experimental::bree256_nonce a_nonce,int a_operatons_count)
{
    for(int i = 0; i<a_operatons_count; i++)
    {
        bree::experimental::bree256_do_encrypt(a_text,g_size_of_data,a_key,a_nonce,a_encrypted_out);
    }
}
void test_decrypt(bree::experimental::bree256_key a_key,const  unsigned char*a_encrypted_out,unsigned char*decrypted_out, bree::experimental::bree256_nonce a_nonce,int a_operatons_count)
{
    for(int i = 0; i<a_operatons_count; i++)
    {
        bree::experimental::bree256_do_decrypt(a_encrypted_out,g_size_of_data,a_key,a_nonce,decrypted_out);
    }
}


void HexDump(const unsigned char* buf, size_t buf_len)
{
    for(size_t pos = 0; pos < buf_len; pos += 16)
    {
        printf("%.4zu: ", pos);

        for(size_t cur = pos; cur < pos + 16; ++cur)
        {
            if(cur < buf_len)
                printf("%02x ", buf[cur]);
            else
                printf("   ");
        }

        printf(" ");

        for(size_t cur = pos; cur < pos + 16; ++cur)
        {
            if(cur < buf_len)
            {
                if(isascii(buf[cur]) && isprint(buf[cur]))
                    printf("%c", buf[cur]);
                else
                    printf(".");
            }
        }

        printf("\n");
    }
}
void intro();

int main()
{
    intro();
     std::cout << "You probably want to scroll up and read details about algorithm first before you go any further. " << std::endl;
     std::cout << "Press key 'y' to start tests and see examples in practice, any other key to exit" << std::endl;
    char e;
    e =std::getchar();
    if(e != 'y'){
    return 0;
    }
    example_print_test();
    std::cout << "Next test is view of how it looks like when you modify one byte in cipher text" << std::endl;
    std::cout << "Press key 'y' to see" << std::endl;
    e =std::getchar();
    e =std::getchar();
    if(e != 'y'){
    return 0;
    }
    example_invalidating_print_test();
    std::cout << "Next test is to measure performance how fast MB per second can be processed" << std::endl;
    std::cout << "Press key 'y' to see" << std::endl;
    e =std::getchar();
    e =std::getchar();
    if(e != 'y'){
    return 0;
    }
    traffic_test();
    std::cout << "Next test is create encrypted message with message integrity mode" << std::endl;
    std::cout << "Press key 'y' to see" << std::endl;
    e =std::getchar();
    e =std::getchar();
    if(e != 'y'){
    return 0;
    }
    AE_message_test();
    std::cout << "Next test is to detect modification of message" << std::endl;
    std::cout << "Press key 'y' to see" << std::endl;
    e =std::getchar();
    e =std::getchar();
    if(e != 'y'){
    return 0;
    }
    detecting_message_modification_test();
    std::cout << "That is all" << std::endl;
    std::cout << "I tried to implement some kind of attack, but I have nothing effective so far, best what can came up is brute force" << std::endl;
    std::cout << "If you have time and would like to research this algorithm, I would like to have results eventually if possible" << std::endl;
    std::cout << "This project is licensed under MIT LICENSE." << std::endl;
    std::cout << "Thank you for reading and have a nice day.;)" << std::endl;
    std::cout << "Best regards," << std::endl;
    std::cout << "          zninja" << std::endl;
    return 0;
}
void intro()
{
    std::cout << "INTRO" << std::endl;
    std::cout << "Symmetric encryption algorithms has purpose to scramble data with the key and unscramble scrambled data with the same key." << std::endl;
    std::cout << "This algorithm supports symmetric encryption and has unusual (optional) message integrity mechanism" << std::endl;
    std::cout << "Most of algorithms does encryption from begin to end." << std::endl;
    std::cout << "Most protocols on the web keeps predictable protocol data at the begin of the message," << std::endl;
    std::cout << "So, most attacks like brute force will be focused on well knowing part of message to break in, like \"HTTP/\" or \"GET\", \"POST\" which are part of http protocol" << std::endl;
    std::cout << "This algorithm encrypts messages in reverse order, from end to begin, each byte of cipher data is dependent of previous ancestors(in range from 4 to 16) in decryption process in reverse order," << std::endl;
    std::cout << "so if you change a single bit of cipher data, you will not be able to decrypt rest of data to original plain text" << std::endl;
    std::cout << "Unusual message integrity mechanism is done by collecting last 32 and first 32 bytes of plain message(if message is less," << std::endl;
    std::cout << "then whole content is used) and hash that content with the shared key, resulting hash is checksum hash," <<std::endl;
    std::cout << "Then hashing the shared key and use hash result to encrypt content of message," << std::endl;
    std::cout << "then hashing hash of the hash of shared key H(H(shared key)) and use to encrypt checksum hash, checksum hash in appended to the end of message cipher text." << std::endl;
    std::cout << "Since modifying a single byte of cipher text will result as wrong decryption rest of the message(in reverse order)," << std::endl;
    std::cout << "it is more then enough to use message integrity scheme like this which saves hash computation compared to other schemes" << std::endl;
    std::cout << "which hashing whole message content and slowing down if message is large." << std::endl;
    std::cout << std::endl;
    std::cout << "  H = (hash function ), shared key=any key of 256 bits created by key exchange or distributed)," << std::endl;
    std::cout << std::endl;
    std::cout << "  /-----------------------------------------------------------------------\\" << std::endl;
    std::cout << "  |                             CHECKSUM                                  |"  << std::endl;
    std::cout << "  |  H(shared key | last 32 bytes of message | first 32 bytes of message) |"  <<std::endl;
    std::cout << "  |                                                                       |"  <<std::endl;
    std::cout << "  \\-----------------------------------------------------------------------/" <<std::endl;
    std::cout << "                                    /" <<std::endl;
    std::cout<<  "                                   /" <<std::endl;
    std::cout << "  hash key1 = H(shared key), hash key2=H(hash key1)"<< std::endl;
    std::cout << "     \\                               \\" << std::endl;
    std::cout << "      \\encrypted with hash key1       \\encrypted with hash key 2"<< std::endl;
    std::cout << "  /--------------------------------------------------------\\" << std::endl;
    std::cout << "  | encrypted message               | encrypted checksum   |" << std::endl;
    std::cout << "  | content..                       |  hash - 32 bytes     |" << std::endl;
    std::cout << "  \\--------------------------------------------------------/" << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;

    std::cout << "Message integrity check during the decryption is done by extracting checksum hash, decrypting it with"<< std::endl;
    std::cout << "hash of the hash of shared key H(H(shared key)) and use that as checksum hash, then decrypting rest of the message with hash of the shared key H(shared key)," << std::endl;
    std::cout << "Then extract first and last 32 bytes of message, hash them along with shared key and compare its result vs checksum hash. If hashes matches, then message is intact" << std::endl;

    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << "\tENCRYPTION ALGORITHM" << std::endl << std::endl;
    std::cout << "First we need to observe how does 1 byte (uint8_t) type in C/C++ work" << std::endl << std::endl;
    std::cout << "uint8_t l_byte = (uint8_t)0; l_byte -= 6;" << std::endl;
    std::cout << "std::cout  << unsigned(l_byte) << std::endl;" << std::endl;
    std::cout << "This will result 250, since range of byte is 0-255 or 256-6=250 or ((0-6)%256+256)%256 = 250" << std::endl << std::endl;
    std::cout << "l_byte += 10;std::cout  << unsigned(l_byte) << std::endl;" << std::endl;
    std::cout << "This will output 4 since 250+10=260-256=4 or (250+10)%256=4" << std::endl;
    std::cout << "So uint8_t is like a clock, hi is spinning in that range 0-255" << std::endl;
    std::cout << std::endl;
    std::cout << "By knowing that and having number 232, I am sure you can not be sure if I get that number by 1000 % 256 or 1256 % 256.. etc.." << std::endl;
    std::cout << std::endl << "ENCRYPTING" << std::endl << std::endl;
    std::cout << "Now let say we have an 256 bit key(32 bytes), 96 bit nonce(12 bytes) and plain text of 10 bytes with value 'a'" << std::endl;
    std::cout << "it look like this [97,97,97,97,97,97,97,97,97,97] in our clock range and will name variable as text." << std::endl;
    std::cout << "let say our key is filled with numbers of value 200 (32*200) are stored in our key" << std::endl;
    std::cout << "nonce will be filled with same values 200 (12*200)" << std::endl;
    std::cout << "at the start of encryption we will create new uint8_t variable called key_sum and put sum value of key (32*200)%256=0"<< std::endl;
    std::cout << "Now we will initialize nonce by adding value of each key value to it like nonce[0] += key[0] .. nonce[0]+=key[12].. etc.." << std::endl;
    std::cout << "We will end up with: " << std::endl << std::endl;
    std::cout << "nonce[0] = 32" << std::endl;
    std::cout << "nonce[1] = 32" << std::endl;
    std::cout << "nonce[2] = 32" << std::endl;
    std::cout << "nonce[3] = 32" << std::endl;
    std::cout << "nonce[4] = 32" << std::endl;
    std::cout << "nonce[5] = 32" << std::endl;
    std::cout << "nonce[6] = 32" << std::endl;
    std::cout << "nonce[7] = 32" << std::endl;
    std::cout << "nonce[8] = 88" << std::endl;
    std::cout << "nonce[9] = 88" << std::endl;
    std::cout << "nonce[10] = 88" << std::endl;
    std::cout << "nonce[11] = 88" << std::endl;
    std::cout << std::endl;
    /**
    a_out[i] = a_plainText[i]+(l_key_t+l_key[i%32]+l_nonce[i%12]);
        l_key[i%32]+=l_nonce[i%12]+a_out[i];
    */
    std::cout << "Also we will now create new uint8_t variable called nonce_sum and put sum value of nonce values =  (32*8+(88+88+88+88)) % 256 = 96"<< std::endl;
    std::cout << "This step of changing nonce value via key is done each 4 byte after the one which position gives result pos % 4 = 0" << std::endl;
    std::cout << "now we have set up all variables in place to start working with plain text encryption " << std::endl;
    std::cout << "we are starting from the end of plain text, so since we have 10 bytes(positions 0 ... 9), we are at position 9 (reverse begin position)" << std::endl << std::endl;
    std::cout << "scrambled_byte= text[pos] + key_sum+nonce_sum + key[pos%32] + nonce[pos%12]" << std::endl;
    std::cout << "225 = 97 + 0 + 96 + 200 + 88" << std::endl << std::endl;
    std::cout << "We have done with scrambling this byte, now we will include this byte in process of scrambling next successor of this byte by modifying key value at index key[pos%32](key[9]) by formula" << std::endl << std::endl;
    std::cout << "key[pos%32]+= scrambled_byte+nonce[11]+nonce_sum" << std::endl;
    std::cout << "key[7] = 200+225+88+96 = 97 by our clock (200+225+88+96)%256" << std::endl;
    std::cout << "So our scrambled message will look like 225 so far." << std::endl;
    std::cout << "Now we need to scramble next byte which is on position 8, this is a index where rule applies (pos % 4 == 0) so we do step from begin" <<std::endl;
    std::cout << "nonce[0] += key[0] .. nonce[0]+=key[12].. etc.. and end up with: " << std::endl << std::endl;
    std::cout << "nonce[0] = 120" << std::endl;
    std::cout << "nonce[1] = 120" << std::endl;
    std::cout << "nonce[2] = 120" << std::endl;
    std::cout << "nonce[3] = 120" << std::endl;
    std::cout << "nonce[4] = 120" << std::endl;
    std::cout << "nonce[5] = 120" << std::endl;
    std::cout << "nonce[6] = 120" << std::endl;
    std::cout << "nonce[7] = 120" << std::endl;
    std::cout << "nonce[8] = 232" << std::endl;
    std::cout << "nonce[9] = 129" << std::endl;
    std::cout << "nonce[10] = 232" << std::endl;
    std::cout << "nonce[11] = 232" << std::endl;
    std::cout << std::endl;
    std::cout << "So now we continue on next byte" << std::endl;
    std::cout << "scrambled_byte= text[pos(8)] + key_sum+nonce_sum + key[pos%32] + nonce[pos%12]" << std::endl;
    std::cout << "113 = 97 + 0 + 96 + 200 + 232" << std::endl;
    std::cout << "key[pos%32]+= scrambled_byte+nonce[11]+nonce_sum" << std::endl;
    std::cout << "key[8] = 200+113+232+96 = 129, and so on...eventually, our cipher text will look like:" << std::endl << std::endl;
    std::cout << "[177, 89, 89, 89, 89, 1, 1, 1, 113,225]" << std::endl<< std::endl;
    std::cout << "All rules apply for decryption process except: " << std::endl << std::endl;
    std::cout << "scrambled_byte= text[pos(8)] + key_sum+nonce_sum + key[pos%32] + nonce[pos%12]" << std::endl;
    std::cout << "key[pos%32]+= scrambled_byte+nonce[11]+nonce_sum" << std::endl << std::endl;
    std::cout << "BECOMES" << std::endl << std::endl;
    std::cout << "plain_byte= scrambled_text[pos] -( key_sum+nonce_sum + key[pos%32] + nonce[pos%12])" << std::endl;
    std::cout << "key[9]+= scrambled_text[pos]+nonce[11]+nonce_sum" << std::endl;
    std::cout << "Translate:  97=225-(0 + 96 + 200 + 88) or by our clock (225-(0 + 96 + 200 + 88))+256" << std::endl;
    std::cout << "if scrambled_text[pos] -( key_sum+nonce_sum + key[pos%32] + nonce[pos%12])+256 is still negative number," << std::endl;
    std::cout << "we keep adding 256 until we have a positive value but that will computer automatically do for us in our code" << std::endl;
    std::cout << "key[9]= 200+225+88+96 = 97 by our clock (% 256)" << std::endl;
    std::cout << "that is all about this algorithm, you can see samples in practice" << std::endl << std::endl;
}
