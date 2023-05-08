#pragma once

#include <string.h>
#include <chrono>
#include <string>
#include <sstream>
#include <ctime>
#include <map>
#include <set>
#include <unordered_map>
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <memory>

#include <uuid.h>
#include <curl/curl.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "third_party/date.h"
#include "third_party/stduuid/include/uuid.h"

#define KEY_LENGTH       2048
#define PUBLIC_KEY_PEM   1
#define PRIVATE_KEY_PEM  0

namespace stelgic
{
class AuthUtils
{
public:
    static inline std::string EncodeUTF8(const std::string& data)
    {
        auto deleter = [](CURL* p) { curl_free(p); };
        std::unique_ptr<CURL, decltype(deleter)> curlPtr(curl_easy_init(), deleter);
        std::unique_ptr<char> output;
        output.reset(curl_easy_escape(curlPtr.get(), data.c_str(), data.length()));
        if(output == nullptr)
            return "";
        return std::string(output.get());
    }

    static inline std::string DecodeUTF8(const std::string &data)
    {
        auto deleter = [](CURL* p) { curl_free(p); };
        std::unique_ptr<CURL, decltype(deleter)> curlPtr(curl_easy_init(), deleter);
        std::unique_ptr<char> output;

        int outlength;
        output.reset(curl_easy_unescape(curlPtr.get(), data.c_str(), data.length(), &outlength));
        std::string res(output.get(), output.get() + outlength);
        if(output == nullptr)
            return "";
        return std::string(output.get());
    }

    static inline std::string GetSignature(std::string key, std::string msg)
    {
        unsigned char hash[32];

        HMAC_CTX* hmac = HMAC_CTX_new();
        HMAC_CTX_reset(hmac);
        HMAC_Init_ex(hmac, &key[0], key.length(), EVP_sha256(), NULL);
        HMAC_Update(hmac, (unsigned char*)&msg[0], msg.length());
        unsigned int len = 32;
        HMAC_Final(hmac, hash, &len);
        HMAC_CTX_free(hmac);

        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < len; i++)
        {   
            ss << std::hex << std::setw(2)  << (unsigned int)hash[i];
        }

        return ss.str();
    }

    static inline std::string GetSignature2(std::string key, std::string msg)
    {
        unsigned char* output = (unsigned char*)malloc(EVP_MAX_MD_SIZE);

        HMAC_CTX* hmac = HMAC_CTX_new();
        HMAC_CTX_reset(hmac);
        HMAC_Init_ex(hmac, &key[0], key.length(), EVP_sha256(), NULL);
        HMAC_Update(hmac, (unsigned char*)&msg[0], msg.length());

        unsigned int len = 0;
        HMAC_Final(hmac, output, &len);
        HMAC_CTX_free(hmac);

        std::string result = base64_encode(output, len);
        
        free(output);
        return result;
    }

    static inline RSA* GenerateKeyPair()
    {
        BIGNUM *bn;
        bn = BN_new();
        BN_set_word(bn, RSA_3);
        RSA *keypair = NULL;
        keypair = RSA_new();

        RSA_generate_key_ex(
            keypair,  /* pointer to the RSA structure */
            KEY_LENGTH, /* number of bits for the key - 2048 is a good value */
            bn,   /* exponent allocated earlier */
            NULL /* callback - can be NULL if progress isn't needed */
        );

        //RSA *keypair = RSA_generate_key(KEY_LENGTH, PUBLIC_EXPONENT, NULL, NULL);
        BN_free(bn);
        return keypair;
    }

    static inline void CreateRSA(RSA* keypair, int pem_type, const std::string& file_name) 
    {
        BIO	*bp = NULL;
        
        if(pem_type == PUBLIC_KEY_PEM) 
        {
            bp = BIO_new_file(file_name.c_str(), "w+");
            int ret = PEM_write_bio_RSAPublicKey(bp, keypair);
            if(ret != 1){
                goto free_all;
            }
        }
        else if(pem_type == PRIVATE_KEY_PEM) 
        {
            bp = BIO_new_file(file_name.c_str(), "w+");
            int ret = PEM_write_bio_RSAPrivateKey(bp, keypair, NULL, NULL, 0, NULL, NULL);
            if(ret != 1){
                goto free_all;
            }
        }

        free_all:
            BIO_free_all(bp);
    }

    static inline void CreateKeys(RSA* keypair, 
        const std::string& priv_filename, 
        const std::string& pub_filename) 
    {
        CreateRSA(keypair, PRIVATE_KEY_PEM, priv_filename.c_str());
        CreateRSA(keypair, PUBLIC_KEY_PEM, pub_filename.c_str());
    }


    static inline RSA* ReadRSA(int pem_type, const std::string& file_name)
    {
        bool success = false;
        RSA *rsa = RSA_new();
        BIO	*bp = NULL;

        if(pem_type == PUBLIC_KEY_PEM) 
        {
            bp = BIO_new_file(file_name.c_str(), "rb");
            rsa = PEM_read_bio_RSAPublicKey(bp, &rsa, NULL, NULL);
            if(!rsa){
                goto free_all;
            }
        }
        else if(pem_type == PRIVATE_KEY_PEM) 
        {
            bp = BIO_new_file(file_name.c_str(), "rb");
            rsa = PEM_read_bio_RSAPrivateKey(bp, &rsa, NULL, NULL);
            if(!rsa){
                goto free_all;
            }
        }

        free_all:
            BIO_free_all(bp);
        
        return rsa;
    }

    static inline RSA* ReadRSA(int pem_type, const char* bytes)
    {
        bool success = false;
        RSA *rsa = RSA_new();
        BIO	*bp = NULL;

        if(pem_type == PUBLIC_KEY_PEM) 
        {
            bp = BIO_new_mem_buf(bytes, strlen(bytes)+1);
            rsa = PEM_read_bio_RSAPublicKey(bp, &rsa, NULL, NULL);
            if(!rsa){
                goto free_all;
            }
        }
        else if(pem_type == PRIVATE_KEY_PEM) 
        {
            bp = BIO_new_mem_buf(bytes, strlen(bytes)+1);
            rsa = PEM_read_bio_RSAPrivateKey(bp, &rsa, NULL, NULL);
            if(!rsa){
                goto free_all;
            }
        }

        free_all:
            BIO_free_all(bp);
        
        return rsa;
    }


    static inline int PublicRsaEncrypt(RSA* public_key, const std::string& msg, std::string& out)
    {
        if(msg.length() == 0)
            return 0;

        int size = RSA_size(public_key);
        int blockSize = size - 42;

        std::string sub_str;
        char* encrypted = new char[size+1];
        memset(encrypted, 0, size+1);

        int length = 0;
        int totalSize = 0;
        int pos = 0;
        int steps = msg.length() / blockSize + 1;

        for(int i=0; i < steps; i++)
        {
            pos = i * blockSize;
            int num_chars = blockSize;
            num_chars = (msg.length() - pos) < blockSize ? (msg.length() - pos) : num_chars;

            if(pos >= msg.length())
                break;

            sub_str = msg.substr(pos, num_chars);
            memset(encrypted, 0, size+1);

            length = RSA_public_encrypt(num_chars, 
                                            (unsigned char*)sub_str.c_str(), 
                                            (unsigned char*)encrypted, 
                                            public_key, 
                                            RSA_PKCS1_OAEP_PADDING);
            if(length >= 0)
            {
                totalSize += length;
                out.append(std::string(encrypted, length));
            }
            else if(length == -1)
            {
                long error = ERR_get_error();
                const char* error_string = ERR_error_string(error, NULL);
                std::cout << error_string << std::endl;
                totalSize = -1;
                break;
            }
        }

        if (encrypted != NULL)
        {
            delete [] encrypted;
            encrypted = NULL;
        }

        return totalSize;
    }

    static inline int PublicRsaDecrypt(RSA* public_key, const std::string& msg, std::string& out)
    {
        if(msg.length() == 0)
            return 0;
        
        const int size = RSA_size(public_key);
        int msize = size + 1;
        char* decrypted = new char[msize];
        std::string sub_str;

        int length = 0;
        int totalSize = 0;
        int pos = 0;
        int steps = msg.length() / size + 1;

        for(int i=0; i < steps; i++)
        {
            pos = i * size;
            int num_chars = size;
            num_chars = (msg.length() - pos) < size ? (msg.length() - pos): num_chars;

            if(pos >= msg.length())
                break;

            sub_str = msg.substr(pos, num_chars);
            memset(decrypted, 0, msize);

            int length = RSA_public_decrypt(num_chars, 
                                        (unsigned char*)sub_str.c_str(), 
                                        (unsigned char*)decrypted, 
                                        public_key, 
                                        RSA_PKCS1_PADDING);
            if(length >= 0)
            {
                totalSize += length;
                out.append(std::string(decrypted, length));
            }
            else if(length == -1)
            {
                long error = ERR_get_error();
                const char* error_string = ERR_error_string(error, NULL);
                std::cout << error_string << std::endl;
                totalSize = -1;
                break;
            }
        }

        if (decrypted != NULL)
        {
            delete[] decrypted;
            decrypted = NULL;
        }

        return totalSize;
    }


    static inline int PrivateRsaEncrypt(RSA* private_key, const std::string& msg, std::string& out)
    {
        if(msg.length() == 0)
            return 0;

        int size = RSA_size(private_key);
        int blockSize = size - 42;

        std::string sub_str;
        int msize = size + 1;
        char* encrypted = new char[msize];
        memset(encrypted, 0, msize);

        int length = 0;
        int totalSize = 0;
        int pos = 0;
        int steps = msg.length() / blockSize + 1;

        for(int i=0; i < steps; i++)
        {
            pos = i * blockSize;
            int num_chars = blockSize;
            num_chars = (msg.length() - pos) < blockSize ? (msg.length() - pos) : num_chars;

            if(pos >= msg.length())
                break;

            sub_str = msg.substr(pos, num_chars);
            memset(encrypted, 0, msize);

            length = RSA_private_encrypt(num_chars, 
                                            (unsigned char*)sub_str.c_str(), 
                                            (unsigned char*)encrypted, 
                                            private_key, 
                                            RSA_PKCS1_PADDING);
            if(length >= 0)
            {
                totalSize += length;
                out.append(std::string(encrypted, length));
            }
            else if(length == -1)
            {
                long error = ERR_get_error();
                const char* error_string = ERR_error_string(error, NULL);
                std::cout << error_string << std::endl;
                totalSize = -1;
                break;
            }
        }

        if (encrypted != NULL)
        {
            delete[] encrypted;
            encrypted = NULL;
        }

        return totalSize;
    }

    static inline int PrivateRsaDecrypt(RSA* private_key, const std::string& msg, std::string& out)
    {
        if(msg.length() == 0)
        {
            std::cout << "Empty message\n";
            return 0;
        }
        
        int size = RSA_size(private_key);
        int msize = size + 1;
        char* decrypted = new char[msize];
        std::string sub_str;

        int length = 0;
        int totalSize = 0;
        int pos = 0;
        int steps = msg.length() / size + 1;

        for(int i=0; i < steps; i++)
        {
            pos = i * size;
            int num_chars = size;
            num_chars = (msg.length() - pos) < size ? (msg.length() - pos): num_chars;

            if(pos >= msg.length())
                break;

            sub_str = msg.substr(pos, num_chars);
            memset(decrypted, 0, msize);

            int length = RSA_private_decrypt(num_chars, 
                                        (unsigned char*)sub_str.c_str(), 
                                        (unsigned char*)decrypted, 
                                        private_key, 
                                        RSA_PKCS1_OAEP_PADDING);
            if(length >= 0)
            {
                totalSize += length;
                out.append(std::string(decrypted, length));
            }
            else if(length == -1)
            {
                long error = ERR_get_error();
                const char* error_string = ERR_error_string(error, NULL);
                std::cout << error_string << std::endl;
                totalSize = -1;
                break;
            }
        }

        if (decrypted != NULL)
        {
            delete[] decrypted;
            decrypted = NULL;
        }

        return totalSize;
    }

    static inline bool EncryptDataToFile(const std::string& pubfile, 
        const std::string& msg, const std::string& outfile)
    {
        char* encoded;
        bool success = false;
        RSA* public_key = ReadRSA(PUBLIC_KEY_PEM, pubfile);
        if(public_key)
        {
            std::string encrypted;
            std::string decrypted(msg);
            decrypted.erase(std::remove(decrypted.begin(), decrypted.end(), '\t'), decrypted.end());
            decrypted.erase(std::remove(decrypted.begin(), decrypted.end(), '\n'), decrypted.end());

            PublicRsaEncrypt(public_key, decrypted, encrypted);
            
            std::ofstream stream(outfile);
            if(stream.is_open())
            {
                size_t outlen;
                if(!Base64Encode((const unsigned char*)encrypted.c_str(), encrypted.length(), &encoded, outlen))
                {
                    std::cout << "Base64Encode failed!\n";
                    success = false;
                    goto free_all;
                }

                std::string output(encoded, outlen);

                stream << output;
                stream.close();
                success = true;
            }
        }

        free_all:
            if(public_key)
                RSA_free(public_key);
            if(encoded)
                free(encoded);

        return success;
    }

    static inline bool DecryptDataFromFile(const std::string& filename, 
        const std::string& outfile, std::string& outdecrypted)
    {
        bool success = false;
        size_t length;
        unsigned char* buffer;
        //RSA* private_key = Utils::ReadRSA(PRIVATE_KEY_PEM, filename);
        RSA* public_key = ReadRSA(PUBLIC_KEY_PEM, filename);
        if(public_key)
        {
            std::stringstream ssencoded;
                    
            std::ifstream stream(outfile);
            if(stream.is_open())
            {
                ssencoded << stream.rdbuf();
                stream.close();

                std::string encoded(ssencoded.str());
                encoded.erase(std::remove(encoded.begin(), encoded.end(), '\n'), encoded.end());

                if(!Base64Decode(encoded, &buffer, &length))
                {
                    std::cout << "Base64Decode failed!\n";
                    success = false;
                    goto free_all;
                }
                
                std::string decrypted;
                std::string encrypted((char*)buffer, length);
                if(PublicRsaDecrypt(public_key, encrypted, decrypted) < 0)
                {
                    std::cout << "Private decrypt failed!\n";
                    success = false;
                    goto free_all;
                }
                outdecrypted = decrypted;
                //std::cout << "DECRYPTED: " << outdecrypted << std::endl;
                success = true;
            }
            else
                std::cout << "Failed to open " << outfile << std::endl;
        }
        else
            std::cout << "Failed to read private key " << filename << std::endl;

        free_all:
            if(public_key)
                RSA_free(public_key);
            if(buffer)
                free(buffer);

        return success;
    }

    static inline bool DecryptDataFromFile(
        const char* bytes, const std::string& outfile, std::string& outdecrypted)
    {
        bool success = false;
        size_t length;
        unsigned char* buffer;
        //RSA* private_key = Utils::ReadRSA(PRIVATE_KEY_PEM, filename);
        RSA* public_key = ReadRSA(PUBLIC_KEY_PEM, bytes);
        if(public_key)
        {
            std::stringstream ssencoded;
                    
            std::ifstream stream(outfile);
            if(stream.is_open())
            {
                ssencoded << stream.rdbuf();
                stream.close();

                std::string encoded(ssencoded.str());
                encoded.erase(std::remove(encoded.begin(), encoded.end(), '\n'), encoded.end());

                if(!Base64Decode(encoded, &buffer, &length))
                {
                    std::cout << "Base64Decode failed!\n";
                    success = false;
                    goto free_all;
                }
                
                std::string decrypted;
                std::string encrypted((char*)buffer, length);
                if(PublicRsaDecrypt(public_key, encrypted, decrypted) < 0)
                {
                    std::cout << "Private decrypt failed!\n";
                    success = false;
                    goto free_all;
                }
                outdecrypted = decrypted;
                //std::cout << "DECRYPTED: " << outdecrypted << std::endl;
                success = true;
            }
            else
                std::cout << "Failed to open " << outfile << std::endl;
        }

        free_all:
            if(public_key)
                RSA_free(public_key);
            if(buffer)
                free(buffer);

        return success;
    }

    static inline bool RSASign(RSA* rsa, const unsigned char* Msg, 
        size_t MsgLen, unsigned char** EncMsg, size_t* MsgLenEnc) 
    {
        EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
        EVP_PKEY* priKey  = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(priKey, rsa);
        if (EVP_DigestSignInit(m_RSASignCtx,NULL, EVP_sha256(), NULL,priKey)<=0) {
            return false;
        }
        if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {
            return false;
        }
        if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <=0) {
            return false;
        }
        *EncMsg = (unsigned char*)malloc(*MsgLenEnc);
        if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) {
            return false;
        }
        EVP_MD_CTX_free(m_RSASignCtx);
        
        return true;
    }


    static inline std::string signMessage(RSA* private_key, std::string plainText) 
    {
        size_t olen;
        unsigned char* encMessage;
        char* base64Text;
        size_t encMessageLength;
        RSASign(private_key, (unsigned char*) plainText.c_str(), plainText.length(), &encMessage, &encMessageLength);
        Base64Encode(encMessage, encMessageLength, &base64Text, olen);
        
        std::string signedMsg(base64Text, olen);

        free(encMessage);
        free(base64Text);
        return signedMsg;
    }

    static inline bool Base64Encode(const unsigned char* buffer, size_t length, char** base64Text, size_t& olen) 
    { 
        BIO *bio, *b64;
        BUF_MEM *bufferPtr;
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
        int n = BIO_write(bio, buffer, length);
        
        BIO_get_mem_ptr(bio, &bufferPtr);
        BIO_set_close(bio, BIO_NOCLOSE);

        BIO_flush(bio);
        BIO_free_all(bio);
        *base64Text=(*bufferPtr).data;
        olen = (*bufferPtr).length;

        if(n > 0)
            return true;
        return false;
    }

    static inline size_t calcDecodeLength(const char* b64input) 
    {
        size_t len = strlen(b64input), padding = 0;
        if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
            padding = 2;
        else if (b64input[len-1] == '=') //last char is =
            padding = 1;
        return (len*3)/4 - padding;
    }


    static inline bool Base64Decode(const std::string& b64message, unsigned char** buffer, size_t* length) 
    {
        BIO *bio, *b64;
        int decodeLen = calcDecodeLength(b64message.c_str());
        *buffer = (unsigned char*)malloc(decodeLen + 1);
        (*buffer)[decodeLen] = '\0';
        bio = BIO_new_mem_buf(b64message.c_str(), -1);
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

        *length = BIO_read(bio, *buffer, b64message.length());
        BIO_free_all(bio);

        if(*length != decodeLen)
            return false;
        return true;
    }


    static inline bool RSAVerifySignature(
        RSA* rsa, unsigned char* MsgHash, size_t MsgHashLen, 
        const char* Msg, size_t MsgLen, bool* Authentic) 
    {
        *Authentic = false;
        EVP_PKEY* pubKey  = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(pubKey, rsa);
        EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();
        if (EVP_DigestVerifyInit(m_RSAVerifyCtx,NULL, EVP_sha256(),NULL,pubKey)<=0)
        {
            return false;
        }
        if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0)
        {
            return false;
        }
        int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
        if (AuthStatus==1) {
            *Authentic = true;
            EVP_MD_CTX_free(m_RSAVerifyCtx);
            return true;
        } 
        else if(AuthStatus==0)
        {
            *Authentic = false;
            EVP_MD_CTX_free(m_RSAVerifyCtx);
            return true;
        } 
        else
        {
            *Authentic = false;
            EVP_MD_CTX_free(m_RSAVerifyCtx);
            return false;
        }
    }

    static inline bool verifySignature(RSA* public_key, std::string plainText, char* signatureBase64) 
    {
        unsigned char* encMessage;
        size_t encMessageLength;
        bool authentic;
        Base64Decode(std::string(signatureBase64), &encMessage, &encMessageLength);
        bool result = RSAVerifySignature(public_key, encMessage, encMessageLength, 
                                        plainText.c_str(), plainText.length(), &authentic);
        return result & authentic;
    }

    static inline std::string GetRandomUUID()
    {
        std::random_device rd;
        auto seed_data = std::array<int, std::mt19937::state_size> {};
        std::generate(std::begin(seed_data), std::end(seed_data), std::ref(rd));
        std::seed_seq seq(std::begin(seed_data), std::end(seed_data));
        std::mt19937 generator(seq);
        uuids::uuid_random_generator gen{ generator };

        uuids::uuid const id = gen();
        assert(!id.is_nil());
        assert(id.as_bytes().size() == 16);

        return uuids::to_string(id);
    }

    static inline std::string GetUrandom(int count)
    {
        std::string urandom;
        std::ifstream istream("/dev/urandom", std::ios::in|std::ios::binary); //Open stream
        if(istream.is_open()) //Check if stream is open
        {
            size_t size = 2048;
            char* memblock = new char[size];

            do
            {
                memset(memblock, '\0', size);
                istream.read(reinterpret_cast<char*>(memblock), size);
                std::string temp(memblock);

                temp.erase(remove_if(temp.begin(), temp.end(), 
                        [](char c) { return !isalnum(c) || isupper(c); } ), temp.end());
                urandom.append(temp);
            }
            while(urandom.length() < 8);

            if (memblock != NULL)
            {
                delete[] memblock;
                memblock = NULL;
            }

            urandom = urandom.substr(0,count);
            istream.close();
        }
        else
            std::cout << "Failed to read /dev/urandom\n";
        return urandom;
    }

    static inline std::string const base64_chars =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789+/";

    static inline std::string base64_encode(unsigned char const * input, size_t len) 
    {
        std::string ret;
        int i = 0;
        int j = 0;
        unsigned char char_array_3[3];
        unsigned char char_array_4[4];

        while (len--) {
            char_array_3[i++] = *(input++);
            if (i == 3) {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) +
                                    ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) +
                                    ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;

                for(i = 0; (i <4) ; i++) {
                    ret += base64_chars[char_array_4[i]];
                }
                i = 0;
            }
        }

        if (i) {
            for(j = i; j < 3; j++) {
                char_array_3[j] = '\0';
            }

            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) +
                                ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) +
                                ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (j = 0; (j < i + 1); j++) {
                ret += base64_chars[char_array_4[j]];
            }

            while((i++ < 3)) {
                ret += '=';
            }
        }

        return ret;
    }

    static inline  std::string base64_encode(std::string const & input) 
    {
        return base64_encode(
                reinterpret_cast<const unsigned char *>(input.data()),
                input.size()
        );
    }

    static inline std::string getISOTimestamp()
    {
        auto now = std::chrono::system_clock::now();
        return date::format("%FT%TZ", date::floor<std::chrono::milliseconds>(now));
    }
};
}
