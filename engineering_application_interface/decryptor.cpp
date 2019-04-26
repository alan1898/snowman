//
// Created by alan on 19-4-26.
//

#include "decryptor.h"

decryptor::decryptor(string scheme) {
    if (scheme == "RW13") {
        classic_abe = new RW13();
    } else if (scheme == "BSW07") {
        classic_abe = new BSW07();
    }
}

CLASSIC_ABE* decryptor::getClassicAbe() {
    return classic_abe;
}

unsigned char* decryptor::getUserKey(element_s *m) {
    // step 1
    int n = element_length_in_bytes(m);
    unsigned char *m_bytes = (unsigned char*)malloc(n);
    element_to_bytes(m_bytes, m);

    // step 2
    unsigned char *user_key = (unsigned char*)malloc(SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256_;
    SHA256_Init(&sha256_);
    SHA256_Update(&sha256_, m_bytes, n);
    SHA256_Final(user_key, &sha256_);

    // return
    return user_key;
}

format_string_bytes* decryptor::decrypt(format_string_bytes *format_encrypt_file_bytes, unsigned char *user_key) {
    // set decrypt_key
    AES_KEY decrypt_key;
    AES_set_decrypt_key(user_key, 256, &decrypt_key);

    // get encrypt_file_bytes
    unsigned char *encrypt_file_bytes = format_encrypt_file_bytes->getBytes();

    // decrypt encrypt_file_bytes
    unsigned char file_bytes[format_encrypt_file_bytes->getN()];
    int len = 0;
    while (len < format_encrypt_file_bytes->getN()) {
        AES_decrypt(encrypt_file_bytes + len, file_bytes + len, &decrypt_key);
        len += AES_BLOCK_SIZE;
    }

    // get format_file_bytes
    format_string_bytes *format_file_bytes = new format_string_bytes(file_bytes, format_encrypt_file_bytes->getN());

    return format_file_bytes;
}

string decryptor::decrypt(string share_json_str, string secret_key_json_str, string attributes_json_str) {
    // get c_share
    cJSON *c_share = cJSON_Parse(share_json_str.c_str());

    message_serialization ms;

    // get ciphertext
    cJSON *c_ciphertext = cJSON_GetObjectItem(c_share, "key_ciphertext");
    Ciphertext *ciphertext = ms.CJSONToCiphertext(c_ciphertext, classic_abe->getPairing());

    // get secret_key
    cJSON *c_secret_key = cJSON_Parse(secret_key_json_str.c_str());
    Key *secret_key = ms.CJSONToKey(c_secret_key, classic_abe->getPairing());

    // get attributes
    cJSON *c_attributes = cJSON_Parse(attributes_json_str.c_str());
    vector<string> *attributes = ms.CJSONToVectorString(c_attributes);

    // get m
    element_s *m = classic_abe->decrypt(ciphertext, secret_key, attributes);
    if (m == NULL) {
        return "";
    }

    // get user_key
    unsigned char *user_key = getUserKey(m);

    // get format_encrypt_file_bytes
    cJSON *c_format_encrypt_file_bytes = cJSON_GetObjectItem(c_share, "content");
    format_string_bytes *format_encrypt_file_bytes = ms.CJSONToFormatStringBytes(c_format_encrypt_file_bytes);
    format_string_bytes *format_file_bytes = decrypt(format_encrypt_file_bytes, user_key);

    cJSON *c_format_file_bytes = ms.formatStringBytesToCJSON(format_file_bytes);

    string res(cJSON_Print(c_format_file_bytes));

    return res;
}

string decryptor::getPlaintextFromDecryptionResult(string decryption_result) {
    message_serialization ms;

    cJSON *c_plaintext = cJSON_Parse(decryption_result.c_str());

    format_string_bytes *format_plaintext_bytes = ms.CJSONToFormatStringBytes(c_plaintext);

    string plaintext((char*)format_plaintext_bytes->getBytes(), format_plaintext_bytes->getN());

    return plaintext;
}