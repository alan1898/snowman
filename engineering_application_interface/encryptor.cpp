//
// Created by alan on 19-4-26.
//

#include "encryptor.h"

encryptor::encryptor(string scheme) {
    if (scheme == "RW13") {
        classic_abe = new RW13();
    } else if (scheme == "BSW07") {
        classic_abe = new BSW07();
    }
}

CLASSIC_ABE* encryptor::getClassicAbe() {
    return classic_abe;
}

unsigned char* encryptor::getUserKey(string user_key_name) {
    // step 1
    unsigned char user_key_name_hash_str_bytes[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, user_key_name.c_str(), user_key_name.size());
    SHA256_Final(user_key_name_hash_str_bytes, &sha256);

    // step 2
    pairing_t pairing;
    pbc_param_t par;
    curve_param cp;
    pbc_param_init_set_str(par, cp.a_param.c_str());
    pairing_init_pbc_param(pairing, par);
    element_t m;
    element_init_GT(m, pairing);
    element_from_hash(m, user_key_name_hash_str_bytes, SHA256_DIGEST_LENGTH);

    // step 3
    int n = element_length_in_bytes(m);
    unsigned char *m_bytes = (unsigned char*)malloc(n);
    element_to_bytes(m_bytes, m);

    // step 4
    unsigned char *user_key = (unsigned char*)malloc(SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256_;
    SHA256_Init(&sha256_);
    SHA256_Update(&sha256_, m_bytes, n);
    SHA256_Final(user_key, &sha256_);

    // return
    return user_key;
}

element_s* encryptor::getM(string user_key_name) {
    // step 1
    unsigned char user_key_name_hash_str_bytes[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, user_key_name.c_str(), user_key_name.size());
    SHA256_Final(user_key_name_hash_str_bytes, &sha256);

    // step 2
    pairing_t pairing;
    pbc_param_t par;
    curve_param cp;
    pbc_param_init_set_str(par, cp.a_param.c_str());
    pairing_init_pbc_param(pairing, par);
    element_t *m = new element_t[1];
    element_init_GT(*m, pairing);
    element_from_hash(*m, user_key_name_hash_str_bytes, SHA256_DIGEST_LENGTH);

    // return
    return *m;
}

format_string_bytes* encryptor::encrypt(format_string_bytes *format_file_bytes, unsigned char *user_key) {
    // set encrypt_key
    AES_KEY encrypt_key;
    AES_set_encrypt_key(user_key, 256, &encrypt_key);

    // get file_bytes
    unsigned char *file_bytes = format_file_bytes->getBytes();

    // encrypt file_bytes
    unsigned char encrypt_file_bytes[format_file_bytes->getN()];
    int len = 0;
    while (len < format_file_bytes->getN()) {
        AES_encrypt(file_bytes + len, encrypt_file_bytes + len, &encrypt_key);
        len += AES_BLOCK_SIZE;
    }

    // get format_encrypt_file_bytes
    format_string_bytes *format_encrypt_file_bytes = new format_string_bytes(encrypt_file_bytes, format_file_bytes->getN());

    return format_encrypt_file_bytes;
}

string encryptor::encrypt(string file_str, string user_key_name, string policy, string public_key_json_str) {
    // get user_key
    unsigned char *user_key = getUserKey(user_key_name);

    // get format_file_bytes
    format_string_bytes *format_file_bytes = new format_string_bytes(file_str);

    // get format_encrypt_file_bytes
    format_string_bytes *format_encrypt_file_bytes = encrypt(format_file_bytes, user_key);

    // get m
    element_s *m = getM(user_key_name);

    // get public_key
    message_serialization ms;
    cJSON *c_public_key = cJSON_Parse(public_key_json_str.c_str());
    Key *public_key = ms.CJSONToKey(c_public_key, classic_abe->getPairing());

    // compute cipertext
    Ciphertext *ciphertext = classic_abe->encrypt(m, policy, public_key);

    cJSON *c_format_encrypt_file_bytes = ms.formatStringBytesToCJSON(format_encrypt_file_bytes);
    cJSON *c_ciphertext = ms.CiphertextToCJSON(ciphertext);

    cJSON *c_res = cJSON_CreateObject();
    cJSON_AddItemToObject(c_res, "content", c_format_encrypt_file_bytes);
    cJSON_AddItemToObject(c_res, "key_ciphertext", c_ciphertext);

    string res(cJSON_Print(c_res));

    return res;
}