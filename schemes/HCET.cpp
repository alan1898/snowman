//
// Created by alan on 19-8-26.
//

#include "HCET.h"

element_s* HCET::H1(element_s *e) {
    element_t *res = new element_t[1];
    element_init_Zr(*res, pairing);

    signed long int n = element_length_in_bytes(e);
    unsigned char *bytes = (unsigned char*)malloc(n);
    element_to_bytes(bytes, e);

    unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, bytes, n);
    SHA256_Final(hash_str_byte, &sha256);
    element_from_hash(*res, hash_str_byte, SHA256_DIGEST_LENGTH);

    return *res;
}

unsigned char* HCET::H2(element_s *e) {
    element_t *res = new element_t[1];
    element_init_G1(*res, pairing);

    signed long int n = element_length_in_bytes(e);
    unsigned char *bytes = (unsigned char*)malloc(n);
    element_to_bytes(bytes, e);

    unsigned char *hash_str_byte = (unsigned char*)malloc(SHA256_DIGEST_LENGTH + 8 + 1);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, bytes, n);
    SHA256_Final(hash_str_byte, &sha256);
    for (signed long int i = 0; i < 8; ++i) {
        hash_str_byte[SHA256_DIGEST_LENGTH + i] = '0';
    }
    hash_str_byte[SHA256_DIGEST_LENGTH + 8] = '\0';

    return hash_str_byte;
}