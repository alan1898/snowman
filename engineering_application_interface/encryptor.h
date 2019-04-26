//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_ENCRYPTOR_H
#define ABELIB_ENCRYPTOR_H

#include "../basis.h"
#include "../schemes/schemes.h"
#include "../message_serialization/message_serialization.h"

class encryptor {
private:
    CLASSIC_ABE *classic_abe;
public:
    encryptor(string scheme);

    CLASSIC_ABE* getClassicAbe();

    unsigned char* getUserKey(string user_key_name);

    element_s *getM(string user_key_name);

    format_string_bytes* encrypt(format_string_bytes *format_file_bytes, unsigned char *user_key);
    string encrypt(string file_str, string user_key_name, string policy, string public_key_json_str);
};


#endif //ABELIB_ENCRYPTOR_H
