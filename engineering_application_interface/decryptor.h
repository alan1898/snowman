//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_DECRYPTOR_H
#define ABELIB_DECRYPTOR_H

#include "../basis.h"
#include "../schemes/schemes.h"
#include "../message_serialization/message_serialization.h"

class decryptor {
private:
    CLASSIC_ABE *classic_abe;
public:
    decryptor(string scheme);

    CLASSIC_ABE* getClassicAbe();

    unsigned char* getUserKey(element_s *m);

    format_string_bytes* decrypt(format_string_bytes *format_encrypt_file_bytes, unsigned char *user_key);

    string decrypt(string share_json_str, string secret_key_json_str, string attributes_json_str);

    string getPlaintextFromDecryptionResult(string decryption_result);
};


#endif //ABELIB_DECRYPTOR_H
