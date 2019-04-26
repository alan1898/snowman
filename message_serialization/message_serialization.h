//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_MESSAGE_SERIALIZATION_H
#define ABELIB_MESSAGE_SERIALIZATION_H

#include "../basis.h"
#include "../scheme_structure/scheme_structure.h"
#include "element_bytes.h"
#include "format_string_bytes.h"

#define KEY_PUBLIC 1
#define KEY_MASTER 2
#define KEY_SECRET 3

class message_serialization {
public:
//    element_bytes* elementToBytes(element_s *elem);
    cJSON* elementBytesToCJSON(element_bytes *elem_bytes);
    element_bytes* CJSONToElementBytes(cJSON *c_element_bytes);

//    format_string_bytes* stringToFormatBytes(string str);
    cJSON* formatStringBytesToCJSON(format_string_bytes *format_str_bytes);
    format_string_bytes* CJSONToFormatStringBytes(cJSON *c_format_str_butes);

    cJSON* KeyToCJSON(Key *key);
    Key* CJSONToKey(cJSON *c_key, pairing_t *pairing);

    cJSON* CiphertextToCJSON(Ciphertext *ciphertext);
    Ciphertext* CJSONToCiphertext(cJSON *c_ciphertext, pairing_t *pairing);

    cJSON* VectorKeyToCJSON(vector<Key*> *vector_key);
    vector<Key*>* CJSONToVectorKey(cJSON *c_vector_key, pairing_t *pairing);

    cJSON* VectorStringToCJSON(vector<string> *vector_string);
    vector<string>* CJSONToVectorString(cJSON *c_vector_string);

    cJSON* keyGenInfoToCJSON(Key *public_key, Key *master_key, vector<string> *attributes);
    cJSON* encryptInfoToCJSON(element_s *m, string policy, Key *public_key);
    cJSON* decryptInfoToCJSON(Ciphertext *ciphertext, Key *secret_key, vector<string> *attributes);
};


#endif //ABELIB_MESSAGE_SERIALIZATION_H
