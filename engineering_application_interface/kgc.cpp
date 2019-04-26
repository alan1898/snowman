//
// Created by alan on 19-4-26.
//

#include "kgc.h"

kgc::kgc(string scheme) {
    if (scheme == "RW13") {
        classic_abe = new RW13();
    } else if (scheme == "BSW07") {
        classic_abe = new BSW07();
    }
}

string kgc::setUp() {
    message_serialization ms;

    vector<Key*> *vector_key = classic_abe->setUp();

    cJSON *c_vector_key = ms.VectorKeyToCJSON(vector_key);

    string res(cJSON_Print(c_vector_key));

    return res;
}

string kgc::keyGen(string public_key_json_str, string master_key_json_str, string attributes_json_str) {
    message_serialization ms;

    // get public_key
    cJSON *c_public_key = cJSON_Parse(public_key_json_str.c_str());
    Key *public_key = ms.CJSONToKey(c_public_key, classic_abe->getPairing());

    // get master_key
    cJSON *c_master_key = cJSON_Parse(master_key_json_str.c_str());
    Key *master_key = ms.CJSONToKey(c_master_key, classic_abe->getPairing());

    // get attributes
    cJSON *c_attributes = cJSON_Parse(attributes_json_str.c_str());
    vector<string> *attributes = ms.CJSONToVectorString(c_attributes);

    Key *secret_key = classic_abe->keyGen(public_key, master_key, attributes);

    cJSON *c_secret_key = ms.KeyToCJSON(secret_key);

    string res(cJSON_Print(c_secret_key));

    return res;
}