//
// Created by alan on 19-4-26.
//

#include "message_serialization.h"

//element_bytes* message_serialization::elementToBytes(element_s *elem) {
//    element_bytes *res = new element_bytes(elem);
//    res->replace();
//
//    return res;
//}
//format_string_bytes* message_serialization::stringToFormatBytes(string str) {
//    format_string_bytes *res = new format_string_bytes(str);
//    res->replace();
//
//    return res;
//}

cJSON* message_serialization::elementBytesToCJSON(element_bytes *elem_bytes) {
    cJSON *res = cJSON_CreateObject();

    cJSON *n = cJSON_CreateNumber(((double)elem_bytes->getN()) + 0.5);
    cJSON *bytes = cJSON_CreateString((char*)elem_bytes->getBytes());
    cJSON *replacement = cJSON_CreateArray();

    cJSON_AddItemToObject(res, "n", n);
    cJSON_AddItemToObject(res, "bytes", bytes);
    cJSON_AddItemToObject(res, "replacement", replacement);

    for (int i = 0; i < elem_bytes->getReplacement()->size(); ++i) {
        cJSON_AddItemToArray(replacement, cJSON_CreateNumber(((double)elem_bytes->getReplacement()->at(i)) + 0.5));
    }

    return res;
}
cJSON* message_serialization::formatStringBytesToCJSON(format_string_bytes *format_str_bytes) {
    format_str_bytes->replace();

    cJSON *res = cJSON_CreateObject();

    cJSON *n = cJSON_CreateNumber(((double)format_str_bytes->getN()) + 0.5);
    cJSON *bytes = cJSON_CreateString((char*)format_str_bytes->getBytes());
    cJSON *replacement = cJSON_CreateArray();

    cJSON_AddItemToObject(res, "n", n);
    cJSON_AddItemToObject(res, "bytes", bytes);
    cJSON_AddItemToObject(res, "replacement", replacement);

    for (int i = 0; i < format_str_bytes->getReplacement()->size(); ++i) {
        cJSON_AddItemToArray(replacement, cJSON_CreateNumber(((double)format_str_bytes->getReplacement()->at(i)) + 0.5));
    }

    return res;
}

element_bytes* message_serialization::CJSONToElementBytes(cJSON *c_element_bytes) {
    cJSON *c_n = cJSON_GetObjectItem(c_element_bytes, "n");
    cJSON *c_bytes = cJSON_GetObjectItem(c_element_bytes, "bytes");
    cJSON *c_replacement = cJSON_GetObjectItem(c_element_bytes, "replacement");

    element_bytes *elem_bytes = new element_bytes();
    elem_bytes->setN((int)c_n->valuedouble);
    elem_bytes->setBytes((unsigned char*)c_bytes->valuestring);
    vector<int> *replacement = new vector<int>();
    for (signed long int j = 0; j < cJSON_GetArraySize(c_replacement); ++j) {
        cJSON *elem_cjson_replacement_item = cJSON_GetArrayItem(c_replacement, j);
        replacement->push_back((int)elem_cjson_replacement_item->valuedouble);
    }
    elem_bytes->setReplacement(replacement);

    return elem_bytes;
}
format_string_bytes* message_serialization::CJSONToFormatStringBytes(cJSON *c_format_str_butes) {
    cJSON *c_n = cJSON_GetObjectItem(c_format_str_butes, "n");
    cJSON *c_bytes = cJSON_GetObjectItem(c_format_str_butes, "bytes");
    cJSON *c_replacement = cJSON_GetObjectItem(c_format_str_butes, "replacement");

    format_string_bytes *format_str_bytes = new format_string_bytes();
    format_str_bytes->setN((int)c_n->valuedouble);
    format_str_bytes->setBytes((unsigned char*)c_bytes->valuestring);
    vector<int> *replacement = new vector<int>();
    for (signed long int j = 0; j < cJSON_GetArraySize(c_replacement); ++j) {
        cJSON *elem_cjson_replacement_item = cJSON_GetArrayItem(c_replacement, j);
        replacement->push_back((int)elem_cjson_replacement_item->valuedouble);
    }
    format_str_bytes->setReplacement(replacement);

    format_str_bytes->recover();

    return format_str_bytes;
}

cJSON* message_serialization::KeyToCJSON(Key *key) {
    cJSON *c_key = cJSON_CreateObject();
    cJSON *c_g1_components = cJSON_CreateObject();
    cJSON *c_g2_components = cJSON_CreateObject();
    cJSON *c_gt_components = cJSON_CreateObject();
    cJSON *c_zr_components = cJSON_CreateObject();

    if (key->getType() == Key::PUBLIC) {
        cJSON_AddItemToObject(c_key, "type", cJSON_CreateNumber(((double)KEY_PUBLIC) + 0.5));
    } else if (key->getType() == Key::MASTER) {
        cJSON_AddItemToObject(c_key, "type", cJSON_CreateNumber(((double)KEY_MASTER) + 0.5));
    } else if (key->getType() == Key::SECRET) {
        cJSON_AddItemToObject(c_key, "type", cJSON_CreateNumber(((double)KEY_SECRET) + 0.5));
    }

    cJSON_AddItemToObject(c_key, "g1_components", c_g1_components);
    cJSON_AddItemToObject(c_key, "g2_components", c_g2_components);
    cJSON_AddItemToObject(c_key, "gt_components", c_gt_components);
    cJSON_AddItemToObject(c_key, "zr_components", c_zr_components);

    map<string, element_s*>::iterator it;
    for (it = key->getComponents("G1")->begin(); it != key->getComponents("G1")->end(); ++it) {
        element_bytes *elem_bytes = new element_bytes(it->second);
        elem_bytes->replace();
        cJSON *elem_cjson = elementBytesToCJSON(elem_bytes);
        cJSON_AddItemToObject(c_g1_components, it->first.c_str(), elem_cjson);
    }
    for (it = key->getComponents("G2")->begin(); it != key->getComponents("G2")->end(); ++it) {
        element_bytes *elem_bytes = new element_bytes(it->second);
        elem_bytes->replace();
        cJSON *elem_cjson = elementBytesToCJSON(elem_bytes);
        cJSON_AddItemToObject(c_g2_components, it->first.c_str(), elem_cjson);
    }
    for (it = key->getComponents("GT")->begin(); it != key->getComponents("GT")->end(); ++it) {
        element_bytes *elem_bytes = new element_bytes(it->second);
        elem_bytes->replace();
        cJSON *elem_cjson = elementBytesToCJSON(elem_bytes);
        cJSON_AddItemToObject(c_gt_components, it->first.c_str(), elem_cjson);
    }
    for (it = key->getComponents("ZR")->begin(); it != key->getComponents("ZR")->end(); ++it) {
        element_bytes *elem_bytes = new element_bytes(it->second);
        elem_bytes->replace();
        cJSON *elem_cjson = elementBytesToCJSON(elem_bytes);
        cJSON_AddItemToObject(c_zr_components, it->first.c_str(), elem_cjson);
    }

    return c_key;
}

Key* message_serialization::CJSONToKey(cJSON *c_key, pairing_t *pairing) {
    Key *res = new Key();

    cJSON *c_g1_components = cJSON_GetObjectItem(c_key, "g1_components");
    cJSON *c_g2_components = cJSON_GetObjectItem(c_key, "g2_components");
    cJSON *c_gt_components = cJSON_GetObjectItem(c_key, "gt_components");
    cJSON *c_zr_components = cJSON_GetObjectItem(c_key, "zr_components");

    for (signed long int i = 0; i < cJSON_GetArraySize(c_g1_components); ++i) {
        cJSON *elem_cjson = cJSON_GetArrayItem(c_g1_components, i);

        element_bytes *elem_bytes = CJSONToElementBytes(elem_cjson);
        elem_bytes->recover();

        element_t elem;
        element_init_G1(elem, *pairing);
        element_from_bytes(elem, elem_bytes->getBytes());

        res->insertComponent(elem_cjson->string, "G1", elem);
    }
    for (signed long int i = 0; i < cJSON_GetArraySize(c_g2_components); ++i) {
        cJSON *elem_cjson = cJSON_GetArrayItem(c_g2_components, i);

        element_bytes *elem_bytes = CJSONToElementBytes(elem_cjson);
        elem_bytes->recover();

        element_t elem;
        element_init_G2(elem, *pairing);
        element_from_bytes(elem, elem_bytes->getBytes());

        res->insertComponent(elem_cjson->string, "G2", elem);
    }
    for (signed long int i = 0; i < cJSON_GetArraySize(c_gt_components); ++i) {
        cJSON *elem_cjson = cJSON_GetArrayItem(c_gt_components, i);

        element_bytes *elem_bytes = CJSONToElementBytes(elem_cjson);
        elem_bytes->recover();

        element_t elem;
        element_init_GT(elem, *pairing);
        element_from_bytes(elem, elem_bytes->getBytes());

        res->insertComponent(elem_cjson->string, "GT", elem);
    }
    for (signed long int i = 0; i < cJSON_GetArraySize(c_zr_components); ++i) {
        cJSON *elem_cjson = cJSON_GetArrayItem(c_zr_components, i);

        element_bytes *elem_bytes = CJSONToElementBytes(elem_cjson);
        elem_bytes->recover();

        element_t elem;
        element_init_Zr(elem, *pairing);
        element_from_bytes(elem, elem_bytes->getBytes());

        res->insertComponent(elem_cjson->string, "ZR", elem);
    }

    return res;
}

cJSON* message_serialization::CiphertextToCJSON(Ciphertext *ciphertext) {
    cJSON *c_ciphertext = cJSON_CreateObject();
    cJSON *c_g1_components = cJSON_CreateObject();
    cJSON *c_g2_components = cJSON_CreateObject();
    cJSON *c_gt_components = cJSON_CreateObject();
    cJSON *c_zr_components = cJSON_CreateObject();

    cJSON_AddItemToObject(c_ciphertext, "policy", cJSON_CreateString(ciphertext->getPolicy().c_str()));

    cJSON_AddItemToObject(c_ciphertext, "g1_components", c_g1_components);
    cJSON_AddItemToObject(c_ciphertext, "g2_components", c_g2_components);
    cJSON_AddItemToObject(c_ciphertext, "gt_components", c_gt_components);
    cJSON_AddItemToObject(c_ciphertext, "zr_components", c_zr_components);

    map<string, element_s*>::iterator it;
    for (it = ciphertext->getComponents("G1")->begin(); it != ciphertext->getComponents("G1")->end(); ++it) {
        element_bytes *elem_bytes = new element_bytes(it->second);
        elem_bytes->replace();
        cJSON *elem_cjson = elementBytesToCJSON(elem_bytes);
        cJSON_AddItemToObject(c_g1_components, it->first.c_str(), elem_cjson);
    }
    for (it = ciphertext->getComponents("G2")->begin(); it != ciphertext->getComponents("G2")->end(); ++it) {
        element_bytes *elem_bytes = new element_bytes(it->second);
        elem_bytes->replace();
        cJSON *elem_cjson = elementBytesToCJSON(elem_bytes);
        cJSON_AddItemToObject(c_g2_components, it->first.c_str(), elem_cjson);
    }
    for (it = ciphertext->getComponents("GT")->begin(); it != ciphertext->getComponents("GT")->end(); ++it) {
        element_bytes *elem_bytes = new element_bytes(it->second);
        elem_bytes->replace();
        cJSON *elem_cjson = elementBytesToCJSON(elem_bytes);
        cJSON_AddItemToObject(c_gt_components, it->first.c_str(), elem_cjson);
    }
    for (it = ciphertext->getComponents("ZR")->begin(); it != ciphertext->getComponents("ZR")->end(); ++it) {
        element_bytes *elem_bytes = new element_bytes(it->second);
        elem_bytes->replace();
        cJSON *elem_cjson = elementBytesToCJSON(elem_bytes);
        cJSON_AddItemToObject(c_zr_components, it->first.c_str(), elem_cjson);
    }

    return c_ciphertext;
}

Ciphertext* message_serialization::CJSONToCiphertext(cJSON *c_ciphertext, pairing_t *pairing) {
    Ciphertext *res = new Ciphertext();

    cJSON *c_policy = cJSON_GetObjectItem(c_ciphertext, "policy");
    cJSON *c_g1_components = cJSON_GetObjectItem(c_ciphertext, "g1_components");
    cJSON *c_g2_components = cJSON_GetObjectItem(c_ciphertext, "g2_components");
    cJSON *c_gt_components = cJSON_GetObjectItem(c_ciphertext, "gt_components");
    cJSON *c_zr_components = cJSON_GetObjectItem(c_ciphertext, "zr_components");

    res->setPolicy(c_policy->valuestring);

    for (signed long int i = 0; i < cJSON_GetArraySize(c_g1_components); ++i) {
        cJSON *elem_cjson = cJSON_GetArrayItem(c_g1_components, i);

        element_bytes *elem_bytes = CJSONToElementBytes(elem_cjson);
        elem_bytes->recover();

        element_t elem;
        element_init_G1(elem, *pairing);
        element_from_bytes(elem, elem_bytes->getBytes());

        res->insertComponent(elem_cjson->string, "G1", elem);
    }
    for (signed long int i = 0; i < cJSON_GetArraySize(c_g2_components); ++i) {
        cJSON *elem_cjson = cJSON_GetArrayItem(c_g2_components, i);

        element_bytes *elem_bytes = CJSONToElementBytes(elem_cjson);
        elem_bytes->recover();

        element_t elem;
        element_init_G2(elem, *pairing);
        element_from_bytes(elem, elem_bytes->getBytes());

        res->insertComponent(elem_cjson->string, "G2", elem);
    }
    for (signed long int i = 0; i < cJSON_GetArraySize(c_gt_components); ++i) {
        cJSON *elem_cjson = cJSON_GetArrayItem(c_gt_components, i);

        element_bytes *elem_bytes = CJSONToElementBytes(elem_cjson);
        elem_bytes->recover();

        element_t elem;
        element_init_GT(elem, *pairing);
        element_from_bytes(elem, elem_bytes->getBytes());

        res->insertComponent(elem_cjson->string, "GT", elem);
    }
    for (signed long int i = 0; i < cJSON_GetArraySize(c_zr_components); ++i) {
        cJSON *elem_cjson = cJSON_GetArrayItem(c_zr_components, i);

        element_bytes *elem_bytes = CJSONToElementBytes(elem_cjson);
        elem_bytes->recover();

        element_t elem;
        element_init_Zr(elem, *pairing);
        element_from_bytes(elem, elem_bytes->getBytes());

        res->insertComponent(elem_cjson->string, "ZR", elem);
    }

    return res;
}

cJSON* message_serialization::VectorKeyToCJSON(vector<Key *> *vector_key) {
    cJSON *c_vector_key = cJSON_CreateArray();

    for (signed long int i = 0; i < vector_key->size(); ++i) {
        cJSON *c_key = KeyToCJSON(vector_key->at(i));
        cJSON_AddItemToArray(c_vector_key, c_key);
    }

    return c_vector_key;
}

vector<Key*>* message_serialization::CJSONToVectorKey(cJSON *c_vector_key, pairing_t *pairing) {
    vector<Key*> *vector_key = new vector<Key*>;

    for (signed long int i = 0; i < cJSON_GetArraySize(c_vector_key); ++i) {
        cJSON *c_key = cJSON_GetArrayItem(c_vector_key, i);
        Key *key = CJSONToKey(c_key, pairing);

        vector_key->push_back(key);
    }

    return vector_key;
}

cJSON* message_serialization::VectorStringToCJSON(vector<string> *vector_string) {
    cJSON *c_vector_string = cJSON_CreateArray();

    for (signed long int i = 0; i < vector_string->size(); ++i) {
        cJSON *c_string = cJSON_CreateString(vector_string->at(i).c_str());
        cJSON_AddItemToArray(c_vector_string, c_string);
    }

    return c_vector_string;
}

vector<string> * message_serialization::CJSONToVectorString(cJSON *c_vector_string) {
    vector<string> *vector_string = new vector<string>;

    for (signed long int i = 0; i < cJSON_GetArraySize(c_vector_string); ++i) {
        cJSON *c_string = cJSON_GetArrayItem(c_vector_string, i);
        string str = c_string->valuestring;

        vector_string->push_back(str);
    }

    return vector_string;
}

cJSON* message_serialization::keyGenInfoToCJSON(Key *public_key, Key *master_key, vector<string> *attributes) {
    cJSON *c_key_gen_info = cJSON_CreateObject();

    cJSON *c_public_key = KeyToCJSON(public_key);
    cJSON *c_master_key = KeyToCJSON(master_key);
    cJSON *c_attributes = VectorStringToCJSON(attributes);

    cJSON_AddItemToObject(c_key_gen_info, "public_key", c_public_key);
    cJSON_AddItemToObject(c_key_gen_info, "master_key", c_master_key);
    cJSON_AddItemToObject(c_key_gen_info, "attributes", c_attributes);

    return c_key_gen_info;
}

cJSON* message_serialization::encryptInfoToCJSON(element_s *m, string policy, Key *public_key) {
    cJSON *c_encrypt_info = cJSON_CreateObject();

    element_bytes *m_bytes = new element_bytes(m);
    m_bytes->replace();
    cJSON *c_m = elementBytesToCJSON(m_bytes);
    cJSON *c_policy = cJSON_CreateString(policy.c_str());
    cJSON *c_public_key = KeyToCJSON(public_key);

    cJSON_AddItemToObject(c_encrypt_info, "m", c_m);
    cJSON_AddItemToObject(c_encrypt_info, "policy", c_policy);
    cJSON_AddItemToObject(c_encrypt_info, "public_key", c_public_key);

    return c_encrypt_info;
}

cJSON* message_serialization::decryptInfoToCJSON(Ciphertext *ciphertext, Key *secret_key, vector<string> *attributes) {
    cJSON *c_decrypt_info = cJSON_CreateObject();

    cJSON *c_ciphertext = CiphertextToCJSON(ciphertext);
    cJSON *c_secret_key = KeyToCJSON(secret_key);
    cJSON *c_attributes = VectorStringToCJSON(attributes);

    cJSON_AddItemToObject(c_decrypt_info, "ciphertext", c_ciphertext);
    cJSON_AddItemToObject(c_decrypt_info, "secret_key", c_secret_key);
    cJSON_AddItemToObject(c_decrypt_info, "attributes", c_attributes);

    return c_decrypt_info;
}