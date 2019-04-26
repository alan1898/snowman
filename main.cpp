//
// Created by alan on 19-4-26.
//

#include "abe.h"

int main() {
    pairing_t pairing;
    pbc_param_t par;
    curve_param cp;
    element_t sample_element;
    pbc_param_init_set_str(par, cp.a_param.c_str());
//    pbc_param_init_a_gen(par, 3, 3);
    pairing_init_pbc_param(pairing, par);
    element_init_Zr(sample_element, pairing);
    element_random(sample_element);
    element_t m;
    element_init_GT(m, pairing);
    element_random(m);
    element_t mm;
    element_init_GT(mm, pairing);
    element_random(mm);

    element_t seed;
    element_init_same_as(seed, sample_element);

    cout << endl;


//    string s = "hmp&mmp";
//    s.replace(3, 1, 1, '\0');
//    cout << s.size() << s << endl;

    encryptor *encryptor1 = new encryptor("RW13");
    decryptor *decryptor1 = new decryptor("RW13");
    kgc *kgc1 = new kgc("RW13");
    string file_str = "终于做完啦！";
//    file_str.replace(16, 1, 1, '\0');

    string policy = "a&b|c";
    vector<string> *attributes = new vector<string>;
    attributes->push_back("a");
    attributes->push_back("c");
    attributes->push_back("d");

    message_serialization ms;

    // set up
    string set_up_res = kgc1->setUp();
    cJSON *c_vector_key = cJSON_Parse(set_up_res.c_str());
    vector<Key*> *vector_key = ms.CJSONToVectorKey(c_vector_key, &pairing);

    // get public_key_json_str and master_key_json_str
    cJSON *c_public_key = ms.KeyToCJSON(vector_key->at(1));
    cJSON *c_master_key = ms.KeyToCJSON(vector_key->at(0));
    string public_key_json_str(cJSON_Print(c_public_key));
    string master_key_json_str(cJSON_Print(c_master_key));

    // get attributes_json_str
    cJSON *c_attributes = ms.VectorStringToCJSON(attributes);
    string attributes_json_str(cJSON_Print(c_attributes));

    // key gen
    string key_gen_res = kgc1->keyGen(public_key_json_str, master_key_json_str, attributes_json_str);

    // get secret_key_json_str
    cJSON *c_secret_key = cJSON_Parse(key_gen_res.c_str());
    string secret_key_json_str(cJSON_Print(c_secret_key));

    // encrypt
    string share_json_str = encryptor1->encrypt(file_str, "alan", policy, public_key_json_str);

    // decrypt
    string decrypt_res = decryptor1->decrypt(share_json_str, secret_key_json_str, attributes_json_str);
    if (decrypt_res == "") {
        cout << "cannot decrypt" << endl;
    } else {
        string plaintext = decryptor1->getPlaintextFromDecryptionResult(decrypt_res);
        cout << plaintext << endl;
    }

//
//    // keyGen
//    cJSON *c_key_gen_info = ms.keyGenInfoToCJSON(vector_key->at(1), vector_key->at(0), attributes);
//    unsigned char *key_gen_info = (unsigned char*)cJSON_Print(c_key_gen_info);
//    unsigned char *secret_key_str = abe_interface.keyGen(key_gen_info);
//
//    // encrypt
//    cJSON *c_encrypt_info = ms.encryptInfoToCJSON(m, policy, vector_key->at(1));
//    unsigned char *encrypt_info = (unsigned char*)cJSON_Print(c_encrypt_info);
//    unsigned char *ciphertext_str = abe_interface.encrypt(encrypt_info);
//
//    // decrypt
//    // get secret_key
//    cJSON *c_secret_key = cJSON_Parse((char*)secret_key_str);
//    Key *secret_key = ms.CJSONToKey(c_secret_key, &pairing);
//    // get ciphertext
//    cJSON *c_ciphertext = cJSON_Parse((char*)ciphertext_str);
//    Ciphertext *ciphertext = ms.CJSONToCiphertext(c_ciphertext, &pairing);
//    cJSON *c_decrypt_info = ms.decryptInfoToCJSON(ciphertext, secret_key, attributes);
//    unsigned char *decrypt_info = (unsigned char*)cJSON_Print(c_decrypt_info);
//    unsigned char *decrypt_res = abe_interface.decrypt(decrypt_info);
//
//    // get res
//    cJSON *c_res = cJSON_Parse((char*)decrypt_res);
//    element_bytes *res_bytes = ms.CJSONToElementBytes(c_res);
//    res_bytes->recover();
//    element_t res;
//    element_init_GT(res, pairing);
//    element_from_bytes(res, res_bytes->getBytes());
//
//    element_printf("%B\n%B\n", m, res);
//
//    cout << element_length_in_bytes(m) << endl;
//
//    // compute Atau
//    element_t Atau;
//    element_init_G1(Atau, pairing);
//    string A = "a";
//    unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
//    SHA256_CTX sha256;
//    SHA256_Init(&sha256);
//    SHA256_Update(&sha256, A.c_str(), A.size());
//    SHA256_Final(hash_str_byte, &sha256);
//    element_from_hash(Atau, hash_str_byte, SHA256_DIGEST_LENGTH);
//    element_printf("%B\n", Atau);
//    // compute Btau
//    element_t Btau;
//    element_init_G1(Btau, pairing);
//    string B = "b";
//    abe_sha as;
//    string hash_str = as.abe_sha256(B);
//    cout << hash_str << endl;

    cout << endl;

    return 0;
}