//
// Created by alan on 19-9-18.
//

#include "DET.h"

vector<signed long int>* DET::testJ() {
    vector<signed long int> *res = new vector<signed long int>();

    res->push_back(6);
    res->push_back(-5);
    res->push_back(1);

    return res;
}

vector<signed long int>* DET::testX() {
    vector<signed long int> *res = new vector<signed long int>();

    res->push_back(-10);
    res->push_back(17);
    res->push_back(-8);
    res->push_back(1);

    return res;
}

vector<signed long int>* DET::testY() {
    vector<signed long int> *res = new vector<signed long int>();

    res->push_back(-72);
    res->push_back(54);
    res->push_back(-13);
    res->push_back(1);

    return res;
}

vector<long> * DET::computeA(vector<signed long int> *J) {
    vector<signed long int> *res = new vector<signed long int>();

    for (signed long int i = 0; i <= J->size(); ++i) {
        res->push_back(i + 1);
    }

    return res;
}

element_s* DET::computeT(vector<signed long int> *a) {
    signed long int t = 0;

    // 从0开始加还是从1开始加？？？
    for (signed long int i = 0; i < a->size(); ++i) {
        t += a->at(i);
    }

    element_t *res = new element_t[1];
    element_init_Zr(*res, pairing);
    element_set_si(*res, t);

    return *res;
}

element_s* DET::computeIWK(signed long int i, vector<signed long int> *J) {
    element_t *res = new element_t[1];
    element_init_Zr(*res, pairing);

    // change i to element
    element_t e_i;
    element_init_Zr(e_i, pairing);
    element_set_si(e_i, i);

    element_t wk;
    element_init_Zr(wk, pairing);
    element_t i_wk;
    element_init_Zr(i_wk, pairing);
    for (signed long int k = 0; k < J->size(); ++k) {
        element_set_si(wk, J->at(k));
        element_sub(i_wk, e_i, wk);

        if (k == 0) {
            element_set(*res, i_wk);
        } else {
            element_mul(*res, *res, i_wk);
        }
    }

    return *res;
}

unsigned char* DET::H1(element_s *e) {
    unsigned char *bytes = (unsigned char*)malloc(gt_length);
    element_to_bytes(bytes, e);

    unsigned char *hash_str_byte = (unsigned char*)malloc(SHA256_DIGEST_LENGTH + 1);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, bytes, gt_length);
    SHA256_Final(hash_str_byte, &sha256);
    hash_str_byte[SHA256_DIGEST_LENGTH] = '\0';

    return hash_str_byte;
}

element_s* DET::H2(element_s *e) {
    element_t *res = new element_t[1];
    element_init_G1(*res, pairing);

    unsigned char *bytes = (unsigned char*)malloc(gt_length);
    element_to_bytes(bytes, e);

    unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, bytes, gt_length);
    SHA256_Final(hash_str_byte, &sha256);

    element_from_hash(*res, hash_str_byte, SHA256_DIGEST_LENGTH);

    return *res;
}

element_s* DET::computeV(Ciphertext_DET *CT, Key *SK, string C2_str, string sk_str, string pre_str, string post_str) {
    // compute awjs
//    vector<signed long int> *awjs = computeA(CT->getJ());

    vector<signed long int> *awjs = testJ();


    element_t awj;
    element_init_Zr(awj, pairing);
    element_t sk3j_awj;
    element_init_G1(sk3j_awj, pairing);
    element_t sk3j__awj;
    element_init_G1(sk3j__awj, pairing);
    element_t sk4j_awj;
    element_init_G1(sk4j_awj, pairing);
    element_t sk4j__awj;
    element_init_G1(sk4j__awj, pairing);

    element_t TTsk3j_awj;
    element_init_G1(TTsk3j_awj, pairing);
    element_t TTsk3j__awj;
    element_init_G1(TTsk3j__awj, pairing);
    element_t TTsk4j_awj;
    element_init_G1(TTsk4j_awj, pairing);
    element_t TTsk4j__awj;
    element_init_G1(TTsk4j__awj, pairing);

    // 从0开始加还是从1开始加？？？
    for (signed long int j = 0; j <= CT->getJ()->size(); ++j) {
        element_set_si(awj, awjs->at(j));

        char j_str[21];
        sprintf(j_str, "%ld", j);

        element_s *sk3j = SK->getComponent(pre_str + "3" + j_str);
        element_s *sk4j = SK->getComponent(pre_str + "4" + j_str);
        element_s *sk3j_ = SK->getComponent(pre_str + "3" + j_str + post_str);
        element_s *sk4j_ = SK->getComponent(pre_str + "4" + j_str + post_str);

        element_pow_zn(sk3j_awj, sk3j, awj);
        element_pow_zn(sk4j_awj, sk4j, awj);
        element_pow_zn(sk3j__awj, sk3j_, awj);
        element_pow_zn(sk4j__awj, sk4j_, awj);

        if (j == 0) {
            element_set(TTsk3j_awj, sk3j_awj);
            element_set(TTsk4j_awj, sk4j_awj);
            element_set(TTsk3j__awj, sk3j__awj);
            element_set(TTsk4j__awj, sk4j__awj);
        } else {
            element_mul(TTsk3j_awj, TTsk3j_awj, sk3j_awj);
            element_mul(TTsk4j_awj, TTsk4j_awj, sk4j_awj);
            element_mul(TTsk3j__awj, TTsk3j__awj, sk3j__awj);
            element_mul(TTsk4j__awj, TTsk4j__awj, sk4j__awj);
        }
    }

    element_s *C2 = CT->getComponent("C2" + C2_str);
    element_s *C3 = CT->getComponent("C3");

    element_t e_3C2, e_3_C3, e_4C2, e_4_C3;
    element_init_GT(e_3C2, pairing);
    element_init_GT(e_3_C3, pairing);
    element_init_GT(e_4C2, pairing);
    element_init_GT(e_4_C3, pairing);
    element_pairing(e_3C2, TTsk3j_awj, C2);
    element_pairing(e_3_C3, TTsk3j__awj, C3);
    element_pairing(e_4C2, TTsk4j_awj, C2);
    element_pairing(e_4_C3, TTsk4j__awj, C3);

    element_t e_e1, e_e2;
    element_init_GT(e_e1, pairing);
    element_init_GT(e_e2, pairing);
    element_mul(e_e1, e_3C2, e_3_C3);
    element_mul(e_e2, e_4C2, e_4_C3);

    element_s *sk1 = SK->getComponent(pre_str + "1" + sk_str);
    element_s *sk2 = SK->getComponent(pre_str + "2" + sk_str);

    element_s *C4 = CT->getComponent("C4");
    element_s *C5 = CT->getComponent("C5");

    element_s *tx_ = SK->getComponent("tx_");
    element_s *ty_ = SK->getComponent("ty_");

    element_t e_1C4, e_2C5;
    element_init_GT(e_1C4, pairing);
    element_init_GT(e_2C5, pairing);
    element_pairing(e_1C4, sk1, C4);
    element_pairing(e_2C5, sk2, C5);
    element_t e_1C4_tx_, e_2C5_ty_;
    element_init_GT(e_1C4_tx_, pairing);
    element_init_GT(e_2C5_ty_, pairing);
    element_pow_zn(e_1C4_tx_, e_1C4, tx_);
    element_pow_zn(e_2C5_ty_, e_2C5, ty_);

    element_t e_e1_e, e_e2_e;
    element_init_GT(e_e1_e, pairing);
    element_init_GT(e_e2_e, pairing);
    element_div(e_e1_e, e_e1, e_1C4_tx_);
    element_div(e_e2_e, e_e2, e_2C5_ty_);

    element_t *res = new element_t[1];
    element_init_GT(*res, pairing);
    element_mul(*res, e_e1_e, e_e2_e);

    return *res;
}

DET::DET() {
    // init pairing
    pbc_param_t par;
    curve_param curves;
    pbc_param_init_set_str(par, curves.a_param.c_str());
    pairing_init_pbc_param(pairing, par);

    // init sample elements
    element_init_G1(g1_sample, pairing);
    element_init_G2(g2_sample, pairing);
    element_init_GT(gt_sample, pairing);
    element_init_Zr(zr_sample, pairing);

    // get the length of group elements
    g1_length = element_length_in_bytes(g1_sample);
    g2_length = element_length_in_bytes(g2_sample);
    gt_length = element_length_in_bytes(gt_sample);
    zr_length = element_length_in_bytes(zr_sample);
}
DET::DET(signed long int L1, signed long int L2, signed long int L3) {
    // init pairing
    pbc_param_t par;
    curve_param curves;
    pbc_param_init_set_str(par, curves.a_param.c_str());
    pairing_init_pbc_param(pairing, par);

    // init sample elements
    element_init_G1(g1_sample, pairing);
    element_init_G2(g2_sample, pairing);
    element_init_GT(gt_sample, pairing);
    element_init_Zr(zr_sample, pairing);

    // get the length of group elements
    g1_length = element_length_in_bytes(g1_sample);
    g2_length = element_length_in_bytes(g2_sample);
    gt_length = element_length_in_bytes(gt_sample);
    zr_length = element_length_in_bytes(zr_sample);

    this->L1 = L1;
    this->L2 = L2;
    this->L3 = L3;
}

vector<Key*>* DET::setUp(signed long int N) {
    this->N = N;

    Key *master_key = new Key(Key::MASTER);
    Key *public_key = new Key(Key::PUBLIC);

    // randomly choose g
    element_t g;
    element_init_G1(g, pairing);
    element_random(g);
    public_key->insertComponent("g", "G1", g);

    // init Ri and ri
    element_t Ri, ri;
    element_init_G1(Ri, pairing);
    element_init_Zr(ri ,pairing);

    string R_str = "R";
    string r_str = "r";
    char num[21];
    for (signed long int i = 1; i <= N; ++i) {
        sprintf(num, "%ld", i);
        // randomly choose ri
        element_random(ri);
        master_key->insertComponent(r_str + num, "ZR", ri);
        // compute Ri=g^ri
        element_pow_zn(Ri, g, ri);
        public_key->insertComponent(R_str + num, "G1", Ri);
    }

    // randomly choose alpha, alpha', gamma1, gamma2, gamma3
    element_t alpha, alpha_, gamma1, gamma2, gamma3;
    element_init_Zr(alpha, pairing);
    element_init_Zr(alpha_, pairing);
    element_init_Zr(gamma1, pairing);
    element_init_Zr(gamma2, pairing);
    element_init_Zr(gamma3, pairing);
    element_random(alpha);
    element_random(alpha_);
    element_random(gamma1);
    element_random(gamma2);
    element_random(gamma3);
    master_key->insertComponent("alpha", "ZR", alpha);
    master_key->insertComponent("alpha_", "ZR", alpha_);
    master_key->insertComponent("gamma1", "ZR", gamma1);
    master_key->insertComponent("gamma2", "ZR", gamma2);
    master_key->insertComponent("gamma3", "ZR", gamma3);

    // randomly choose W1, W2
    element_t W1, W2;
    element_init_G1(W1, pairing);
    element_init_G1(W2, pairing);
    element_random(W1);
    element_random(W2);
    public_key->insertComponent("W1", "G1", W1);
    public_key->insertComponent("W2", "G1", W2);

    // compute e(g,W1), e(g,W2)
    element_t e_gW1, e_gW2;
    element_init_GT(e_gW1, pairing);
    element_init_GT(e_gW2, pairing);
    element_pairing(e_gW1, g, W1);
    element_pairing(e_gW2, g, W2);

    // compute alpha*gamma1, alpha*gamma2, alpha'*gamma1, alpha'*gamma3
    element_t alpha_gamma1, alpha_gamma2, alpha__gamma1, alpha__gamma3;
    element_init_Zr(alpha_gamma1, pairing);
    element_init_Zr(alpha_gamma2, pairing);
    element_init_Zr(alpha__gamma1, pairing);
    element_init_Zr(alpha__gamma3, pairing);
    element_mul(alpha_gamma1, alpha, gamma1);
    element_mul(alpha_gamma2, alpha, gamma2);
    element_mul(alpha__gamma1, alpha_, gamma1);
    element_mul(alpha__gamma3, alpha_, gamma3);

    // compute e_gW1_alpha_gamma1, e_gW2_alpha_gamma1, e_gW1_alpha_gamma2, e_gW2_alpha_gamma2
    element_t e_gW1_alpha_gamma1, e_gW2_alpha_gamma1, e_gW1_alpha_gamma2, e_gW2_alpha_gamma2;
    element_init_GT(e_gW1_alpha_gamma1, pairing);
    element_init_GT(e_gW2_alpha_gamma1, pairing);
    element_init_GT(e_gW1_alpha_gamma2, pairing);
    element_init_GT(e_gW2_alpha_gamma2, pairing);
    element_pow_zn(e_gW1_alpha_gamma1, e_gW1, alpha_gamma1);
    element_pow_zn(e_gW2_alpha_gamma1, e_gW2, alpha_gamma1);
    element_pow_zn(e_gW1_alpha_gamma2, e_gW1, alpha_gamma2);
    element_pow_zn(e_gW2_alpha_gamma2, e_gW2, alpha_gamma2);

    // compute e_gW1_alpha__gamma1, e_gW2_alpha__gamma1, e_gW1_alpha__gamma3, e_gW2_alpha__gamma3
    element_t e_gW1_alpha__gamma1, e_gW2_alpha__gamma1, e_gW1_alpha__gamma3, e_gW2_alpha__gamma3;
    element_init_GT(e_gW1_alpha__gamma1, pairing);
    element_init_GT(e_gW2_alpha__gamma1, pairing);
    element_init_GT(e_gW1_alpha__gamma3, pairing);
    element_init_GT(e_gW2_alpha__gamma3, pairing);
    element_pow_zn(e_gW1_alpha__gamma1, e_gW1, alpha__gamma1);
    element_pow_zn(e_gW2_alpha__gamma1, e_gW2, alpha__gamma1);
    element_pow_zn(e_gW1_alpha__gamma3, e_gW1, alpha__gamma3);
    element_pow_zn(e_gW2_alpha__gamma3, e_gW2, alpha__gamma3);

    // compute u1, v1, u2, v2
    element_t u1, v1, u2, v2;
    element_init_GT(u1, pairing);
    element_init_GT(v1, pairing);
    element_init_GT(u2, pairing);
    element_init_GT(v2, pairing);
    element_mul(u1, e_gW1_alpha_gamma1, e_gW2_alpha_gamma1);
    element_mul(v1, e_gW1_alpha_gamma2, e_gW2_alpha_gamma2);
    element_mul(u2, e_gW1_alpha__gamma1, e_gW2_alpha__gamma1);
    element_mul(v2, e_gW1_alpha__gamma3, e_gW2_alpha__gamma3);
    public_key->insertComponent("u1", "GT", u1);
    public_key->insertComponent("v1", "GT", v1);
    public_key->insertComponent("u2", "GT", u2);
    public_key->insertComponent("v2", "GT", v2);

    // compute g^alpha, g^alpha'
    element_t g_alpha, g_alpha_;
    element_init_G1(g_alpha, pairing);
    element_init_G1(g_alpha_, pairing);
    element_pow_zn(g_alpha, g, alpha);
    element_pow_zn(g_alpha_, g, alpha_);
    public_key->insertComponent("g_alpha", "G1", g_alpha);
    public_key->insertComponent("g_alpha_", "G1", g_alpha_);

    vector<Key*> *res = new vector<Key*>(2);
    (*res)[0] = master_key;
    (*res)[1] = public_key;

    return res;
}

Ciphertext_DET* DET::encrypt(Key *public_key, vector<signed long int> *J, vector<signed long int> *X, vector<signed long int> *Y, unsigned char *message) {
    Ciphertext_DET *res = new Ciphertext_DET(J);

    // obtain public params
    element_t u1, v1, u2, v2;
    element_init_same_as(u1, public_key->getComponent("u1"));
    element_set(u1, public_key->getComponent("u1"));
    element_init_same_as(v1, public_key->getComponent("v1"));
    element_set(v1, public_key->getComponent("v1"));
    element_init_same_as(u2, public_key->getComponent("u2"));
    element_set(u2, public_key->getComponent("u2"));
    element_init_same_as(v2, public_key->getComponent("v2"));
    element_set(v2, public_key->getComponent("v2"));
    element_t g_alpha, g_alpha_;
    element_init_same_as(g_alpha, public_key->getComponent("g_alpha"));
    element_set(g_alpha, public_key->getComponent("g_alpha"));
    element_init_same_as(g_alpha_, public_key->getComponent("g_alpha_"));
    element_set(g_alpha_, public_key->getComponent("g_alpha_"));
    element_t g;
    element_init_same_as(g, public_key->getComponent("g"));
    element_set(g, public_key->getComponent("g"));
    element_t W1, W2;
    element_init_same_as(W1, public_key->getComponent("W1"));
    element_set(W1, public_key->getComponent("W1"));
    element_init_same_as(W2, public_key->getComponent("W2"));
    element_set(W2, public_key->getComponent("W2"));

    // randomly choose z1, z2, z
    element_t z1, z2, z;
    element_init_Zr(z1, pairing);
    element_init_Zr(z2, pairing);
    element_init_Zr(z, pairing);
    element_random(z1);
    element_random(z2);
    element_random(z);

    // compute u1^z1
    element_t u1_z1;
    element_init_GT(u1_z1, pairing);
    element_pow_zn(u1_z1, u1, z1);

    // compute v1^z2
    element_t v1_z2;
    element_init_GT(v1_z2, pairing);
    element_pow_zn(v1_z2, v1, z2);

    // compute u1^z1*v1^z2
    element_t u1_z1_v1_z2;
    element_init_GT(u1_z1_v1_z2, pairing);
    element_mul(u1_z1_v1_z2, u1_z1, v1_z2);
    element_printf("u1^z1*v1^z2: %B\n", u1_z1_v1_z2);

    // compute H1(u1^z1*v1^z2)
    unsigned char* H_1 = H1(u1_z1_v1_z2);

    // compute m||z
    unsigned char *mz = (unsigned char*)malloc(8 + zr_length + 1);
    for (signed long int index = 0; index < 8; ++index) {
        mz[index] = message[index];
    }
    element_to_bytes(mz + 8, z);
    mz[8 + zr_length] = '\0';

    // compute C*
    res->Cstar = (unsigned char*)malloc(SHA256_DIGEST_LENGTH +1);
    for (signed long int i = 0; i < 8 + zr_length; ++i) {
        int Cvalue = (int)mz[i] ^ (int)H_1[i];
        res->Cstar[i] = (unsigned char)Cvalue;
    }
    res->Cstar[SHA256_DIGEST_LENGTH] = '\0';

    // compute u2^z1
    element_t u2_z1;
    element_init_GT(u2_z1, pairing);
    element_pow_zn(u2_z1, u2, z1);

    // compute v2^z2
    element_t v2_z2;
    element_init_GT(v2_z2, pairing);
    element_pow_zn(v2_z2, v2, z2);

    // compute u2^z1*v2^z2
    element_t u2_z1_v2_z2;
    element_init_GT(u2_z1_v2_z2, pairing);
    element_mul(u2_z1_v2_z2, u2_z1, v2_z2);

    // change message to m
    unsigned char hash_bytes[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message, 8);
    SHA256_Final(hash_bytes, &sha256);
    element_t m;
    element_init_G1(m, pairing);
    element_from_hash(m, hash_bytes, SHA256_DIGEST_LENGTH);

    // compute m^z
    element_t m_z;
    element_init_G1(m_z, pairing);
    element_pow_zn(m_z, m, z);

    // compute C1=m^z*H2(u2^z1*v2^z2)
    element_t C1;
    element_init_G1(C1, pairing);
    element_mul(C1, m_z, H2(u2_z1_v2_z2));
    res->insertComponent("C1", "G1", C1);

    // compute awk
//    vector<signed long int> *awk = computeA(J);
    vector<signed long int> *awk = testJ();

    // compute tw
    element_s *tw = computeT(awk);

    // compute z1/tw
    element_t z1_tw;
    element_init_Zr(z1_tw, pairing);
    element_div(z1_tw, z1, tw);

    // compute z2/tw
    element_t z2_tw;
    element_init_Zr(z2_tw, pairing);
    element_div(z2_tw, z2, tw);

    // compute C2=g^alpha^(z1/tw)
    element_t C2;
    element_init_G1(C2, pairing);
    element_pow_zn(C2, g_alpha, z1_tw);
    res->insertComponent("C2", "G1", C2);

    // compute C3=g^(z2/tw)
    element_t C3;
    element_init_G1(C3, pairing);
    element_pow_zn(C3, g, z2_tw);
    res->insertComponent("C3", "G1", C3);

    // compute C2'=g^alpha'^(z1/tw)
    element_t C2_;
    element_init_G1(C2_, pairing);
    element_pow_zn(C2_, g_alpha_, z1_tw);
    res->insertComponent("C2_", "G1", C2_);

    // compute C3'=g^z
    element_t C3_;
    element_init_G1(C3_, pairing);
    element_pow_zn(C3_, g, z);
    res->insertComponent("C3_", "G1", C3_);

    // compute z1+z2
    element_t z1_z2;
    element_init_Zr(z1_z2, pairing);
    element_add(z1_z2, z1, z2);

    // init------
    element_t is_wks_tw;
    element_init_Zr(is_wks_tw, pairing);
    element_t Ri;
    element_init_G1(Ri, pairing);
    element_t Ri_is_wks_tw;
    element_init_G1(Ri_is_wks_tw, pairing);
    element_t Ris;
    element_init_G1(Ris, pairing);
    // init------

    // compute C4
    for (signed long int m = 0; m < X->size(); ++m) {
        element_s *is_wks = computeIWK(X->at(m), J);

        element_div(is_wks_tw, is_wks, tw);

        string str = "R";
        char num[21];
        sprintf(num, "%ld", X->at(m));
        element_set(Ri, public_key->getComponent(str + num));

        element_pow_zn(Ri_is_wks_tw, Ri, is_wks_tw);

        if (m == 0) {
            element_set(Ris, Ri_is_wks_tw);
        } else {
            element_mul(Ris, Ris, Ri_is_wks_tw);
        }
    }
    element_t W1_Ris;
    element_init_G1(W1_Ris, pairing);
    element_mul(W1_Ris, W1, Ris);
    element_t C4;
    element_init_G1(C4, pairing);
    element_pow_zn(C4, W1_Ris, z1_z2);
    res->insertComponent("C4", "G1", C4);

    // compute C5
    for (signed long int m = 0; m < Y->size(); ++m) {
        element_s *is_wks = computeIWK(Y->at(m), J);

        element_div(is_wks_tw, is_wks, tw);

        string str = "R";
        char num[21];
        sprintf(num, "%ld", Y->at(m));
        element_set(Ri, public_key->getComponent(str + num));

        element_pow_zn(Ri_is_wks_tw, Ri, is_wks_tw);

        if (m == 0) {
            element_set(Ris, Ri_is_wks_tw);
        } else {
            element_mul(Ris, Ris, Ri_is_wks_tw);
        }
    }
    element_t W2_Ris;
    element_init_G1(W2_Ris, pairing);
    element_mul(W2_Ris, W2, Ris);
    element_t C5;
    element_init_G1(C5, pairing);
    element_pow_zn(C5, W2_Ris, z1_z2);
    res->insertComponent("C5", "G1", C5);

    return res;
}

Key* DET::keyGen(Key *public_key, Key *master_key, vector<signed long int> *X_, vector<signed long int> *Y_) {
    Key *res = new Key(Key::SECRET);

    // obtain public params
    element_t u1, v1, u2, v2;
    element_init_same_as(u1, public_key->getComponent("u1"));
    element_set(u1, public_key->getComponent("u1"));
    element_init_same_as(v1, public_key->getComponent("v1"));
    element_set(v1, public_key->getComponent("v1"));
    element_init_same_as(u2, public_key->getComponent("u2"));
    element_set(u2, public_key->getComponent("u2"));
    element_init_same_as(v2, public_key->getComponent("v2"));
    element_set(v2, public_key->getComponent("v2"));
    element_t g_alpha, g_alpha_;
    element_init_same_as(g_alpha, public_key->getComponent("g_alpha"));
    element_set(g_alpha, public_key->getComponent("g_alpha"));
    element_init_same_as(g_alpha_, public_key->getComponent("g_alpha_"));
    element_set(g_alpha_, public_key->getComponent("g_alpha_"));
    element_t g;
    element_init_same_as(g, public_key->getComponent("g"));
    element_set(g, public_key->getComponent("g"));
    element_t W1, W2;
    element_init_same_as(W1, public_key->getComponent("W1"));
    element_set(W1, public_key->getComponent("W1"));
    element_init_same_as(W2, public_key->getComponent("W2"));
    element_set(W2, public_key->getComponent("W2"));

    // obtain master key
    element_t alpha, alpha_, gamma1, gamma2, gamma3;
    element_init_same_as(alpha, master_key->getComponent("alpha"));
    element_set(alpha, master_key->getComponent("alpha"));
    element_init_same_as(alpha_, master_key->getComponent("alpha_"));
    element_set(alpha_, master_key->getComponent("alpha_"));
    element_init_same_as(gamma1, master_key->getComponent("gamma1"));
    element_set(gamma1, master_key->getComponent("gamma1"));
    element_init_same_as(gamma2, master_key->getComponent("gamma2"));
    element_set(gamma2, master_key->getComponent("gamma2"));
    element_init_same_as(gamma3, master_key->getComponent("gamma3"));
    element_set(gamma3, master_key->getComponent("gamma3"));

    // randomly s
    element_t s;
    element_init_Zr(s, pairing);
    element_random(s);

    // compute s1, s2, s3
    element_t s1, s2, s3;
    element_init_Zr(s1, pairing);
    element_init_Zr(s2, pairing);
    element_init_Zr(s3, pairing);
    element_add(s1, gamma1, s);
    element_add(s2, gamma2, s);
    element_add(s3, gamma3, s);

    // compute axi' and ayj'
//    vector<signed long int> *axi_ = computeA(X_);
//    vector<signed long int> *ayj_ = computeA(Y_);
//    vector<signed long int> *axi_ = testX();
//    vector<signed long int> *ayj_ = testY();

    // compute tx' and ty'
//    element_s *tx_ = computeT(axi_);
//    element_s *ty_ = computeT(ayj_);
    element_t tx_, ty_;
    element_init_Zr(tx_, pairing);
    element_init_Zr(ty_, pairing);
    element_random(tx_);
    element_random(ty_);
    res->insertComponent("tx_", "ZR", tx_);
    res->insertComponent("ty_", "ZR", ty_);

    // compute s/tx', s/ty'
    element_t s_tx_, s_ty_;
    element_init_Zr(s_tx_, pairing);
    element_init_Zr(s_ty_, pairing);
    element_div(s_tx_, s, tx_);
    element_div(s_ty_, s, ty_);

    // compute sk1=g^alpha^(s/tx')
    element_t sk1;
    element_init_G1(sk1, pairing);
    element_pow_zn(sk1, g_alpha, s_tx_);
    res->insertComponent("sk1", "G1", sk1);

    // compute sk2=g^alpha^(s/ty')
    element_t sk2;
    element_init_G1(sk2, pairing);
    element_pow_zn(sk2, g_alpha, s_ty_);
    res->insertComponent("sk2", "G1", sk2);

    // compute sk1'=g^alpha'^(s/tx')
    element_t sk1_;
    element_init_G1(sk1_, pairing);
    element_pow_zn(sk1_, g_alpha_, s_tx_);
    res->insertComponent("sk1_", "G1", sk1_);

    // compute sk2'=g^alpha'^(s/ty')
    element_t sk2_;
    element_init_G1(sk2_, pairing);
    element_pow_zn(sk2_, g_alpha_, s_ty_);
    res->insertComponent("sk2_", "G1", sk2_);

    // compute W1^s1
    element_t W1_s1;
    element_init_G1(W1_s1, pairing);
    element_pow_zn(W1_s1, W1, s1);

    // compute alpha*s2
    element_t alpha_s2;
    element_init_Zr(alpha_s2, pairing);
    element_mul(alpha_s2, alpha, s2);

    // compute W1^(alpha*s2)
    element_t W1_alpha_s2;
    element_init_G1(W1_alpha_s2, pairing);
    element_pow_zn(W1_alpha_s2, W1, alpha_s2);

    // compute alpha'*s3
    element_t alpha__s3;
    element_init_Zr(alpha__s3, pairing);
    element_mul(alpha__s3, alpha_, s3);

    // compute W1^(alpha'*s3)
    element_t W1_alpha__s3;
    element_init_G1(W1_alpha__s3, pairing);
    element_pow_zn(W1_alpha__s3, W1, alpha__s3);

    // compute W2^s1
    element_t W2_s1;
    element_init_G1(W2_s1, pairing);
    element_pow_zn(W2_s1, W2, s1);

    // compute W2^(alpha*s2)
    element_t W2_alpha_s2;
    element_init_G1(W2_alpha_s2, pairing);
    element_pow_zn(W2_alpha_s2, W2, alpha_s2);

    // compute W2^(alpha'*s3)
    element_t W2_alpha__s3;
    element_init_G1(W2_alpha__s3, pairing);
    element_pow_zn(W2_alpha__s3, W2, alpha__s3);

    // init------
    element_t ri;
    element_init_Zr(ri, pairing);
    element_t s_ri;
    element_init_Zr(s_ri, pairing);
    element_t i_n;
    element_init_Zr(i_n, pairing);
    element_t s_ri_i_n;
    element_init_Zr(s_ri_i_n, pairing);
    element_t g_s_ri_i_n;
    element_init_G1(g_s_ri_i_n, pairing);

    element_t s_alpha_ri_i_n;
    element_init_Zr(s_alpha_ri_i_n, pairing);
    element_t g_s_alpha_ri_i_n;
    element_init_G1(g_s_alpha_ri_i_n, pairing);

    element_t s_alpha__ri_i_n;
    element_init_Zr(s_alpha__ri_i_n, pairing);
    element_t g_s_alpha__ri_i_n;
    element_init_G1(g_s_alpha__ri_i_n, pairing);

    element_t n_e;
    element_init_Zr(n_e, pairing);
    element_t i_e;
    element_init_Zr(i_e, pairing);

    element_t TTg_s_ri_i_n;
    element_init_G1(TTg_s_ri_i_n, pairing);
    element_t TTg_s_alpha_ri_i_n;
    element_init_G1(TTg_s_alpha_ri_i_n, pairing);
    element_t TTg_s_alpha__ri_i_n;
    element_init_G1(TTg_s_alpha__ri_i_n, pairing);

    element_t sk3n;
    element_init_G1(sk3n, pairing);
    element_t sk4n;
    element_init_G1(sk4n, pairing);
    element_t sk3n_;
    element_init_G1(sk3n_, pairing);
    element_t sk4n_;
    element_init_G1(sk4n_, pairing);
    element_t sk3n__;
    element_init_G1(sk3n__, pairing);
    element_t sk4n__;
    element_init_G1(sk4n__, pairing);

    string sk_str = "sk";
    string r_str = "r";

    for (signed long int n = 0; n <= L1; ++n) {
        element_set_si(n_e, n);

        char n_str[21];
        sprintf(n_str, "%ld", n);

        for (signed long int l = 0; l < X_->size(); ++l) {
            signed long int i = X_->at(l);
            element_set_si(i_e, i);

            element_pow_zn(i_n, i_e, n_e);

            char i_str[21];
            sprintf(i_str, "%ld", i);
            element_set(ri, master_key->getComponent(r_str + i_str));

            element_mul(s_ri, s, ri);

            element_mul(s_ri_i_n, s_ri, i_n);

            element_pow_zn(g_s_ri_i_n, g, s_ri_i_n);

            if (l == 0) {
                element_set(TTg_s_ri_i_n, g_s_ri_i_n);
            } else {
                element_mul(TTg_s_ri_i_n, TTg_s_ri_i_n, g_s_ri_i_n);
            }

            element_mul(s_alpha_ri_i_n, s_ri_i_n, alpha);

            element_pow_zn(g_s_alpha_ri_i_n, g, s_alpha_ri_i_n);

            if (l == 0) {
                element_set(TTg_s_alpha_ri_i_n, g_s_alpha_ri_i_n);
            } else {
                element_mul(TTg_s_alpha_ri_i_n, TTg_s_alpha_ri_i_n, g_s_alpha_ri_i_n);
            }

            element_mul(s_alpha__ri_i_n, s_ri_i_n, alpha_);

            element_pow_zn(g_s_alpha__ri_i_n, g, s_alpha__ri_i_n);

            if (l == 0) {
                element_set(TTg_s_alpha__ri_i_n, g_s_alpha__ri_i_n);
            } else {
                element_mul(TTg_s_alpha__ri_i_n, TTg_s_alpha__ri_i_n, g_s_alpha__ri_i_n);
            }
        }

        element_mul(sk3n, W1_s1, TTg_s_ri_i_n);
        res->insertComponent(sk_str + "3" + n_str, "G1", sk3n);
        element_mul(sk3n_, W1_alpha_s2, TTg_s_alpha_ri_i_n);
        res->insertComponent(sk_str + "3" + n_str + "_", "G1", sk3n_);
        element_mul(sk3n__, W1_alpha__s3, TTg_s_alpha__ri_i_n);
        res->insertComponent(sk_str + "3" + n_str + "__", "G1", sk3n__);

        for (signed long int l = 0; l < Y_->size(); ++l) {
            signed long int i = Y_->at(l);
            element_set_si(i_e, i);

            element_pow_zn(i_n, i_e, n_e);

            char i_str[21];
            sprintf(i_str, "%ld", i);
            element_set(ri, master_key->getComponent(r_str + i_str));

            element_mul(s_ri, s, ri);

            element_mul(s_ri_i_n, s_ri, i_n);

            element_pow_zn(g_s_ri_i_n, g, s_ri_i_n);

            if (l == 0) {
                element_set(TTg_s_ri_i_n, g_s_ri_i_n);
            } else {
                element_mul(TTg_s_ri_i_n, TTg_s_ri_i_n, g_s_ri_i_n);
            }

            element_mul(s_alpha_ri_i_n, s_ri_i_n, alpha);

            element_pow_zn(g_s_alpha_ri_i_n, g, s_alpha_ri_i_n);

            if (l == 0) {
                element_set(TTg_s_alpha_ri_i_n, g_s_alpha_ri_i_n);
            } else {
                element_mul(TTg_s_alpha_ri_i_n, TTg_s_alpha_ri_i_n, g_s_alpha_ri_i_n);
            }

            element_mul(s_alpha__ri_i_n, s_ri_i_n, alpha_);

            element_pow_zn(g_s_alpha__ri_i_n, g, s_alpha__ri_i_n);

            if (l == 0) {
                element_set(TTg_s_alpha__ri_i_n, g_s_alpha__ri_i_n);
            } else {
                element_mul(TTg_s_alpha__ri_i_n, TTg_s_alpha__ri_i_n, g_s_alpha__ri_i_n);
            }
        }

        element_mul(sk4n, W2_s1, TTg_s_ri_i_n);
        res->insertComponent(sk_str + "4" + n_str, "G1", sk4n);
        element_mul(sk4n_, W2_alpha_s2, TTg_s_alpha_ri_i_n);
        res->insertComponent(sk_str + "4" + n_str + "_", "G1", sk4n_);
        element_mul(sk4n__, W2_alpha__s3, TTg_s_alpha__ri_i_n);
        res->insertComponent(sk_str + "4" + n_str + "__", "G1", sk4n__);

    }

    return res;
}

Key* DET::trapdoor(Key *secret_key, vector<signed long int> *X_, vector<signed long int> *Y_) {
    Key *res = new Key(Key::SECRET);

    res->insertComponent("td1", "G1", secret_key->getComponent("sk1_"));
    res->insertComponent("td2", "G1", secret_key->getComponent("sk2_"));

    for (signed long int i = 0; i <= L1; ++i) {
        string str = "td";
        string sstr = "sk";
        char num[21];
        sprintf(num, "%ld", i);

        res->insertComponent(str + "3" + num, "G1", secret_key->getComponent(sstr + "3" + num));
        res->insertComponent(str + "3" + num + "_", "G1", secret_key->getComponent(sstr + "3" + num + "__"));
        res->insertComponent(str + "4" + num, "G1", secret_key->getComponent(sstr + "4" + num));
        res->insertComponent(str + "4" + num + "_", "G1", secret_key->getComponent(sstr + "4" + num + "__"));
    }

    return res;
}