//
// Created by alan on 19-10-24.
//

#include "CP_ABEETaC.h"

element_s* CP_ABEETaC::H1(element_s *e) {
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

unsigned char* CP_ABEETaC::H2(unsigned char* str, signed long int len) {
    unsigned char *hash_str_byte = (unsigned char*)malloc(SHA256_DIGEST_LENGTH + 1);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, len);
    SHA256_Final(hash_str_byte, &sha256);
    hash_str_byte[SHA256_DIGEST_LENGTH] = '\0';

    return hash_str_byte;
}

element_s* CP_ABEETaC::computeXsub(Ciphertext_CET *ciphertext, SecretKey *key_x, string post_s) {
    // compute wi
    utils util;
    map<signed long int, signed long int>* matchedAttributes = util.attributesMatching(key_x->getAttributes(), ciphertext->getAccessStructure()->getRho());
    element_t_matrix* attributesMatrix = util.getAttributesMatrix(ciphertext->getAccessStructure()->getM(), matchedAttributes);
    map<signed long int, signed long int>* x_to_attributes = util.xToAttributes(ciphertext->getAccessStructure()->getM(), matchedAttributes);
    element_t_matrix* inverse_M = util.inverse(attributesMatrix);
    element_t_vector* unit = util.getCoordinateAxisUnitVector(inverse_M);
    element_t_vector* x = new element_t_vector(inverse_M->col(), inverse_M->getElement(0, 0));
    extend_math_operation emo;
    signed long int type = emo.gaussElimination(x, inverse_M, unit);
    if (-1 == type) {
        return NULL;
    }

    // obtain C', K, L
    element_t C_, K, L;
    element_init_same_as(C_, ciphertext->getComponent("C_"));
    element_set(C_, ciphertext->getComponent("C_"));
    element_init_same_as(K, key_x->getComponent("K" + post_s));
    element_set(K, key_x->getComponent("K" + post_s));
    element_init_same_as(L, key_x->getComponent("L" + post_s));
    element_set(L, key_x->getComponent("L" + post_s));

    // compute e(C',K)
    element_t e_C_K;
    element_init_GT(e_C_K, pairing);
    element_pairing(e_C_K, C_, K);

    element_t denominator;
    element_init_GT(denominator, pairing);

    // init------
    element_t Ci, Di, Ki;
    element_init_G1(Ci, pairing);
    element_init_G1(Di, pairing);
    element_init_G1(Ki, pairing);
    element_t e_CiL, e_DiKi;
    element_init_GT(e_CiL, pairing);
    element_init_GT(e_DiKi, pairing);
    element_t e_e;
    element_init_GT(e_e, pairing);
    element_t factor_denominator;
    element_init_GT(factor_denominator, pairing);
    // init------
    map<signed long int, signed long int>::iterator it;
    for (it = matchedAttributes->begin(); it != matchedAttributes->end(); ++it) {
        // get attribute
        string attr = (*key_x->getAttributes())[it->second];

        // get Ci, Di, Ki
        element_set(Ci, ciphertext->getComponent("C" + attr));
        element_set(Di, ciphertext->getComponent("D" + attr));
        element_set(Ki, key_x->getComponent("K" + attr + post_s));

        // compute e(Ci,L), e(Di,Ki)
        element_pairing(e_CiL, Ci, L);
        element_pairing(e_DiKi, Di, Ki);

        // compute factor_denominator
        element_mul(e_e, e_CiL, e_DiKi);
        // get wi
        signed long int attribute_index = it->second;
        map<signed long int, signed long int>::iterator itt = x_to_attributes->find(attribute_index);
        signed long int x_index = itt->second;
        element_pow_zn(factor_denominator, e_e, x->getElement(x_index));

        if (it == matchedAttributes->begin()) {
            element_set(denominator, factor_denominator);
        } else {
            element_mul(denominator, denominator, factor_denominator);
        }
    }

    element_t *res = new element_t[1];
    element_init_GT(*res, pairing);
    element_div(*res, e_C_K, denominator);

    return *res;
}

unsigned char* CP_ABEETaC::computeH2Input(element_s *e_gg_alpha__s, Ciphertext_CET *ciphertext) {
    unsigned char* res = (unsigned char*)malloc(gt_length + (3 * g1_length) + (ciphertext->getAccessStructure()->getM()->row() * g1_length * 2) + 1);
    signed long int str_index = 0;

    element_to_bytes(res + str_index, e_gg_alpha__s);
    str_index += gt_length;

    // add C
    element_to_bytes(res + str_index, ciphertext->getComponent("C"));
    str_index += g1_length;

    // add C'
    element_to_bytes(res + str_index, ciphertext->getComponent("C_"));
    str_index += g1_length;

    // add C''
    element_to_bytes(res + str_index, ciphertext->getComponent("C__"));
    str_index += g1_length;

    for (signed long int i = 0; i < ciphertext->getAccessStructure()->getM()->row(); ++i) {
        map<signed long int, string>::iterator it = ciphertext->getAccessStructure()->getRho()->find(i);
        string attr = it->second;
        element_to_bytes(res + str_index, ciphertext->getComponent("C" + attr));
        str_index += g1_length;
        element_to_bytes(res + str_index, ciphertext->getComponent("D" + attr));
        str_index += g1_length;
    }
    res[str_index] = '\0';

    return res;
}

CP_ABEETaC::CP_ABEETaC() {
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

vector<Key*>* CP_ABEETaC::setUp(vector<string> *attributes) {
    // randomly choose g
    element_t g;
    element_init_G1(g, pairing);
    element_random(g);

    // randomly choose alpha, alpha', a
    element_t alpha, alpha_, a;
    element_init_Zr(alpha, pairing);
    element_init_Zr(alpha_, pairing);
    element_init_Zr(a, pairing);
    element_random(alpha);
    element_random(alpha_);
    element_random(a);

    // compute e_gg
    element_t e_gg;
    element_init_GT(e_gg, pairing);
    element_pairing(e_gg, g, g);

    // compute e_gg_alpha
    element_t e_gg_alpha;
    element_init_GT(e_gg_alpha, pairing);
    element_pow_zn(e_gg_alpha, e_gg, alpha);

    // compute e_gg_alpha_
    element_t e_gg_alpha_;
    element_init_GT(e_gg_alpha_, pairing);
    element_pow_zn(e_gg_alpha_, e_gg, alpha_);

    // compute g^a
    element_t g_a;
    element_init_G1(g_a, pairing);
    element_pow_zn(g_a, g, a);

    // compute g^alpha
    element_t g_alpha;
    element_init_G1(g_alpha, pairing);
    element_pow_zn(g_alpha, g, alpha);

    // compute g^alpha'
    element_t g_alpha_;
    element_init_G1(g_alpha_, pairing);
    element_pow_zn(g_alpha_, g, alpha_);

    Key *master_key = new Key(Key::MASTER);
    Key *public_key = new Key(Key::PUBLIC);

    master_key->insertComponent("g_alpha", "G1", g_alpha);
    master_key->insertComponent("g_alpha_", "G1", g_alpha_);
    public_key->insertComponent("g", "G1", g);
    public_key->insertComponent("e_gg_alpha", "GT", e_gg_alpha);
    public_key->insertComponent("e_gg_alpha_", "GT", e_gg_alpha_);
    public_key->insertComponent("g_a", "G1", g_a);
    element_t hi;
    element_init_G1(hi, pairing);
    for (signed long int i = 0; i < attributes->size(); ++i) {
        element_random(hi);
        public_key->insertComponent("h" + attributes->at(i), "G1", hi);
    }

    vector<Key*> *res = new vector<Key*>(2);
    (*res)[0] = master_key;
    (*res)[1] = public_key;

    return res;
}

Ciphertext_CET* CP_ABEETaC::encrypt(Key *public_key, access_structure *A, unsigned char *message) {
    Ciphertext_CET *res = new Ciphertext_CET(A->getM(), A->getRho());

    utils util;

    // obtain public parameters
    element_t g, e_gg_alpha, e_gg_alpha_, g_a;
    element_init_same_as(g, public_key->getComponent("g"));
    element_set(g, public_key->getComponent("g"));
    element_init_same_as(e_gg_alpha, public_key->getComponent("e_gg_alpha"));
    element_set(e_gg_alpha, public_key->getComponent("e_gg_alpha"));
    element_init_same_as(e_gg_alpha_, public_key->getComponent("e_gg_alpha_"));
    element_set(e_gg_alpha_, public_key->getComponent("e_gg_alpha_"));
    element_init_same_as(g_a, public_key->getComponent("g_a"));
    element_set(g_a, public_key->getComponent("g_a"));

    // randomly choose s to be shared
    element_t s;
    element_init_Zr(s, pairing);
    element_random(s);

    // generate vector y
    element_t_vector *y = new element_t_vector(A->getM()->col(), zr_sample);
    element_set(y->getElement(0), s);
    for (signed long int i = 1; i < y->length(); ++i) {
        element_random(y->getElement(i));
    }

    // compute shares
    extend_math_operation emo;
    element_t_vector *lambda = emo.multiply(A->getM(), y);

    // randomly choose u
    element_t u;
    element_init_Zr(u, pairing);
    element_random(u);

    // change message to m
    unsigned char hash_bytes[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message, 8);
    SHA256_Final(hash_bytes, &sha256);
    element_t m;
    element_init_G1(m, pairing);
    element_from_hash(m, hash_bytes, SHA256_DIGEST_LENGTH);

    // compute m^u
    element_t m_u;
    element_init_G1(m_u, pairing);
    element_pow_zn(m_u, m, u);

    // compute e(g,g)^(alpha*s)
    element_t e_gg_alpha_s;
    element_init_GT(e_gg_alpha_s, pairing);
    element_pow_zn(e_gg_alpha_s, e_gg_alpha, s);

    // compute e(g,g)^(alpha'*s)
    element_t e_gg_alpha__s;
    element_init_GT(e_gg_alpha__s, pairing);
    element_pow_zn(e_gg_alpha__s, e_gg_alpha_, s);

    // compute C
    element_t C;
    element_init_G1(C, pairing);
    element_mul(C, m_u, H1(e_gg_alpha_s));
    res->insertComponent("C", "G1", C);

    // compute C'=g^s
    element_t C_;
    element_init_G1(C_, pairing);
    element_pow_zn(C_, g, s);
    res->insertComponent("C_", "G1", C_);

    // compute C''=g^u
    element_t C__;
    element_init_G1(C__, pairing);
    element_pow_zn(C__, g, u);
    res->insertComponent("C__", "G1", C__);

    // init
    element_t ri, neg_ri;
    element_init_Zr(ri, pairing);
    element_init_Zr(neg_ri, pairing);
    element_t Ci, Di;
    element_init_G1(Ci, pairing);
    element_init_G1(Di, pairing);
    element_t g_a_lambdai, hrhoi, hrhoi_neg_ri;
    element_init_G1(g_a_lambdai, pairing);
    element_init_G1(hrhoi, pairing);
    element_init_G1(hrhoi_neg_ri, pairing);
    // end init
    for (signed long int i = 0; i < A->getM()->row(); ++i) {
        // randomly choose ri
        element_random(ri);

        // compute -ri
        element_neg(neg_ri, ri);

        // compute g^(a*lambdai)
        element_pow_zn(g_a_lambdai, g_a, lambda->getElement(i));

        // obtain hrhoi
        map<signed long int, string>::iterator it = A->getRho()->find(i);
        string attr = it->second;
        element_set(hrhoi, public_key->getComponent("h" + attr));

        // compute hrhoi^(-ri)
        element_pow_zn(hrhoi_neg_ri, hrhoi, neg_ri);

        // compute Ci=g^(a*lambdai)*hrhoi^(-ri)
        element_mul(Ci, g_a_lambdai, hrhoi_neg_ri);
        res->insertComponent("C" + attr, "G1", Ci);

        // compute Di=g^ri
        element_pow_zn(Di, g, ri);
        res->insertComponent("D" + attr, "G1", Di);
    }

    // compute C*
    unsigned char *mu = (unsigned char*)malloc(8 + zr_length + 1);
    for (signed long int index = 0; index < 8; ++index) {
        mu[index] = message[index];
    }
    element_to_bytes(mu + 8, u);
    mu[8 + zr_length] = '\0';
    unsigned char *str = computeH2Input(e_gg_alpha__s, res);
    unsigned char *H_2 = H2(str, gt_length + (3 * g1_length) + (A->getM()->row() * g1_length * 2) + 1);
    // compute C*
    res->Cstar = (unsigned char*)malloc(SHA256_DIGEST_LENGTH +1);
    for (signed long int i = 0; i < 8 + zr_length; ++i) {
        int Cvalue = (int)mu[i] ^ (int)H_2[i];
        res->Cstar[i] = (unsigned char)Cvalue;
    }
    res->Cstar[SHA256_DIGEST_LENGTH] = '\0';

    return res;
}

SecretKey* CP_ABEETaC::keyGen(Key *public_key, Key *master_key, vector<string> *attributes) {
    SecretKey *res = new SecretKey(attributes);

    // obtain public parameters
    element_t g, g_a;
    element_init_same_as(g, public_key->getComponent("g"));
    element_set(g, public_key->getComponent("g"));
    element_init_same_as(g_a, public_key->getComponent("g_a"));
    element_set(g_a, public_key->getComponent("g_a"));

    // obtain master key
    element_t g_alpha, g_alpha_;
    element_init_same_as(g_alpha, master_key->getComponent("g_alpha"));
    element_set(g_alpha, master_key->getComponent("g_alpha"));
    element_init_same_as(g_alpha_, master_key->getComponent("g_alpha_"));
    element_set(g_alpha_, master_key->getComponent("g_alpha_"));

    // randomly choose t, t'
    element_t t, t_;
    element_init_Zr(t, pairing);
    element_init_Zr(t_, pairing);
    element_random(t);
    element_random(t_);

    // compute g^(a*t)
    element_t g_a_t;
    element_init_G1(g_a_t, pairing);
    element_pow_zn(g_a_t, g_a, t);

    // compute g^(a*t')
    element_t g_a_t_;
    element_init_G1(g_a_t_, pairing);
    element_pow_zn(g_a_t_, g_a, t_);

    // compute K=g^alpha*g^(a*t)
    element_t K;
    element_init_G1(K, pairing);
    element_mul(K, g_alpha, g_a_t);
    res->insertComponent("K", "G1", K);

    // compute K'=g^alpha'*g^(a*t')
    element_t K_;
    element_init_G1(K_, pairing);
    element_mul(K_, g_alpha_, g_a_t_);
    res->insertComponent("K_", "G1", K_);

    // compute L=g^t
    element_t L;
    element_init_G1(L, pairing);
    element_pow_zn(L, g, t);
    res->insertComponent("L", "G1", L);

    // compute L'=g^t'
    element_t L_;
    element_init_G1(L_, pairing);
    element_pow_zn(L_, g, t_);
    res->insertComponent("L_", "G1", L_);

    // init------
    element_t Kx, Kx_;
    element_init_G1(Kx, pairing);
    element_init_G1(Kx_, pairing);
    element_t hx;
    element_init_G1(hx, pairing);
    // init------
    for (signed long int i = 0; i < attributes->size(); ++i) {
        // obtain hx
        element_set(hx, public_key->getComponent("h" + attributes->at(i)));

        // compute Kx=hx^t
        element_pow_zn(Kx, hx, t);
        res->insertComponent("K" + attributes->at(i), "G1", Kx);

        // compute Kx'=hx^t'
        element_pow_zn(Kx_, hx, t_);
        res->insertComponent("K" + attributes->at(i) + "_", "G1", Kx_);
    }

    return res;
}

SecretKey* CP_ABEETaC::trapdoor(Key *public_key, Key *master_key, vector<string> *attributes) {
    SecretKey *res = new SecretKey(attributes);

    // obtain public parameters
    element_t g, g_a;
    element_init_same_as(g, public_key->getComponent("g"));
    element_set(g, public_key->getComponent("g"));
    element_init_same_as(g_a, public_key->getComponent("g_a"));
    element_set(g_a, public_key->getComponent("g_a"));

    // obtain master key
    element_t g_alpha;
    element_init_same_as(g_alpha, master_key->getComponent("g_alpha"));
    element_set(g_alpha, master_key->getComponent("g_alpha"));

    // randomly choose t
    element_t t;
    element_init_Zr(t, pairing);
    element_random(t);

    // compute g^(a*t)
    element_t g_a_t;
    element_init_G1(g_a_t, pairing);
    element_pow_zn(g_a_t, g_a, t);

    // compute K=g^alpha*g^(a*t)
    element_t K;
    element_init_G1(K, pairing);
    element_mul(K, g_alpha, g_a_t);
    res->insertComponent("K", "G1", K);

    // compute L=g^t
    element_t L;
    element_init_G1(L, pairing);
    element_pow_zn(L, g, t);
    res->insertComponent("L", "G1", L);

    // init------
    element_t Kx;
    element_init_G1(Kx, pairing);
    element_t hx;
    element_init_G1(hx, pairing);
    // init------
    for (signed long int i = 0; i < attributes->size(); ++i) {
        // obtain hx
        element_set(hx, public_key->getComponent("h" + attributes->at(i)));

        // compute Kx=hx^t
        element_pow_zn(Kx, hx, t);
        res->insertComponent("K" + attributes->at(i), "G1", Kx);
    }

    return res;
}

bool* CP_ABEETaC::test(Key *public_key, Ciphertext_CET *CTA, SecretKey *TdSA, Ciphertext_CET *CTB, SecretKey *TdSB) {
    element_s *XsubA = computeXsub(CTA, TdSA, "");
    element_s *XsubB = computeXsub(CTB, TdSB, "");

    // compute XA
    element_t XA;
    element_init_G1(XA, pairing);
    element_div(XA, CTA->getComponent("C"), H1(XsubA));
//    cout << "XA" << endl;

    // compute XB
    element_t XB;
    element_init_G1(XB, pairing);
    element_div(XB, CTB->getComponent("C"), H1(XsubB));
//    cout << "XB" << endl;

    // compute e(CA'',XB)
    element_t e_CA__XB;
    element_init_GT(e_CA__XB, pairing);
    element_pairing(e_CA__XB, CTA->getComponent("C__"), XB);

    // compute e(CB'',XA)
    element_t e_CB__XA;
    element_init_GT(e_CB__XA, pairing);
    element_pairing(e_CB__XA, CTB->getComponent("C__"), XA);

    bool *res = new bool();

    if (element_cmp(e_CA__XB, e_CB__XA) == 0) {
        *res = true;
        return res;
    } else {
        *res = false;
        return res;
    }
}

unsigned char* CP_ABEETaC::decrypt(Key *public_key, Ciphertext_CET *ciphertext_cet, SecretKey *secret_key) {
    element_s *Xsub = computeXsub(ciphertext_cet, secret_key, "");
    element_s *Xsub_ = computeXsub(ciphertext_cet, secret_key, "_");

    unsigned char *str = computeH2Input(Xsub_, ciphertext_cet);
    unsigned char *H_2 = H2(str, gt_length + (3 * g1_length) + (ciphertext_cet->getAccessStructure()->getM()->row() * g1_length * 2) + 1);

    unsigned char *res = (unsigned char*)malloc(8 + 1);
    res[8] = '\0';
    unsigned char *u_bytes = (unsigned char*)malloc(zr_length + 1);
    u_bytes[zr_length] = '\0';

    for (signed long int i = 0; i < 8; ++i) {
        int mzvalue = (int)ciphertext_cet->Cstar[i] ^ (int)H_2[i];
        res[i] = (unsigned char)mzvalue;
    }
    for (signed long int i = 8; i < 8 + zr_length; ++i) {
        int mzvalue = (int)ciphertext_cet->Cstar[i] ^ (int)H_2[i];
        u_bytes[i - 8] = (unsigned char)mzvalue;
    }

    element_t u;
    element_init_Zr(u, pairing);
    element_from_bytes(u, u_bytes);
//    element_printf("恢复出来的u为：%B\n", u);

    // verify
    // obtain g
    element_t g;
    element_init_same_as(g, public_key->getComponent("g"));
    element_set(g, public_key->getComponent("g"));
    // compute g^u
    element_t g_u;
    element_init_G1(g_u, pairing);
    element_pow_zn(g_u, g, u);
    // obtain C''
    element_t C__;
    element_init_same_as(C__, ciphertext_cet->getComponent("C__"));
    element_set(C__, ciphertext_cet->getComponent("C__"));
    if (element_cmp(g_u, C__) != 0) {
        return NULL;
    }

    // verify
    // change res to m
    unsigned char hash_bytes[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, res, 8);
    SHA256_Final(hash_bytes, &sha256);
    element_t m;
    element_init_G1(m, pairing);
    element_from_hash(m, hash_bytes, SHA256_DIGEST_LENGTH);
    // compute m^u
    element_t m_u;
    element_init_G1(m_u, pairing);
    element_pow_zn(m_u, m, u);
    // compute m^u*H1(Xsub)
    element_t m_u_H1;
    element_init_G1(m_u_H1, pairing);
    element_mul(m_u_H1, m_u, H1(Xsub));
    // obtain C
    element_t C;
    element_init_same_as(C, ciphertext_cet->getComponent("C"));
    element_set(C, ciphertext_cet->getComponent("C"));
    if (element_cmp(C, m_u_H1) != 0) {
        return NULL;
    }

    return res;
}