//
// Created by alan on 19-10-24.
//

#include "LU_CP_ABEEaVT.h"

element_s* LU_CP_ABEEaVT::H1(element_s *e) {
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

unsigned char* LU_CP_ABEEaVT::H2(element_s *e) {
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

element_s* LU_CP_ABEEaVT::computeXdelte(Ciphertext_CET *ciphertext, SecretKey *key_x, string pre_s, string post_s) {
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

    // obtain C0, K0, K1
    element_t C0, K0, K1;
    element_init_same_as(C0, ciphertext->getComponent("C0"));
    element_init_same_as(K0, key_x->getComponent(pre_s + "0" + post_s));
    element_init_same_as(K1, key_x->getComponent(pre_s + "1" + post_s));
    element_set(C0, ciphertext->getComponent("C0"));
    element_set(K0, key_x->getComponent(pre_s + "0" + post_s));
    element_set(K1, key_x->getComponent(pre_s + "1" + post_s));

    // compute e_C0_K0
    element_t e_C0_K0;
    element_init_GT(e_C0_K0, pairing);
    element_pairing(e_C0_K0, C0, K0);

    element_t denominator;
    element_init_GT(denominator, pairing);

    // init------
    element_t Ci1, Ci2, Ktau2, Ci3, Ktau3;
    element_init_G1(Ci1, pairing);
    element_init_G1(Ci2, pairing);
    element_init_G1(Ktau2, pairing);
    element_init_G1(Ci3, pairing);
    element_init_G1(Ktau3, pairing);
    element_t e_Ci1_K1, e_Ci2_Ktau2, e_Ci3_Ktau3;
    element_init_GT(e_Ci1_K1, pairing);
    element_init_GT(e_Ci2_Ktau2, pairing);
    element_init_GT(e_Ci3_Ktau3, pairing);
    element_t e_e, e_e_e, factor_denominator;
    element_init_GT(e_e, pairing);
    element_init_GT(e_e_e, pairing);
    element_init_GT(factor_denominator, pairing);
    // init------
    map<signed long int, signed long int>::iterator it;
    for (it = matchedAttributes->begin(); it != matchedAttributes->end(); ++it) {
        // get attribute
        string attr = (*key_x->getAttributes())[it->second];

        // get Ci1, Ci2, Ktau2, Ci3, Ktau3
        element_set(Ci1, ciphertext->getComponent("C" + attr + "1"));
        element_set(Ci2, ciphertext->getComponent("C" + attr + "2"));
        element_set(Ktau2, key_x->getComponent(pre_s + attr + "2" + post_s));
        element_set(Ci3, ciphertext->getComponent("C" + attr + "3"));
        element_set(Ktau3, key_x->getComponent(pre_s + attr + "3" + post_s));

        // compute e_Ci1_K1, e_Ci2_Ktau2, e_Ci3_Ktau3
        element_pairing(e_Ci1_K1, Ci1, K1);
        element_pairing(e_Ci2_Ktau2, Ci2, Ktau2);
        element_pairing(e_Ci3_Ktau3, Ci3, Ktau3);

        // compute factor_denominator
        element_mul(e_e, e_Ci1_K1, e_Ci2_Ktau2);
        element_mul(e_e_e, e_e, e_Ci3_Ktau3);
        // get wi
        signed long int attribute_index = it->second;
        map<signed long int, signed long int>::iterator itt = x_to_attributes->find(attribute_index);
        signed long int x_index = itt->second;
        element_pow_zn(factor_denominator, e_e_e, x->getElement(x_index));

        if (it == matchedAttributes->begin()) {
            element_set(denominator, factor_denominator);
        } else {
            element_mul(denominator, denominator, factor_denominator);
        }
    }

    element_t *res = new element_t[1];
    element_init_GT(*res, pairing);
    element_div(*res, e_C0_K0, denominator);

    return *res;
}

element_s* LU_CP_ABEEaVT::computeV(Ciphertext_CET *ct, Key *sp_ch, Key *pk_ch, element_s *r_ch, element_t_matrix *M, map<signed long int, string> *rho) {
    element_t *res = new element_t[1];
    element_init_Zr(*res, pairing);

    int n_total = g1_length + g1_length + 8 + zr_length + g1_length + g1_length + g1_length + (M->row() * g1_length);
    unsigned char* str = (unsigned char*)malloc(n_total + 1);
    int str_index = 0;

    // add y of pk_ch
    element_to_bytes(str + str_index, pk_ch->getComponent("y"));
    str_index += g1_length;

    // add C
    element_to_bytes(str + str_index, ct->getComponent("C"));
    str_index += g1_length;

    // add C*
    for (signed long int i = 0; i < 8 + zr_length; ++i) {
        str[str_index] = ct->Cstar[i];
        str_index++;
    }

    // add C0
    element_to_bytes(str + str_index, ct->getComponent("C0"));
    str_index += g1_length;

    // add C0'
    element_to_bytes(str + str_index, ct->getComponent("C0_"));
    str_index += g1_length;

    // add C03
    element_to_bytes(str + str_index, ct->getComponent("C03"));
    str_index += g1_length;

    // add Ctau3
    for (signed long int i = 0; i < M->row(); ++i) {
        map<signed long int, string>::iterator it = rho->find(i);
        string attr = it->second;
        element_to_bytes(str + str_index, ct->getComponent("C" + attr + "3"));
        str_index += g1_length;
    }

    str[str_index] = '\0';

    // compute hash value of str
    element_t m_ch;
    element_init_Zr(m_ch, pairing);
    unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, n_total);
    SHA256_Final(hash_str_byte, &sha256);
    element_from_hash(m_ch, hash_str_byte, SHA256_DIGEST_LENGTH);


    // compute V
    chamhash *ch = new chamhash();
    element_set(*res, ch->hash(sp_ch, pk_ch, m_ch, r_ch));

    return *res;
}

LU_CP_ABEEaVT::LU_CP_ABEEaVT() {
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

vector<Key*>* LU_CP_ABEEaVT::setUp() {
    chamhash *ch = new chamhash();
    Key *sp = ch->setup();
    vector<Key*> *sk_pk = ch->keygen(sp);

    // randomly choose g, u, h, w, v
    element_t g, u, h, w, v;
    element_init_G1(g, pairing);
    element_init_G1(u, pairing);
    element_init_G1(h, pairing);
    element_init_G1(w, pairing);
    element_init_G1(v, pairing);
    element_random(g);
    element_random(u);
    element_random(h);
    element_random(w);
    element_random(v);

    // randomly choose alpha and alpha_
    element_t alpha, alpha_;
    element_init_Zr(alpha, pairing);
    element_init_Zr(alpha_, pairing);
    element_random(alpha);
    element_random(alpha_);

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

    Key *master_key = new Key(Key::MASTER);
    Key *public_key = new Key(Key::PUBLIC);
    Key *sk_ch = new Key(Key::MASTER);
    Key *pk_ch = new Key(Key::PUBLIC);
    Key *sp_ch = new Key(Key::PUBLIC);

    master_key->insertComponent("alpha", "ZR", alpha);
    master_key->insertComponent("alpha_", "ZR", alpha_);
    public_key->insertComponent("g", "G1", g);
    public_key->insertComponent("u", "G1", u);
    public_key->insertComponent("h", "G1", h);
    public_key->insertComponent("w", "G1", w);
    public_key->insertComponent("v", "G1", v);
    public_key->insertComponent("e_gg_alpha", "GT", e_gg_alpha);
    public_key->insertComponent("e_gg_alpha_", "GT", e_gg_alpha_);
    sk_ch->insertComponent("x", "ZR", sk_pk->at(0)->getComponent("x"));
    pk_ch->insertComponent("y", "G1", sk_pk->at(1)->getComponent("y"));
    sp_ch->insertComponent("g", "G1", sp->getComponent("g"));

    vector<Key*> *res = new vector<Key*>(5);
    (*res)[0] = master_key;
    (*res)[1] = public_key;
    (*res)[2] = sk_ch;
    (*res)[3] = pk_ch;
    (*res)[4] = sp_ch;

    return res;
}

SecretKey* LU_CP_ABEEaVT::keyGen(Key *public_key, Key *master_key, vector<string> *attributes) {
    SecretKey *res = new SecretKey(attributes);

    // obtain public parameters
    element_t g, u, h, w, v;
    element_init_same_as(g, public_key->getComponent("g"));
    element_set(g, public_key->getComponent("g"));
    element_init_same_as(u, public_key->getComponent("u"));
    element_set(u, public_key->getComponent("u"));
    element_init_same_as(h, public_key->getComponent("h"));
    element_set(h, public_key->getComponent("h"));
    element_init_same_as(w, public_key->getComponent("w"));
    element_set(w, public_key->getComponent("w"));
    element_init_same_as(v, public_key->getComponent("v"));
    element_set(v, public_key->getComponent("v"));

    // obtain master key
    element_t alpha, alpha_;
    element_init_same_as(alpha, master_key->getComponent("alpha"));
    element_set(alpha, master_key->getComponent("alpha"));
    element_init_same_as(alpha_, master_key->getComponent("alpha_"));
    element_set(alpha_, master_key->getComponent("alpha_"));

    // randomly choose r
    element_t r;
    element_init_Zr(r, pairing);
    element_random(r);
    // compute -r
    element_t neg_r;
    element_init_Zr(neg_r, pairing);
    element_neg(neg_r, r);

    // compute g_alpha
    element_t g_alpha;
    element_init_G1(g_alpha, pairing);
    element_pow_zn(g_alpha, g, alpha);

    // compute w_r
    element_t w_r;
    element_init_G1(w_r, pairing);
    element_pow_zn(w_r, w, r);

    // compute K0=g^alpha*w^r
    element_t K0;
    element_init_G1(K0, pairing);
    element_mul(K0, g_alpha, w_r);
    res->insertComponent("K0", "G1", K0);

    // compute K1=g_r
    element_t K1;
    element_init_G1(K1, pairing);
    element_pow_zn(K1, g, r);
    res->insertComponent("K1", "G1", K1);

    // randomly choose r_
    element_t r_;
    element_init_Zr(r_, pairing);
    element_random(r_);
    // compute -r'
    element_t neg_r_;
    element_init_Zr(neg_r_, pairing);
    element_neg(neg_r_, r_);

    // compute g_alpha_
    element_t g_alpha_;
    element_init_G1(g_alpha_, pairing);
    element_pow_zn(g_alpha_, g, alpha_);

    // compute w_r_
    element_t w_r_;
    element_init_G1(w_r_, pairing);
    element_pow_zn(w_r_, w, r_);

    // compute K0'=g^alpha'*w^r'
    element_t K0_;
    element_init_G1(K0_, pairing);
    element_mul(K0_, g_alpha_, w_r_);
    res->insertComponent("K0_", "G1", K0_);

    // compute K1'=g^r'
    element_t K1_;
    element_init_G1(K1_, pairing);
    element_pow_zn(K1_, g, r_);
    res->insertComponent("K1_", "G1", K1_);

    // compute v^(-r)
    element_t v_neg_r;
    element_init_G1(v_neg_r, pairing);
    element_pow_zn(v_neg_r, v, neg_r);

    // compute v^(-r')
    element_t v_neg_r_;
    element_init_G1(v_neg_r_, pairing);
    element_pow_zn(v_neg_r_, v, neg_r_);

    // compute Ktau2 and Ktau3, Ktau2' and Ktau3'
    element_t rtau;
    element_init_Zr(rtau, pairing);
    element_t Ktau2, Ktau3;
    element_init_G1(Ktau2, pairing);
    element_init_G1(Ktau3, pairing);
    element_t Atau;
    element_init_Zr(Atau, pairing);
    element_t u_Atau, u_Atau_h, u_Atau_h_rtau;
    element_init_G1(u_Atau, pairing);
    element_init_G1(u_Atau_h, pairing);
    element_init_G1(u_Atau_h_rtau, pairing);
    for (signed long int i = 0; i < attributes->size(); ++i) {
        // randomly choose rtau
        element_random(rtau);

        // compute Ktau2=g^rtau
        element_pow_zn(Ktau2, g, rtau);
        res->insertComponent("K" + (*attributes)[i] + "2", "G1", Ktau2);

        // compute Atau
        unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, (*attributes)[i].c_str(), (*attributes)[i].size());
        SHA256_Final(hash_str_byte, &sha256);
        element_from_hash(Atau, hash_str_byte, SHA256_DIGEST_LENGTH);

        // compute u^Atau
        element_pow_zn(u_Atau, u, Atau);

        // compute u^Atau*h
        element_mul(u_Atau_h, u_Atau, h);

        // compute (u^Atau*h)^rtau
        element_pow_zn(u_Atau_h_rtau, u_Atau_h, rtau);

        // compute Ktau3=(u^Atau*h)^rtau*v^(-r)
        element_mul(Ktau3, u_Atau_h_rtau, v_neg_r);
        res->insertComponent("K" + (*attributes)[i] + "3", "G1", Ktau3);

        // Ktau2' and Ktau3'---------------------------------------------------------------------------------------------
        // randomly choose rtau
        element_random(rtau);

        // compute Ktau2=g^rtau
        element_pow_zn(Ktau2, g, rtau);
        res->insertComponent("K" + (*attributes)[i] + "2_", "G1", Ktau2);

//       // compute Atau  在这里有重复计算问题
//       unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
//       SHA256_CTX sha256;
//       SHA256_Init(&sha256);
//       SHA256_Update(&sha256, (*attributes)[i].c_str(), (*attributes)[i].size());
//       SHA256_Final(hash_str_byte, &sha256);
//       element_from_hash(Atau, hash_str_byte, SHA256_DIGEST_LENGTH);
//
//       // compute u^Atau  在这里有重复计算问题
//       element_pow_zn(u_Atau, u, Atau);
//
//       // compute u^Atau*h  在这里有重复计算问题
//       element_mul(u_Atau_h, u_Atau, h);

        // compute (u^Atau*h)^rtau
        element_pow_zn(u_Atau_h_rtau, u_Atau_h, rtau);

        // compute Ktau3=(u^Atau*h)^rtau*v^(-r)
        element_mul(Ktau3, u_Atau_h_rtau, v_neg_r_);
        res->insertComponent("K" + (*attributes)[i] + "3_", "G1", Ktau3);
        // Ktau2' and Ktau3'---------------------------------------------------------------------------------------------
    }

//    // compute Ktau2' and Ktau3'
//    for (signed long int i = 0; i < attributes->size(); ++i) {
//        // randomly choose rtau
//        element_random(rtau);
//
//        // compute Ktau2=g^rtau
//        element_pow_zn(Ktau2, g, rtau);
//        res->insertComponent("K" + (*attributes)[i] + "2_", "G1", Ktau2);
//
//        // compute Atau  在这里有重复计算问题
//        unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
//        SHA256_CTX sha256;
//        SHA256_Init(&sha256);
//        SHA256_Update(&sha256, (*attributes)[i].c_str(), (*attributes)[i].size());
//        SHA256_Final(hash_str_byte, &sha256);
//        element_from_hash(Atau, hash_str_byte, SHA256_DIGEST_LENGTH);
//
//        // compute u^Atau  在这里有重复计算问题
//        element_pow_zn(u_Atau, u, Atau);
//
//        // compute u^Atau*h  在这里有重复计算问题
//        element_mul(u_Atau_h, u_Atau, h);
//
//        // compute (u^Atau*h)^rtau
//        element_pow_zn(u_Atau_h_rtau, u_Atau_h, rtau);
//
//        // compute Ktau3=(u^Atau*h)^rtau*v^(-r)
//        element_mul(Ktau3, u_Atau_h_rtau, v_neg_r_);
//        res->insertComponent("K" + (*attributes)[i] + "3_", "G1", Ktau3);
//    }

    return res;
}

SecretKey* LU_CP_ABEEaVT::trapdoor(SecretKey *secret_key) {
    SecretKey *res = new SecretKey(secret_key->getAttributes());

    // obtain K0
    element_t K0;
    element_init_same_as(K0, secret_key->getComponent("K0"));
    element_set(K0, secret_key->getComponent("K0"));
    res->insertComponent("T0", "G1", K0);

    // obtain K1
    element_t K1;
    element_init_same_as(K1, secret_key->getComponent("K1"));
    element_set(K1, secret_key->getComponent("K1"));
    res->insertComponent("T1", "G1", K1);

    // obtain Ktau2 and Ktau3
    element_t Ktau2, Ktau3;
    element_init_G1(Ktau2, pairing);
    element_init_G1(Ktau3, pairing);
    for (signed long int i = 0; i < secret_key->getAttributes()->size(); ++i) {
        element_set(Ktau2, secret_key->getComponent("K" + (*secret_key->getAttributes())[i] + "2"));
        res->insertComponent("T" + (*secret_key->getAttributes())[i] + "2", "G1", Ktau2);
        element_set(Ktau3, secret_key->getComponent("K" + (*secret_key->getAttributes())[i] + "3"));
        res->insertComponent("T" + (*secret_key->getAttributes())[i] + "3", "G1", Ktau3);
    }

    return res;
}

Ciphertext_CET* LU_CP_ABEEaVT::encrypt(Key *public_key, access_structure *A, unsigned char *message, Key *sp_ch, Key *pk_ch) {
    Ciphertext_CET *res = new Ciphertext_CET(A->getM(), A->getRho());

    utils util;

    // obtain public parameters
    element_t g, u, h, w, v;
    element_init_same_as(g, public_key->getComponent("g"));
    element_set(g, public_key->getComponent("g"));
    element_init_same_as(u, public_key->getComponent("u"));
    element_set(u, public_key->getComponent("u"));
    element_init_same_as(h, public_key->getComponent("h"));
    element_set(h, public_key->getComponent("h"));
    element_init_same_as(w, public_key->getComponent("w"));
    element_set(w, public_key->getComponent("w"));
    element_init_same_as(v, public_key->getComponent("v"));
    element_set(v, public_key->getComponent("v"));
    element_t e_gg_alpha, e_gg_alpha_;
    element_init_same_as(e_gg_alpha, public_key->getComponent("e_gg_alpha"));
    element_set(e_gg_alpha, public_key->getComponent("e_gg_alpha"));
    element_init_same_as(e_gg_alpha_, public_key->getComponent("e_gg_alpha_"));
    element_set(e_gg_alpha_, public_key->getComponent("e_gg_alpha_"));

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
    element_t_vector *shares = emo.multiply(A->getM(), y);

    // randomly choose u and t0
    element_t uu, t0;
    element_init_Zr(uu, pairing);
    element_init_Zr(t0, pairing);
    element_random(uu);
    element_random(t0);
//    element_printf("原始的z为：%B\n", uu);

    // change message to m
    unsigned char hash_bytes[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message, 8);
    SHA256_Final(hash_bytes, &sha256);
    element_t m;
    element_init_G1(m, pairing);
    element_from_hash(m, hash_bytes, SHA256_DIGEST_LENGTH);

    // compute m^uu
    element_t m_uu;
    element_init_G1(m_uu, pairing);
    element_pow_zn(m_uu, m, uu);

    // compute e(g,g)^(alpha*s)
    element_t e_gg_alpha_s;
    element_init_GT(e_gg_alpha_s, pairing);
    element_pow_zn(e_gg_alpha_s, e_gg_alpha, s);

    // compute H1(e(g,g)^(alpha*s))
    element_t H_1;
    element_init_G1(H_1, pairing);
    element_set(H_1, H1(e_gg_alpha_s));

    // compute C
    element_t C;
    element_init_G1(C, pairing);
    element_mul(C, m_uu, H_1);
    res->insertComponent("C", "G1", C);

    // compute C0=g^s
    element_t C0;
    element_init_G1(C0, pairing);
    element_pow_zn(C0, g, s);
    res->insertComponent("C0", "G1", C0);

    // compute C0'=g^uu
    element_t C0_;
    element_init_G1(C0_, pairing);
    element_pow_zn(C0_, g, uu);
    res->insertComponent("C0_", "G1", C0_);

    // compute C03=g^t0
    element_t C03;
    element_init_G1(C03, pairing);
    element_pow_zn(C03, g, t0);
    res->insertComponent("C03", "G1", C03);

    // compute e(g,g)^(alpha'*s)
    element_t e_gg_alpha__s;
    element_init_GT(e_gg_alpha__s, pairing);
    element_pow_zn(e_gg_alpha__s, e_gg_alpha_, s);

    unsigned char *muu = (unsigned char*)malloc(8 + zr_length + 1);
    for (signed long int index = 0; index < 8; ++index) {
        muu[index] = message[index];
    }
    element_to_bytes(muu + 8, uu);
    muu[8 + zr_length] = '\0';
//    printf("muu is %s\n", muu);
    unsigned char *H_2 = H2(e_gg_alpha__s);

    // compute C*
    res->Cstar = (unsigned char*)malloc(SHA256_DIGEST_LENGTH +1);
    for (signed long int i = 0; i < 8 + zr_length; ++i) {
        int Cvalue = (int)muu[i] ^ (int)H_2[i];
        res->Cstar[i] = (unsigned char)Cvalue;
    }
    res->Cstar[SHA256_DIGEST_LENGTH] = '\0';

//    // test
//    for (signed long int i = 0; i < n1 + n2; ++i) {
//        int muuvalue = (int)res->Cstar[i] ^ (int)H_2[i];
//        muu[i] = (unsigned char)muuvalue;
//    }
//    printf("muu is %s\n", muu);
//    element_t mess;
//    element_init_Zr(mess, pairing);
//    element_from_bytes(mess, muu);
//    element_printf("message is %B\n", mess);

    // init------
    element_t ttau;
    element_init_Zr(ttau, pairing);
    element_t rhotau;
    element_init_Zr(rhotau, pairing);
    element_t Ctau1, Ctau2, Ctau3;
    element_init_G1(Ctau1, pairing);
    element_init_G1(Ctau2, pairing);
    element_init_G1(Ctau3, pairing);
    element_t w_lambdatau, v_ttau;
    element_init_G1(w_lambdatau, pairing);
    element_init_G1(v_ttau, pairing);
    element_t neg_ttau;
    element_t u_rhotau, u_rhotau_h;
    element_init_Zr(neg_ttau, pairing);
    element_init_G1(u_rhotau, pairing);
    element_init_G1(u_rhotau_h, pairing);
    element_t w_s;
    element_init_G1(w_s, pairing);
    element_t v_t0;
    element_init_G1(v_t0, pairing);
    element_t C01;
    element_init_G1(C01, pairing);
    element_t r_ch;
    element_init_Zr(r_ch, pairing);
    element_t u_V;
    element_init_G1(u_V, pairing);
    element_t u_V_h;
    element_init_G1(u_V_h, pairing);
    element_t neg_t0;
    element_init_Zr(neg_t0, pairing);
    element_t C02;
    element_init_G1(C02, pairing);
    // init------
    for (signed long int i = 0; i < A->getM()->row(); ++i) {
        // get ttau
        element_random(ttau);

        // get rhotau
        map<signed long int, string>::iterator it = A->getRho()->find(i);
        string attr = it->second;
        element_set(rhotau, util.stringToElementT(attr, "ZR", &pairing));

        // compute Ctau1, Ctau2, Ctau3
        element_pow_zn(w_lambdatau, w, shares->getElement(i));
        element_pow_zn(v_ttau, v, ttau);
        element_mul(Ctau1, w_lambdatau, v_ttau);
        element_neg(neg_ttau, ttau);
        element_pow_zn(u_rhotau, u, rhotau);
        element_mul(u_rhotau_h, u_rhotau, h);
        element_pow_zn(Ctau2, u_rhotau_h, neg_ttau);
        element_pow_zn(Ctau3, g, ttau);

        res->insertComponent("C" + attr + "1", "G1", Ctau1);
        res->insertComponent("C" + attr + "2", "G1", Ctau2);
        res->insertComponent("C" + attr + "3", "G1", Ctau3);
    }

    // compute w^s
    element_pow_zn(w_s, w, s);

    // compute v^t0
    element_pow_zn(v_t0, v, t0);

    // compute C01=w^s*v^t0
    element_mul(C01, w_s, v_t0);
    res->insertComponent("C01", "G1", C01);

    // randomly choose rnd
    element_random(r_ch);
    res->insertComponent("rch", "ZR", r_ch);

    // compute V
    element_s *V = computeV(res, sp_ch, pk_ch, r_ch, A->getM(), A->getRho());
//    element_printf("V is %B\n", V);

    // compute u^V
    element_pow_zn(u_V, u, V);

    // compute u^V*h
    element_mul(u_V_h, u_V, h);

    // compute -t0
    element_neg(neg_t0, t0);

    // compute C02
    element_pow_zn(C02, u_V_h, neg_t0);
    res->insertComponent("C02", "G1", C02);

    return res;
}

bool* LU_CP_ABEEaVT::test(Key *public_key, Ciphertext_CET *CTA, SecretKey *TdSA, Ciphertext_CET *CTB, SecretKey *TdSB, Key *sp_ch, Key *pk_ch) {
    // obtain public parameters
    element_t g, u, h, w, v;
    element_init_same_as(g, public_key->getComponent("g"));
    element_set(g, public_key->getComponent("g"));
    element_init_same_as(u, public_key->getComponent("u"));
    element_set(u, public_key->getComponent("u"));
    element_init_same_as(h, public_key->getComponent("h"));
    element_set(h, public_key->getComponent("h"));
    element_init_same_as(w, public_key->getComponent("w"));
    element_set(w, public_key->getComponent("w"));
    element_init_same_as(v, public_key->getComponent("v"));
    element_set(v, public_key->getComponent("v"));

    // VA
    element_s *VA = computeV(CTA, sp_ch, pk_ch, CTA->getComponent("rch"), CTA->getAccessStructure()->getM(), CTA->getAccessStructure()->getRho());

    // VB
    element_s *VB = computeV(CTB, sp_ch, pk_ch, CTB->getComponent("rch"), CTB->getAccessStructure()->getM(), CTB->getAccessStructure()->getRho());

    // init params
    element_t Ci2, Ci3;
    element_t e_gCi2, Ai, u_Ai, u_Ai_h, e_Ci3uAih, inv_e_Ci3uAih;
    element_init_G1(Ci2, pairing);
    element_init_G1(Ci3, pairing);
    element_init_GT(e_gCi2, pairing);
    element_init_Zr(Ai, pairing);
    element_init_G1(u_Ai, pairing);
    element_init_G1(u_Ai_h, pairing);
    element_init_GT(e_Ci3uAih, pairing);
    element_init_GT(inv_e_Ci3uAih, pairing);
    // test the first structure
    for (signed long int i = 0; i < CTA->getAccessStructure()->getM()->row(); ++i) {
        map<signed long int, string>::iterator it = CTA->getAccessStructure()->getRho()->find(i);
        string attr = it->second;

        // obtain Ci2 and Ci3
        element_set(Ci2, CTA->getComponent("C" + attr + "2"));
        element_set(Ci3, CTA->getComponent("C" + attr + "3"));

        // compute e_gCi2
        element_pairing(e_gCi2, g, Ci2);

        // compute Ai
        unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, attr.c_str(), attr.size());
        SHA256_Final(hash_str_byte, &sha256);
        element_from_hash(Ai, hash_str_byte, SHA256_DIGEST_LENGTH);

        // compute u_Ai
        element_pow_zn(u_Ai, u, Ai);

        // compute u_Ai_h
        element_mul(u_Ai_h, u_Ai, h);

        // compute e(Ci3,u^Ai*h)
        element_pairing(e_Ci3uAih, Ci3, u_Ai_h);

        // compute e(Ci3,u^Ai*h)^(-1)
        element_invert(inv_e_Ci3uAih, e_Ci3uAih);

        if (element_cmp(e_gCi2, inv_e_Ci3uAih) != 0) {
            return NULL;
        }
    }
//    cout << "1-1" << endl;
    for (signed long int i = 0; i < CTB->getAccessStructure()->getM()->row(); ++i) {
        map<signed long int, string>::iterator it = CTB->getAccessStructure()->getRho()->find(i);
        string attr = it->second;

        // obtain Ci2 and Ci3
        element_set(Ci2, CTB->getComponent("C" + attr + "2"));
        element_set(Ci3, CTB->getComponent("C" + attr + "3"));

        // compute e_gCi2
        element_pairing(e_gCi2, g, Ci2);

        // compute Ai
        unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, attr.c_str(), attr.size());
        SHA256_Final(hash_str_byte, &sha256);
        element_from_hash(Ai, hash_str_byte, SHA256_DIGEST_LENGTH);

        // compute u_Ai
        element_pow_zn(u_Ai, u, Ai);

        // compute u_Ai_h
        element_mul(u_Ai_h, u_Ai, h);

        // compute e(Ci3,u^Ai*h)
        element_pairing(e_Ci3uAih, Ci3, u_Ai_h);

        // compute e(Ci3,u^Ai*h)^(-1)
        element_invert(inv_e_Ci3uAih, e_Ci3uAih);

        if (element_cmp(e_gCi2, inv_e_Ci3uAih) != 0) {
            return NULL;
        }
    }
//    cout << "1-2" << endl;

    // test the second structure
    element_s *XdelteA = computeXdelte(CTA, TdSA, "T", "");
//    cout << "XdelteA" << endl;
    element_s *XdelteB = computeXdelte(CTB, TdSB, "T", "");
//    cout << "XdelteB" << endl;

    // compute XA
    element_t XA;
    element_init_G1(XA, pairing);
    element_div(XA, CTA->getComponent("C"), H1(XdelteA));
//    cout << "XA" << endl;

    // compute XB
    element_t XB;
    element_init_G1(XB, pairing);
    element_div(XB, CTB->getComponent("C"), H1(XdelteB));
//    cout << "XB" << endl;

    // compute e(C0'A,XB)
    element_t e_C0_A_XB;
    element_init_GT(e_C0_A_XB, pairing);
    element_pairing(e_C0_A_XB, CTA->getComponent("C0_"), XB);
//    element_printf("e(C0'A,XB) is: %B\n", e_C0_A_XB);
//    cout << "e_C0_A_XB" << endl;

    // compute e(C0'B,XA)
    element_t e_C0_B_XA;
    element_init_GT(e_C0_B_XA, pairing);
    element_pairing(e_C0_B_XA, CTB->getComponent("C0_"), XA);
//    element_printf("e(C0'B,XA) is: %B\n", e_C0_B_XA);
//    cout << "e_C0_B_XA" << endl;

    bool *res = new bool();

    if (element_cmp(e_C0_A_XB, e_C0_B_XA) == 0) {
        *res = true;
        return res;
    } else {
        *res = false;
        return res;
    }
}

unsigned char* LU_CP_ABEEaVT::decrypt(Key *public_key, Ciphertext_CET *ciphertext_cet, SecretKey *secret_key, Key *sp_ch, Key *pk_ch) {
    // test step one
    // obtain public parameters
    element_t g, u, h, w, v;
    element_init_same_as(g, public_key->getComponent("g"));
    element_set(g, public_key->getComponent("g"));
    element_init_same_as(u, public_key->getComponent("u"));
    element_set(u, public_key->getComponent("u"));
    element_init_same_as(h, public_key->getComponent("h"));
    element_set(h, public_key->getComponent("h"));
    element_init_same_as(w, public_key->getComponent("w"));
    element_set(w, public_key->getComponent("w"));
    element_init_same_as(v, public_key->getComponent("v"));
    element_set(v, public_key->getComponent("v"));

    // V
    element_s *V = computeV(ciphertext_cet, sp_ch, pk_ch, ciphertext_cet->getComponent("rch"), ciphertext_cet->getAccessStructure()->getM(), ciphertext_cet->getAccessStructure()->getRho());

    // init params
    element_t Ci2, Ci3;
    element_t e_gCi2, Ai, u_Ai, u_Ai_h, e_Ci3uAih, inv_e_Ci3uAih;
    element_init_G1(Ci2, pairing);
    element_init_G1(Ci3, pairing);
    element_init_GT(e_gCi2, pairing);
    element_init_Zr(Ai, pairing);
    element_init_G1(u_Ai, pairing);
    element_init_G1(u_Ai_h, pairing);
    element_init_GT(e_Ci3uAih, pairing);
    element_init_GT(inv_e_Ci3uAih, pairing);
    for (signed long int i = 0; i < ciphertext_cet->getAccessStructure()->getM()->row(); ++i) {
        map<signed long int, string>::iterator it = ciphertext_cet->getAccessStructure()->getRho()->find(i);
        string attr = it->second;

        // obtain Ci2 and Ci3
        element_set(Ci2, ciphertext_cet->getComponent("C" + attr + "2"));
        element_set(Ci3, ciphertext_cet->getComponent("C" + attr + "3"));

        // compute e_gCi2
        element_pairing(e_gCi2, g, Ci2);

        // compute Ai
        unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, attr.c_str(), attr.size());
        SHA256_Final(hash_str_byte, &sha256);
        element_from_hash(Ai, hash_str_byte, SHA256_DIGEST_LENGTH);

        // compute u_Ai
        element_pow_zn(u_Ai, u, Ai);

        // compute u_Ai_h
        element_mul(u_Ai_h, u_Ai, h);

        // compute e(Ci3,u^Ai*h)
        element_pairing(e_Ci3uAih, Ci3, u_Ai_h);

        // compute e(Ci3,u^Ai*h)^(-1)
        element_invert(inv_e_Ci3uAih, e_Ci3uAih);

        if (element_cmp(e_gCi2, inv_e_Ci3uAih) != 0) {
            return NULL;
        }
    }

    // decrypt
    element_s *Xdelte = computeXdelte(ciphertext_cet, secret_key, "K", "");
    element_s *Xdelte_ = computeXdelte(ciphertext_cet, secret_key, "K", "_");

    unsigned char *H_2 = H2(Xdelte_);

    unsigned char *res = (unsigned char*)malloc(8 + 1);
    res[8] = '\0';
    unsigned char *z_bytes = (unsigned char*)malloc(zr_length + 1);
    z_bytes[zr_length] = '\0';

    for (signed long int i = 0; i < 8; ++i) {
        int mzvalue = (int)ciphertext_cet->Cstar[i] ^ (int)H_2[i];
        res[i] = (unsigned char)mzvalue;
    }
    for (signed long int i = 8; i < 8 + zr_length; ++i) {
        int mzvalue = (int)ciphertext_cet->Cstar[i] ^ (int)H_2[i];
        z_bytes[i - 8] = (unsigned char)mzvalue;
    }

    element_t z;
    element_init_Zr(z, pairing);
    element_from_bytes(z, z_bytes);
//    element_printf("恢复出来的z为：%B\n", z);

    // verify
    // compute g^z
    element_t g_z;
    element_init_G1(g_z, pairing);
    element_pow_zn(g_z, g, z);
    // obtain C0'
    element_t C0_;
    element_init_same_as(C0_, ciphertext_cet->getComponent("C0_"));
    element_set(C0_, ciphertext_cet->getComponent("C0_"));
    if (element_cmp(g_z, C0_) != 0) {
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
    // compute m^z
    element_t m_z;
    element_init_G1(m_z, pairing);
    element_pow_zn(m_z, m, z);
    // compute m^z*H1(Xdelte)
    element_t m_z_H1;
    element_init_G1(m_z_H1, pairing);
    element_mul(m_z_H1, m_z, H1(Xdelte));
    // obtain C
    element_t C;
    element_init_same_as(C, ciphertext_cet->getComponent("C"));
    element_set(C, ciphertext_cet->getComponent("C"));
    if (element_cmp(C, m_z_H1) != 0) {
        return NULL;
    }

    return res;
}