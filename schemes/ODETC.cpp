//
// Created by alan on 19-9-22.
//

#include "ODETC.h"

element_s* ODETC::H1(element_s *e) {
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

unsigned char* ODETC::H2(unsigned char *str, signed long int len) {
    unsigned char *hash_str_byte = (unsigned char*)malloc(SHA256_DIGEST_LENGTH + 1);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, len);
    SHA256_Final(hash_str_byte, &sha256);
    hash_str_byte[SHA256_DIGEST_LENGTH] = '\0';

    return hash_str_byte;
}

element_s* ODETC::computeXsub(Ciphertext_CET *ciphertext, SecretKey *key_x, string post_s) {
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

vector<Key*>* ODETC::setUp(vector<string> *attributes) {
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

SecretKey* ODETC::keyGen(Key *public_key, Key *master_key, vector<string> *attributes) {
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

    // randomly choose z, z'
    element_t z, z_;
    element_init_Zr(z, pairing);
    element_init_Zr(z_, pairing);
    element_random(z);
    element_random(z_);
    res->insertComponent("z", "ZR", z);
    res->insertComponent("z_", "ZR", z_);
    // compute z^(-1), z'^(-1)
    element_t inv_z, inv_z_;
    element_init_Zr(inv_z, pairing);
    element_init_Zr(inv_z_, pairing);
    element_invert(inv_z, z);
    element_invert(inv_z_, z_);

    // compute t/z, t'/z'
    element_t t_z, t__z_;
    element_init_Zr(t_z, pairing);
    element_init_Zr(t__z_, pairing);
    element_div(t_z, t, z);
    element_div(t__z_, t_, z_);

    // compute g^(alpha/z), g^(alpha'/z')
    element_t g_alpha_z, g_alpha__z_;
    element_init_G1(g_alpha_z, pairing);
    element_init_G1(g_alpha__z_, pairing);
    element_pow_zn(g_alpha_z, g_alpha, inv_z);
    element_pow_zn(g_alpha__z_, g_alpha_, inv_z_);

    // compute g^(a*t/z), g^(a*t'/z')
    element_t g_a_t_z, g_a_t__z_;
    element_init_G1(g_a_t_z, pairing);
    element_init_G1(g_a_t__z_, pairing);
    element_pow_zn(g_a_t_z, g_a, t_z);
    element_pow_zn(g_a_t__z_, g_a, t__z_);

    // compute K=g^(alpha/z)*g^(a*t/z)
    element_t K;
    element_init_G1(K, pairing);
    element_mul(K, g_alpha_z, g_a_t_z);
    res->insertComponent("K", "G1", K);

    // compute K'=g^(alpha'/z'), g^(a*t'/z')
    element_t K_;
    element_init_G1(K_, pairing);
    element_mul(K_, g_alpha__z_, g_a_t__z_);
    res->insertComponent("K_", "G1", K_);

    // compute L=g^(t/z)
    element_t L;
    element_init_G1(L, pairing);
    element_pow_zn(L, g, t_z);
    res->insertComponent("L", "G1", L);

    // compute L'=g^(t'/z')
    element_t L_;
    element_init_G1(L_, pairing);
    element_pow_zn(L_, g, t__z_);
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

        // compute Kx=hx^(t/z)
        element_pow_zn(Kx, hx, t_z);
        res->insertComponent("K" + attributes->at(i), "G1", Kx);

        // compute Kx'=hx^(t'/z')
        element_pow_zn(Kx_, hx, t__z_);
        res->insertComponent("K" + attributes->at(i) + "_", "G1", Kx_);
    }

    return res;
}

Ciphertext_CET* ODETC::encrypt(Key *public_key, access_structure *A, unsigned char *message) {
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

SecretKey* ODETC::trapdoor(Key *public_key, Key *master_key, vector<string> *attributes) {
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

    // randomly choose z
    element_t z;
    element_init_Zr(z, pairing);
    element_random(z);
    res->insertComponent("z", "ZR", z);
    // compute z^(-1)
    element_t inv_z;
    element_init_Zr(inv_z, pairing);
    element_invert(inv_z, z);

    // compute t/z
    element_t t_z;
    element_init_Zr(t_z, pairing);
    element_div(t_z, t, z);

    // compute g^(alpha/z)
    element_t g_alpha_z;
    element_init_G1(g_alpha_z, pairing);
    element_pow_zn(g_alpha_z, g_alpha, inv_z);

    // compute g^(a*t/z)
    element_t g_a_t_z;
    element_init_G1(g_a_t_z, pairing);
    element_pow_zn(g_a_t_z, g_a, t_z);

    // compute K=g^(alpha/z)*g^(a*t/z)
    element_t K;
    element_init_G1(K, pairing);
    element_mul(K, g_alpha_z, g_a_t_z);
    res->insertComponent("K", "G1", K);

    // compute L=g^(t/z)
    element_t L;
    element_init_G1(L, pairing);
    element_pow_zn(L, g, t_z);
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

        // compute Kx=hx^(t/z)
        element_pow_zn(Kx, hx, t_z);
        res->insertComponent("K" + attributes->at(i), "G1", Kx);
    }

    return res;
}

Ciphertext_CET* ODETC::transform(Ciphertext_CET *Ct, SecretKey *TkS, string *key_type) {
    Ciphertext_CET *res = new Ciphertext_CET();

    if (*key_type == "Td") {
        res->insertComponent("Xsub", "GT", computeXsub(Ct, TkS, ""));
    } else {
        res->insertComponent("Xsub", "GT", computeXsub(Ct, TkS, ""));
        res->insertComponent("Xsub_", "GT", computeXsub(Ct, TkS, "_"));
    }

    return res;
}