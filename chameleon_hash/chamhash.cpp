//
// Created by alan on 19-8-19.
//

#include "chamhash.h"

chamhash::chamhash() {
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

Key* chamhash::setup() {
    Key *sp = new Key(Key::PUBLIC);
    element_t g;
    element_init_G1(g, pairing);
    element_random(g);
    sp->insertComponent("g", "G1", g);

    return sp;
}

vector<Key*>* chamhash::keygen(Key *sp) {
    // obtain system parameters
    element_t g;
    element_init_same_as(g, sp->getComponent("g"));
    element_set(g, sp->getComponent("g"));

    // randomly choose x
    element_t x;
    element_init_Zr(x, pairing);
    element_random(x);

    // compute y=g^x
    element_t y;
    element_init_G1(y, pairing);
    element_pow_zn(y, g, x);

    Key *sk = new Key(Key::SECRET);
    Key *pk = new Key(Key::PUBLIC);

    sk->insertComponent("x", "ZR", x);
    pk->insertComponent("y", "G1", y);

    vector<Key*> *res = new vector<Key*>(2);
    (*res)[0] = sk;
    (*res)[1] = pk;

    return res;
}

element_s* chamhash::hash(Key *sp, Key *pk, element_s *m, element_s *r) {
    // obtain system parameters
    element_t g;
    element_init_same_as(g, sp->getComponent("g"));
    element_set(g, sp->getComponent("g"));

    // obtain public key
    element_t y;
    element_init_same_as(y, pk->getComponent("y"));
    element_set(y, pk->getComponent("y"));

    // compute g^m
    element_t g_m;
    element_init_G1(g_m, pairing);
    element_pow_zn(g_m, g, m);

    // compute y^r
    element_t y_r;
    element_init_G1(y_r, pairing);
    element_pow_zn(y_r, y, r);

    // compute hash=g^m*y^r
    element_t hash_g1;
    element_init_G1(hash_g1, pairing);
    element_mul(hash_g1, g_m, y_r);

    // transfer the G1 element to string
    unsigned char *hash_g1_bytes = (unsigned char*)malloc(g1_length + 1);
    element_to_bytes(hash_g1_bytes, hash_g1);
    hash_g1_bytes[g1_length] = '\0';

    // hash the string to a fixed length string
    unsigned char hash_g1_bytes_hash_str[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, hash_g1_bytes, g1_length);
    SHA256_Final(hash_g1_bytes_hash_str, &sha256);

    // get a Zr element from the string
    element_t *res = new element_t[1];
    element_init_Zr(*res, pairing);
    element_from_hash(*res, hash_g1_bytes_hash_str, SHA256_DIGEST_LENGTH);

    return *res;
}

element_s* chamhash::forge(Key *sp, Key *pk, Key *sk, element_s *m, element_s *r, element_s *m_) {
    // obtain system parameters
    element_t g;
    element_init_same_as(g, sp->getComponent("g"));
    element_set(g, sp->getComponent("g"));

    // obtain public key
    element_t y;
    element_init_same_as(y, pk->getComponent("y"));
    element_set(y, pk->getComponent("y"));

    // obtain secret key
    element_t x;
    element_init_same_as(x, sk->getComponent("x"));
    element_set(x, sk->getComponent("x"));

    // compute m-m'
    element_t m_m_;
    element_init_Zr(m_m_, pairing);
    element_sub(m_m_, m, m_);

    // compute (m-m')/x
    element_t m_m__x;
    element_init_Zr(m_m__x, pairing);
    element_div(m_m__x, m_m_, x);

    // compute r'=(m-m')/x+r
    element_t *res = new element_t[1];
    element_init_Zr(*res, pairing);
    element_add(*res, m_m__x, r);

    return *res;
}