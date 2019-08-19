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
    element_t *res = new element_t[1];
    element_init_G1(*res, pairing);
    element_mul(*res, g_m, y_r);

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