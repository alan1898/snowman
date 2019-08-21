//
// Created by alan on 19-8-21.
//

#include "BCET.h"

vector<Key*>* BCET::setUp() {
    // init pairing
    pbc_param_t par;
    curve_param curves;
    pbc_param_init_set_str(par, curves.a_param.c_str());
    pairing_init_pbc_param(pairing, par);

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

    master_key->insertComponent("alpha", "ZR", alpha);
    master_key->insertComponent("alpha_", "ZR", alpha_);
    public_key->insertComponent("g", "G1", g);
    public_key->insertComponent("u", "G1", u);
    public_key->insertComponent("h", "G1", h);
    public_key->insertComponent("w", "G1", w);
    public_key->insertComponent("v", "G1", v);
    public_key->insertComponent("e_gg_alpha", "GT", e_gg_alpha);
    public_key->insertComponent("e_gg_alpha_", "GT", e_gg_alpha_);

    vector<Key*> *res = new vector<Key*>(2);
    (*res)[0] = master_key;
    (*res)[1] = public_key;

    return res;
}

Key* BCET::keyGen(Key *public_key, Key *master_key, vector<string> *attributes) {
    Key *res = new Key();

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

    // compute Ktau2 and Ktau3
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
    }

    // compute Ktau2' and Ktau3'
    for (signed long int i = 0; i < attributes->size(); ++i) {
        // randomly choose rtau
        element_random(rtau);

        // compute Ktau2=g^rtau
        element_pow_zn(Ktau2, g, rtau);
        res->insertComponent("K" + (*attributes)[i] + "2_", "G1", Ktau2);

        // compute Atau  在这里有重复计算问题
        unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, (*attributes)[i].c_str(), (*attributes)[i].size());
        SHA256_Final(hash_str_byte, &sha256);
        element_from_hash(Atau, hash_str_byte, SHA256_DIGEST_LENGTH);

        // compute u^Atau  在这里有重复计算问题
        element_pow_zn(u_Atau, u, Atau);

        // compute u^Atau*h  在这里有重复计算问题
        element_mul(u_Atau_h, u_Atau, h);

        // compute (u^Atau*h)^rtau
        element_pow_zn(u_Atau_h_rtau, u_Atau_h, rtau);

        // compute Ktau3=(u^Atau*h)^rtau*v^(-r)
        element_mul(Ktau3, u_Atau_h_rtau, v_neg_r_);
        res->insertComponent("K" + (*attributes)[i] + "3_", "G1", Ktau3);
    }

    return res;
}

Key* BCET::trapdoor(Key *secret_key, vector<string> *attributes) {
    Key *res = new Key();

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

    // obtain Ktau2 and Ktau3  在这里有属性不完全匹配的问题
    element_t Ktau2, Ktau3;
    element_init_G1(Ktau2, pairing);
    element_init_G1(Ktau3, pairing);
    for (signed long int i = 0; i < attributes->size(); ++i) {
        element_set(Ktau2, secret_key->getComponent("K" + (*attributes)[i] + "2"));
        res->insertComponent("T" + (*attributes)[i] + "2", "G1", Ktau2);
        element_set(Ktau3, secret_key->getComponent("K" + (*attributes)[i] + "3"));
        res->insertComponent("T" + (*attributes)[i] + "3", "G1", Ktau3);
    }

    return res;
}