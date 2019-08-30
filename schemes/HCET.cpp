//
// Created by alan on 19-8-26.
//

#include "HCET.h"

element_s* HCET::H1(element_s *e) {
    element_t *res = new element_t[1];
    element_init_Zr(*res, pairing);

    signed long int n = element_length_in_bytes(e);
    unsigned char *bytes = (unsigned char*)malloc(n);
    element_to_bytes(bytes, e);

    unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, bytes, n);
    SHA256_Final(hash_str_byte, &sha256);
    element_from_hash(*res, hash_str_byte, SHA256_DIGEST_LENGTH);

    return *res;
}

unsigned char* HCET::H2(element_s *e) {
    element_t *res = new element_t[1];
    element_init_G1(*res, pairing);

    signed long int n = element_length_in_bytes(e);
    unsigned char *bytes = (unsigned char*)malloc(n);
    element_to_bytes(bytes, e);

    unsigned char *hash_str_byte = (unsigned char*)malloc(SHA256_DIGEST_LENGTH + 8 + 1);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, bytes, n);
    SHA256_Final(hash_str_byte, &sha256);
    for (signed long int i = 0; i < 8; ++i) {
        hash_str_byte[SHA256_DIGEST_LENGTH + i] = '0';
    }
    hash_str_byte[SHA256_DIGEST_LENGTH + 8] = '\0';

    return hash_str_byte;
}

vector<Key*>* HCET::setUp(signed long int q) {
    this->q = q;

    // init pairing
    pbc_param_t par;
    curve_param curves;
    pbc_param_init_set_str(par, curves.a_param.c_str());
    pairing_init_pbc_param(pairing, par);

    chamhash *ch = new chamhash();
    Key *sp = ch->setup();
    vector<Key*> *sk_pk = ch->keygen(sp);

    // randomly choose g, u, h, w, v, g2, g3
    element_t g, u, h, w, v, g2, g3;
    element_init_G1(g, pairing);
    element_init_G1(u, pairing);
    element_init_G1(h, pairing);
    element_init_G1(w, pairing);
    element_init_G1(v, pairing);
    element_init_G1(g2, pairing);
    element_init_G1(g3, pairing);
    element_random(g);
    element_random(u);
    element_random(h);
    element_random(w);
    element_random(v);
    element_random(g2);
    element_random(g3);

    // randomly choose alpha and alpha_
    element_t alpha, alpha_;
    element_init_Zr(alpha, pairing);
    element_init_Zr(alpha_, pairing);
    element_random(alpha);
    element_random(alpha_);

    // compute g1=g^alpha
    element_t g1;
    element_init_G1(g1, pairing);
    element_pow_zn(g1, g, alpha);

    // compute g1'=g^alpha'
    element_t g1_;
    element_init_G1(g1_, pairing);
    element_pow_zn(g1_, g, alpha_);

    // compute g2_alpha
    element_t g2_alpha;
    element_init_G1(g2_alpha, pairing);
    element_pow_zn(g2_alpha, g2, alpha);

    // compute g2_alpha_
    element_t g2_alpha_;
    element_init_G1(g2_alpha_, pairing);
    element_pow_zn(g2_alpha_, g2, alpha_);

    Key *master_key = new Key(Key::MASTER);
    Key *public_key = new Key(Key::PUBLIC);
    Key *sk_ch = new Key(Key::MASTER);
    Key *pk_ch = new Key(Key::PUBLIC);
    Key *sp_ch = new Key(Key::PUBLIC);

    master_key->insertComponent("g2_alpha", "G1", g2_alpha);
    master_key->insertComponent("g2_alpha_", "G1", g2_alpha_);
    public_key->insertComponent("g", "G1", g);
    public_key->insertComponent("u", "G1", u);
    public_key->insertComponent("h", "G1", h);
    public_key->insertComponent("w", "G1", w);
    public_key->insertComponent("v", "G1", v);
    public_key->insertComponent("g1", "G1", g1);
    public_key->insertComponent("g1_", "G1", g1_);
    public_key->insertComponent("g2", "G1", g2);
    public_key->insertComponent("g3", "G1", g3);
    element_t hi;
    element_init_G1(hi, pairing);
    string str = "h";
    char num[21];
    for (signed long int i = 1; i <= q; ++i) {
        element_random(hi);
        sprintf(num, "%ld", i);
        public_key->insertComponent(str + num, "G1", hi);
    }
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

Key* HCET::authKeyGen(Key *public_key, Key *master_key, element_t_vector *ID) {
    Key *res = new Key();

    // randomly choose r and r'
    element_t r, r_;
    element_init_Zr(r, pairing);
    element_init_Zr(r_, pairing);
    element_random(r);
    element_random(r_);

    // obtain public parameters
    element_t g, u, h, w, v, g1, g1_, g2, g3;
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
    element_init_same_as(g1, public_key->getComponent("g1"));
    element_set(g1, public_key->getComponent("g1"));
    element_init_same_as(g1_, public_key->getComponent("g1_"));
    element_set(g1_, public_key->getComponent("g1_"));
    element_init_same_as(g2, public_key->getComponent("g2"));
    element_set(g2, public_key->getComponent("g2"));
    element_init_same_as(g3, public_key->getComponent("g3"));
    element_set(g3, public_key->getComponent("g3"));

    // obtain master key
    element_t g2_alpha, g2_alpha_;
    element_init_same_as(g2_alpha, master_key->getComponent("g2_alpha"));
    element_set(g2_alpha, master_key->getComponent("g2_alpha"));
    element_init_same_as(g2_alpha_, master_key->getComponent("g2_alpha_"));
    element_set(g2_alpha_, master_key->getComponent("g2_alpha_"));

    // compute h1^I1*...*hj^Ij
    element_t hs_Is;
    element_init_G1(hs_Is, pairing);
    element_t h_I;
    element_init_G1(h_I, pairing);
    string str = "h";
    char num[21];
    for (signed long int i = 1; i <= ID->length(); ++i) {
        sprintf(num, "%ld", i);
        element_pow_zn(h_I, public_key->getComponent(str + num), ID->getElement(i - 1));

        if (i == 1) {
            element_set(hs_Is, h_I);
        } else {
            element_mul(hs_Is, hs_Is, h_I);
        }
    }

    // compute h1^I1*...*hj^Ij*g3
    element_t hs_Is_g3;
    element_init_G1(hs_Is_g3, pairing);
    element_mul(hs_Is_g3, hs_Is, g3);

    // compute h1^I1*...*hj^Ij*g3*w
    element_t hs_Is_g3_w;
    element_init_G1(hs_Is_g3_w, pairing);
    element_mul(hs_Is_g3_w, hs_Is_g3, w);

    // compute (h1^I1*...*hj^Ij*g3*w)^r
    element_t hs_Is_g3_w_r;
    element_init_G1(hs_Is_g3_w_r, pairing);
    element_pow_zn(hs_Is_g3_w_r, hs_Is_g3_w, r);

    // compute K0=g2^alpha*(h1^I1*...*hj^Ij*g3*w)^r
    element_t K0;
    element_init_G1(K0, pairing);
    element_mul(K0, g2_alpha, hs_Is_g3_w_r);
    res->insertComponent("K0", "G1", K0);

    // compute (h1^I1*...*hj^Ij*g3*w)^r'
    element_t hs_Is_g3_w_r_;
    element_init_G1(hs_Is_g3_w_r_, pairing);
    element_pow_zn(hs_Is_g3_w_r_, hs_Is_g3_w, r_);

    // compute K0'=g2^alpha*(h1^I1*...*hj^Ij*g3*w)^r'
    element_t K0_;
    element_init_G1(K0_, pairing);
    element_mul(K0_, g2_alpha_, hs_Is_g3_w_r_);
    res->insertComponent("K0_", "G1", K0_);

    // compute K1=g^r
    element_t K1;
    element_init_G1(K1, pairing);
    element_pow_zn(K1, g, r);
    res->insertComponent("K1", "G1", K1);

    // compute K1'=g^r'
    element_t K1_;
    element_init_G1(K1_, pairing);
    element_pow_zn(K1_, g, r_);
    res->insertComponent("K1_", "G1", K1_);

    // compute neg_r and neg_r_
    element_t neg_r, neg_r_;
    element_init_Zr(neg_r, pairing);
    element_init_Zr(neg_r_, pairing);
    element_neg(neg_r, r);
    element_neg(neg_r_, r_);

    // compute R0=v^(-r)
    element_t R0;
    element_init_G1(R0, pairing);
    element_pow_zn(R0, v, neg_r);
    res->insertComponent("R0", "G1", R0);

    // compute R0'=v^(-r')
    element_t R0_;
    element_init_G1(R0_, pairing);
    element_pow_zn(R0_, v, neg_r_);
    res->insertComponent("R0_", "G1", R0_);

    element_t Ri, Ri_;
    element_init_G1(Ri, pairing);
    element_init_G1(Ri_, pairing);
    string sstr = "R";
    for (signed long int i = ID->length() + 1; i <= q; ++i) {
        sprintf(num, "%ld", i);
        element_pow_zn(Ri, public_key->getComponent(str + num), r);
        res->insertComponent(sstr + num, "G1", Ri);
        element_pow_zn(Ri_, public_key->getComponent(str + num), r_);
        res->insertComponent(sstr + num + "_", "G1", Ri_);

    }

    return res;
}

Key* HCET::authDelegate(Key *public_key, Key *SKID, element_t_vector *ID) {
    Key *res = new Key();

    // randomly choose rtilde, rtilde_
    element_t rtilde, rtilde_;
    element_init_Zr(rtilde, pairing);
    element_init_Zr(rtilde_, pairing);
    element_random(rtilde);
    element_random(rtilde_);

    // compute neg_rtilde, neg_rtilde_
    element_t neg_rtilde, neg_rtilde_;
    element_init_Zr(neg_rtilde, pairing);
    element_init_Zr(neg_rtilde_, pairing);
    element_neg(neg_rtilde, rtilde);
    element_neg(neg_rtilde_, rtilde_);

    // obtain public parameters
    element_t g, u, h, w, v, g1, g1_, g2, g3;
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
    element_init_same_as(g1, public_key->getComponent("g1"));
    element_set(g1, public_key->getComponent("g1"));
    element_init_same_as(g1_, public_key->getComponent("g1_"));
    element_set(g1_, public_key->getComponent("g1_"));
    element_init_same_as(g2, public_key->getComponent("g2"));
    element_set(g2, public_key->getComponent("g2"));
    element_init_same_as(g3, public_key->getComponent("g3"));
    element_set(g3, public_key->getComponent("g3"));

    // obtain K0bar, K0bar_, K1bar, K1bar_, R0bar, R0bar_
    element_t K0bar, K0bar_, K1bar, K1bar_, R0bar, R0bar_;
    element_init_G1(K0bar, pairing);
    element_init_G1(K0bar_, pairing);
    element_init_G1(K1bar, pairing);
    element_init_G1(K1bar_, pairing);
    element_init_G1(R0bar, pairing);
    element_init_G1(R0bar_, pairing);
    element_set(K0bar, SKID->getComponent("K0"));
    element_set(K0bar_, SKID->getComponent("K0_"));
    element_set(K1bar, SKID->getComponent("K1"));
    element_set(K1bar_, SKID->getComponent("K1_"));
    element_set(R0bar, SKID->getComponent("R0"));
    element_set(R0bar_, SKID->getComponent("R0_"));

    // compute h1^I1*...*hj^Ij
    element_t hs_Is;
    element_init_G1(hs_Is, pairing);
    element_t h_I;
    element_init_G1(h_I, pairing);
    string str = "h";
    char num[21];
    for (signed long int i = 1; i <= ID->length(); ++i) {
        sprintf(num, "%ld", i);
        element_pow_zn(h_I, public_key->getComponent(str + num), ID->getElement(i - 1));

        if (i == 1) {
            element_set(hs_Is, h_I);
        } else {
            element_mul(hs_Is, hs_Is, h_I);
        }
    }

    // compute h1^I1*...*hj^Ij*g3
    element_t hs_Is_g3;
    element_init_G1(hs_Is_g3, pairing);
    element_mul(hs_Is_g3, hs_Is, g3);

    // compute h1^I1*...*hj^Ij*g3*w
    element_t hs_Is_g3_w;
    element_init_G1(hs_Is_g3_w, pairing);
    element_mul(hs_Is_g3_w, hs_Is_g3, w);

    // compute (h1^I1*...*hj^Ij*g3*w)^rtilde
    element_t hs_Is_g3_w_rtilde;
    element_init_G1(hs_Is_g3_w_rtilde, pairing);
    element_pow_zn(hs_Is_g3_w_rtilde, hs_Is_g3_w, rtilde);

    // compute (h1^I1*...*hj^Ij*g3*w)^rtilde'
    element_t hs_Is_g3_w_rtilde_;
    element_init_G1(hs_Is_g3_w_rtilde_, pairing);
    element_pow_zn(hs_Is_g3_w_rtilde_, hs_Is_g3_w, rtilde_);

    element_t Ribar, Ribar_;
    element_init_G1(Ribar, pairing);
    element_init_G1(Ribar_, pairing);
    string sstr = "R";
    element_t R_I;
    element_init_G1(R_I, pairing);

    // obtain Rjbar and Rjbar'
    sprintf(num, "%ld", ID->length());
    element_set(Ribar, SKID->getComponent(sstr + num));
    element_set(Ribar_, SKID->getComponent(sstr + num + "_"));
    // compute K0=K0bar*Rjbar^Ij*(h1^I1*...*hj^Ij*g3*w)^rtilde
    // compute Rjbar^Ij
    element_pow_zn(R_I, Ribar, ID->getElement(ID->length() - 1));
    // compute K0bar*Rjbar^Ij
    element_t K0bar_Rjbar_Ij;
    element_init_G1(K0bar_Rjbar_Ij, pairing);
    element_mul(K0bar_Rjbar_Ij, K0bar, R_I);
    // compute K0
    element_t K0;
    element_init_G1(K0, pairing);
    element_mul(K0, K0bar_Rjbar_Ij, hs_Is_g3_w_rtilde);
    res->insertComponent("K0", "G1", K0);
    // compute K0'=K0bar'*Rjbar'^Ij*(h1^I1*...*hj^Ij*g3*w)^rtilde'
    // compute Rjbar'^Ij
    element_pow_zn(R_I, Ribar_, ID->getElement(ID->length() - 1));
    // compute K0bar'*Rjbar'^Ij
    element_t K0bar__Rjbar__Ij;
    element_init_G1(K0bar__Rjbar__Ij, pairing);
    element_mul(K0bar__Rjbar__Ij, K0bar_, R_I);
    // compute K0'
    element_t K0_;
    element_init_G1(K0_, pairing);
    element_mul(K0_, K0bar__Rjbar__Ij, hs_Is_g3_w_rtilde_);
    res->insertComponent("K0_", "G1", K0_);

    // compute g^rtilde
    element_t g_rtilde;
    element_init_G1(g_rtilde, pairing);
    element_pow_zn(g_rtilde, g, rtilde);

    // compute g^rtilde'
    element_t g_rtilde_;
    element_init_G1(g_rtilde_, pairing);
    element_pow_zn(g_rtilde_, g, rtilde_);

    // compute K1=K1bar*g^rtilde
    element_t K1;
    element_init_G1(K1, pairing);
    element_mul(K1, K1bar, g_rtilde);
    res->insertComponent("K1", "G1", K1);

    // compute K1'=K1bar'*g^rtilde'
    element_t K1_;
    element_init_G1(K1_, pairing);
    element_mul(K1_, K1bar_, g_rtilde_);
    res->insertComponent("K1_", "G1", K1_);

    // compute v^(-rtilde)
    element_t v_neg_rtilde;
    element_init_G1(v_neg_rtilde, pairing);
    element_pow_zn(v_neg_rtilde, v, neg_rtilde);

    // compute v^(-rtilde')
    element_t v_neg_rtilde_;
    element_init_G1(v_neg_rtilde_, pairing);
    element_pow_zn(v_neg_rtilde_, v, neg_rtilde_);

    // compute R0=R0bar*v^(-rtilde)
    element_t R0;
    element_init_G1(R0, pairing);
    element_mul(R0, R0bar, v_neg_rtilde);
    res->insertComponent("R0", "G1", R0);

    // compute R0'=R0bar'*v^(-rtilde')
    element_t R0_;
    element_init_G1(R0_, pairing);
    element_mul(R0_, R0bar_, v_neg_rtilde_);
    res->insertComponent("R0_", "G1", R0_);

    // compute Ri and Ri' from i=j+1 to i=q
    element_t h_r;
    element_t h_r_;
    element_init_G1(h_r, pairing);
    element_init_G1(h_r_, pairing);
    element_t Ri, Ri_;
    element_init_G1(Ri, pairing);
    element_init_G1(Ri_, pairing);
    for (signed long int i = ID->length() + 1; i <= q; ++i) {
        sprintf(num, "%ld", i);
        element_pow_zn(h_r, public_key->getComponent(str + num), rtilde);
        element_pow_zn(h_r_, public_key->getComponent(str + num ), rtilde_);
        element_set(Ribar, SKID->getComponent(sstr + num));
        element_set(Ribar_, SKID->getComponent(sstr + num + "_"));

        // compute Ri
        element_mul(Ri, Ribar, h_r);
        res->insertComponent(sstr + num, "G1", Ri);

        // compute Ri'
        element_mul(Ri_, Ribar_, h_r_);
        res->insertComponent(sstr + num + "_", "G1", Ri_);
    }

    return res;
}