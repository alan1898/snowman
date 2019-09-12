//
// Created by alan on 19-9-12.
//

#include "HABE.h"

element_s* HABE::computeXdelte(Ciphertext_HCET *ciphertext, SecretKey *key_x, string pre_s, string post_s) {
    // get structure
    map<string, access_structure*>::iterator iterator1 = ciphertext->getAA()->find(*(key_x->getKgcName()));
    access_structure *structure = iterator1->second;
    // compute wi
    utils util;
    map<signed long int, signed long int>* matchedAttributes = util.attributesMatching(key_x->getAttributes(), structure->getRho());
    element_t_matrix* attributesMatrix = util.getAttributesMatrix(structure->getM(), matchedAttributes);
    map<signed long int, signed long int>* x_to_attributes = util.xToAttributes(structure->getM(), matchedAttributes);
    element_t_matrix* inverse_M = util.inverse(attributesMatrix);
    element_t_vector* unit = util.getCoordinateAxisUnitVector(inverse_M);
    element_t_vector* x= new element_t_vector(inverse_M->col(), inverse_M->getElement(0, 0));
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

    //init
    //------------------------------------------------------------------------------------------------------------------
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
    //------------------------------------------------------------------------------------------------------------------

    map<signed long int, signed long int>::iterator it;
    for (it = matchedAttributes->begin(); it != matchedAttributes->end(); ++it) {
        // get attribute
        string attr = (*(key_x->getAttributes()))[it->second];

        // get Ci1, K1, Ci2, Ktau2, Ci3, Ktau3
        element_set(Ci1, ciphertext->getComponent("C" + *(key_x->getKgcName()) + attr + "1"));
        element_set(Ci2, ciphertext->getComponent("C" + *(key_x->getKgcName()) + attr + "2"));
        element_set(Ktau2, key_x->getComponent(pre_s + attr + "2" + post_s));
        element_set(Ci3, ciphertext->getComponent("C" + *(key_x->getKgcName()) + attr + "3"));
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

    // obtain Cj0
    element_t Cj0;
    element_init_G1(Cj0, pairing);
    element_set(Cj0, ciphertext->getComponent("C" + *(key_x->getKgcName()) + "0"));

    // compute e(Cj0,K1)
    element_t e_Cj0K1;
    element_init_GT(e_Cj0K1, pairing);
    element_pairing(e_Cj0K1, Cj0, K1);

    element_mul(denominator, e_Cj0K1, denominator);

    element_t *res = new element_t[1];
    element_init_GT(*res, pairing);
    element_div(*res, e_C0_K0, denominator);

    return *res;
}

HABE::HABE() {
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

vector<Key*>* HABE::setUp(signed long int q) {
    this->q = q;

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

    // randomly choose alpha
    element_t alpha;
    element_init_Zr(alpha, pairing);
    element_random(alpha);

    // compute g1=g^alpha
    element_t g1;
    element_init_G1(g1, pairing);
    element_pow_zn(g1, g, alpha);

    // compute g2_alpha
    element_t g2_alpha;
    element_init_G1(g2_alpha, pairing);
    element_pow_zn(g2_alpha, g2, alpha);

    Key *master_key = new Key(Key::MASTER);
    Key *public_key = new Key(Key::PUBLIC);

    master_key->insertComponent("g2_alpha", "G1", g2_alpha);
    public_key->insertComponent("g", "G1", g);
    public_key->insertComponent("u", "G1", u);
    public_key->insertComponent("h", "G1", h);
    public_key->insertComponent("w", "G1", w);
    public_key->insertComponent("v", "G1", v);
    public_key->insertComponent("g1", "G1", g1);
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

    vector<Key*> *res = new vector<Key*>(2);
    (*res)[0] = master_key;
    (*res)[1] = public_key;

    return res;
}

Key* HABE::authKeyGen(Key *public_key, Key *master_key, element_t_vector *ID) {
    Key *res = new Key();

    // randomly choose r
    element_t r;
    element_init_Zr(r, pairing);
    element_random(r);

    // obtain public parameters
    element_t g, u, h, w, v, g1, g2, g3;
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
    element_init_same_as(g2, public_key->getComponent("g2"));
    element_set(g2, public_key->getComponent("g2"));
    element_init_same_as(g3, public_key->getComponent("g3"));
    element_set(g3, public_key->getComponent("g3"));

    // obtain master key
    element_t g2_alpha;
    element_init_same_as(g2_alpha, master_key->getComponent("g2_alpha"));
    element_set(g2_alpha, master_key->getComponent("g2_alpha"));

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

    // compute K1=g^r
    element_t K1;
    element_init_G1(K1, pairing);
    element_pow_zn(K1, g, r);
    res->insertComponent("K1", "G1", K1);

    // compute neg_r and neg_r_
    element_t neg_r;
    element_init_Zr(neg_r, pairing);
    element_neg(neg_r, r);

    // compute R0=v^(-r)
    element_t R0;
    element_init_G1(R0, pairing);
    element_pow_zn(R0, v, neg_r);
    res->insertComponent("R0", "G1", R0);

    element_t Ri;
    element_init_G1(Ri, pairing);
    string sstr = "R";
    for (signed long int i = ID->length() + 1; i <= q; ++i) {
        sprintf(num, "%ld", i);
        element_pow_zn(Ri, public_key->getComponent(str + num), r);
        res->insertComponent(sstr + num, "G1", Ri);
    }

    return res;
}

Key* HABE::authDelegate(Key *public_key, Key *SKID, element_t_vector *ID) {
    Key *res = new Key();

    // randomly choose rtilde
    element_t rtilde;
    element_init_Zr(rtilde, pairing);
    element_random(rtilde);

    // compute neg_rtilde
    element_t neg_rtilde;
    element_init_Zr(neg_rtilde, pairing);
    element_neg(neg_rtilde, rtilde);

    // obtain public parameters
    element_t g, u, h, w, v, g1, g2, g3;
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
    element_init_same_as(g2, public_key->getComponent("g2"));
    element_set(g2, public_key->getComponent("g2"));
    element_init_same_as(g3, public_key->getComponent("g3"));
    element_set(g3, public_key->getComponent("g3"));

    // obtain K0bar, K1bar, R0bar
    element_t K0bar, K1bar, R0bar;
    element_init_G1(K0bar, pairing);
    element_init_G1(K1bar, pairing);
    element_init_G1(R0bar, pairing);
    element_set(K0bar, SKID->getComponent("K0"));
    element_set(K1bar, SKID->getComponent("K1"));
    element_set(R0bar, SKID->getComponent("R0"));

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

    element_t Ribar;
    element_init_G1(Ribar, pairing);
    string sstr = "R";
    element_t R_I;
    element_init_G1(R_I, pairing);

    // obtain Rjbar and Rjbar'
    sprintf(num, "%ld", ID->length());
    element_set(Ribar, SKID->getComponent(sstr + num));
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

    // compute g^rtilde
    element_t g_rtilde;
    element_init_G1(g_rtilde, pairing);
    element_pow_zn(g_rtilde, g, rtilde);

    // compute K1=K1bar*g^rtilde
    element_t K1;
    element_init_G1(K1, pairing);
    element_mul(K1, K1bar, g_rtilde);
    res->insertComponent("K1", "G1", K1);

    // compute v^(-rtilde)
    element_t v_neg_rtilde;
    element_init_G1(v_neg_rtilde, pairing);
    element_pow_zn(v_neg_rtilde, v, neg_rtilde);

    // compute R0=R0bar*v^(-rtilde)
    element_t R0;
    element_init_G1(R0, pairing);
    element_mul(R0, R0bar, v_neg_rtilde);
    res->insertComponent("R0", "G1", R0);

    // compute Ri and Ri' from i=j+1 to i=q
    element_t h_r;
    element_init_G1(h_r, pairing);
    element_t Ri;
    element_init_G1(Ri, pairing);
    for (signed long int i = ID->length() + 1; i <= q; ++i) {
        sprintf(num, "%ld", i);
        element_pow_zn(h_r, public_key->getComponent(str + num), rtilde);
        element_set(Ribar, SKID->getComponent(sstr + num));

        // compute Ri
        element_mul(Ri, Ribar, h_r);
        res->insertComponent(sstr + num, "G1", Ri);
    }

    return res;
}

SecretKey* HABE::userKeyGen(Key *public_key, Key *SKID, element_t_vector *ID, string *kgc_name,
                            vector<string> *attributes) {
    SecretKey *res = new SecretKey(attributes, kgc_name);

    // randomly choose rtilde
    element_t rtilde;
    element_init_Zr(rtilde, pairing);
    element_random(rtilde);

    // compute neg_rtilde
    element_t neg_rtilde;
    element_init_Zr(neg_rtilde, pairing);
    element_neg(neg_rtilde, rtilde);

    // obtain public parameters
    element_t g, u, h, w, v, g1, g2, g3;
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
    element_init_same_as(g2, public_key->getComponent("g2"));
    element_set(g2, public_key->getComponent("g2"));
    element_init_same_as(g3, public_key->getComponent("g3"));
    element_set(g3, public_key->getComponent("g3"));

    // obtain K0bar, K1bar, R0bar
    element_t K0bar, K1bar, R0bar;
    element_init_G1(K0bar, pairing);
    element_init_G1(K1bar, pairing);
    element_init_G1(R0bar, pairing);
    element_set(K0bar, SKID->getComponent("K0"));
    element_set(K1bar, SKID->getComponent("K1"));
    element_set(R0bar, SKID->getComponent("R0"));

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

    // compute g^rtilde
    element_t g_rtilde;
    element_init_G1(g_rtilde, pairing);
    element_pow_zn(g_rtilde, g, rtilde);

    // compute K0
    element_t K0;
    element_init_G1(K0, pairing);
    element_mul(K0, K0bar, hs_Is_g3_w_rtilde);
    res->insertComponent("K0", "G1", K0);

    // compute K1
    element_t K1;
    element_init_G1(K1, pairing);
    element_mul(K1, K1bar, g_rtilde);
    res->insertComponent("K1", "G1", K1);

    // compute v^(-rtilde)
    element_t v_neg_rtilde;
    element_init_G1(v_neg_rtilde, pairing);
    element_pow_zn(v_neg_rtilde, v, neg_rtilde);

    // compute R0bar*v^(-rtilde)
    element_t R0bar_v_neg_rtilde;
    element_init_G1(R0bar_v_neg_rtilde, pairing);
    element_mul(R0bar_v_neg_rtilde, R0bar, v_neg_rtilde);

    element_t rtau;
    element_init_Zr(rtau, pairing);
    element_t Ktau2, Ktau3;
    element_init_G1(Ktau2, pairing);
    element_init_G1(Ktau3, pairing);
    element_t Atau;
    element_init_Zr(Atau, pairing);
    element_t u_Atau, u_Atau_h, u_Atau_h_rtau, u_Atau_h_rtau_;
    element_init_G1(u_Atau, pairing);
    element_init_G1(u_Atau_h, pairing);
    element_init_G1(u_Atau_h_rtau, pairing);
    element_init_G1(u_Atau_h_rtau_, pairing);
    for (signed long int i = 0; i < attributes->size(); ++i) {
        // randomly choose rtau, rtau'
        element_random(rtau);

        // compute Ktau2
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

        // compute Ktau3
        element_mul(Ktau3, u_Atau_h_rtau, R0bar_v_neg_rtilde);
        res->insertComponent("K" + (*attributes)[i] + "3", "G1", Ktau3);
    }

    return res;
}

Ciphertext_HCET* HABE::encrypt(Key *public_key, map<string, access_structure *> *AA, element_s *m) {
    Ciphertext_HCET *res = new Ciphertext_HCET(AA);

    utils util;

    // obtain public parameters
    element_t g, u, h, w, v, g1, g2, g3;
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
    element_init_same_as(g2, public_key->getComponent("g2"));
    element_set(g2, public_key->getComponent("g2"));
    element_init_same_as(g3, public_key->getComponent("g3"));
    element_set(g3, public_key->getComponent("g3"));

    // randomly choose s
    element_t s;
    element_init_Zr(s, pairing);
    element_random(s);

    element_t sj;
    element_init_Zr(sj, pairing);
    element_t s_sj;
    element_init_Zr(s_sj, pairing);

    extend_math_operation emo;

    // compute e(g1,g2)
    element_t e_g1g2;
    element_init_GT(e_g1g2, pairing);
    element_pairing(e_g1g2, g1, g2);

    // compute e(g1,g2)^s
    element_t e_g1g2_s;
    element_init_GT(e_g1g2_s, pairing);
    element_pow_zn(e_g1g2_s, e_g1g2, s);

    // compute C=m*e(g1,g2)^s
    element_t C;
    element_init_GT(C, pairing);
    element_mul(C, m, e_g1g2_s);
    res->insertComponent("C", "GT", C);

    // compute C0=g^s
    element_t C0;
    element_init_G1(C0, pairing);
    element_pow_zn(C0, g, s);
    res->insertComponent("C0", "G1", C0);

    //init
    //------------------------------------------------------------------------------------------------------------------
    element_t hs_Is;
    element_init_G1(hs_Is, pairing);
    element_t h_I;
    element_init_G1(h_I, pairing);
    string str = "h";
    char num[21];
    //------------------------------------------------------------------------------------------------------------------
    element_t hs_Is_g3;
    element_init_G1(hs_Is_g3, pairing);
    element_t hs_Is_g3_s;
    element_init_G1(hs_Is_g3_s, pairing);
    element_t w_sj;
    element_init_G1(w_sj, pairing);
    element_t Cj0;
    element_init_G1(Cj0, pairing);
    //------------------------------------------------------------------------------------------------------------------
    element_t tjtau;
    element_init_Zr(tjtau, pairing);
    element_t rhojtau;
    element_init_Zr(rhojtau, pairing);
    element_t w_lambdajtau;
    element_init_G1(w_lambdajtau, pairing);
    element_t v_tjtau;
    element_init_G1(v_tjtau, pairing);
    element_t Cjtau1;
    element_init_G1(Cjtau1, pairing);
    element_t u_rhojtau;
    element_init_G1(u_rhojtau, pairing);
    element_t u_rhojtau_h;
    element_init_G1(u_rhojtau_h, pairing);
    element_t neg_tjtau;
    element_init_Zr(neg_tjtau, pairing);
    element_t Cjtau2;
    element_init_G1(Cjtau2, pairing);
    element_t Cjtau3;
    element_init_G1(Cjtau3, pairing);
    //------------------------------------------------------------------------------------------------------------------
    map<string, access_structure*>::iterator iterator1;
    for (iterator1 = AA->begin(); iterator1 != AA->end(); ++iterator1) {
        // randomly choose sj
        element_random(sj);

        // a random vector
        element_t_vector *zj = new element_t_vector(iterator1->second->getM()->col(), zr_sample);
        element_sub(s_sj, s, sj);
        element_set(zj->getElement(0), s_sj);
        for (signed long int k = 1; k < zj->length(); ++k) {
            element_random(zj->getElement(k));
        }

        // compute shares
        element_t_vector *lambdaj = emo.multiply(iterator1->second->getM(), zj);

        // compute h1^Ij1*h2^Ij2*...*hyj^Ijyj
        for (signed long int ji = 1; ji <= iterator1->second->getID()->length(); ++ji) {
            sprintf(num, "%ld", ji);
            element_pow_zn(h_I, public_key->getComponent(str + num), iterator1->second->getID()->getElement(ji - 1));

            if (ji == 1) {
                element_set(hs_Is, h_I);
            } else {
                element_mul(hs_Is, hs_Is, h_I);
            }
        }
        // compute h1^Ij1*h2^Ij2*...*hyj^Ijyj*g3
        element_mul(hs_Is_g3, hs_Is, g3);
        // compute (h1^Ij1*h2^Ij2*...*hyj^Ijyj*g3)^s
        element_pow_zn(hs_Is_g3_s, hs_Is_g3, s);
        // compute w^sj
        element_pow_zn(w_sj, w, sj);
        // compute Cj0
        element_mul(Cj0, hs_Is_g3_s, w_sj);
        res->insertComponent("C" + *(iterator1->second->getName()) + "0", "G1", Cj0);

        for (signed long int jtau = 0; jtau < iterator1->second->getM()->row(); ++jtau) {
            // randomly choose tjtau
            element_random(tjtau);

            // get rhojtau
            map<signed long int, string>::iterator it = iterator1->second->getRho()->find(jtau);
            string attr = it->second;
            element_set(rhojtau, util.stringToElementT(attr, "ZR", &pairing));

            // compute w^lambdajtau
            element_pow_zn(w_lambdajtau, w, lambdaj->getElement(jtau));
            // compute v^tjtau
            element_pow_zn(v_tjtau, v, tjtau);
            // compute Cjtau1
            element_mul(Cjtau1, w_lambdajtau, v_tjtau);
            res->insertComponent("C" + *(iterator1->second->getName()) + attr + "1", "G1", Cjtau1);

            // compute u^rhojtau
            element_pow_zn(u_rhojtau, u, rhojtau);
            // compute u^rhojtau*h
            element_mul(u_rhojtau_h, u_rhojtau, h);
            // compute -tjtau
            element_neg(neg_tjtau, tjtau);
            // compute Cjtau2
            element_pow_zn(Cjtau2, u_rhojtau_h, neg_tjtau);
            res->insertComponent("C" + *(iterator1->second->getName()) + attr + "2", "G1", Cjtau2);

            // compute Cjtau3
            element_pow_zn(Cjtau3, g, tjtau);
            res->insertComponent("C" + *(iterator1->second->getName()) + attr + "3", "G1", Cjtau3);
        }
    }

    return res;
}

element_s* HABE::decrypt(Ciphertext_HCET *ciphertext_hcet, SecretKey *secret_key) {
    map<string, access_structure*>::iterator iterator1 = ciphertext_hcet->getAA()->find(*(secret_key->getKgcName()));

    element_t B;
    element_init_GT(B, pairing);
    element_set(B, computeXdelte(ciphertext_hcet, secret_key, "K", ""));

    // get C
    element_t C;
    element_init_GT(C, pairing);
    element_set(C, ciphertext_hcet->getComponent("C"));

    element_t *res = new element_t[1];
    element_init_GT(*res, pairing);
    element_div(*res, C, B);

    return *res;
}