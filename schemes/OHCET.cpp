//
// Created by alan on 19-9-11.
//

#include "OHCET.h"

element_s* OHCET::H1(element_s *e) {
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

unsigned char* OHCET::H2(element_s *e) {
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

element_s* OHCET::computeXdelte(Ciphertext_HCET *ciphertext, SecretKey *key_x, string pre_s, string post_s) {
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

element_s* OHCET::computeVj(Ciphertext_HCET *ct, Key *sp_ch, Key *pk_ch, element_s *r_ch,
                            access_structure *structure) {
    element_t *res = new element_t[1];
    element_init_Zr(*res, pairing);

    int n_total = g1_length + g1_length + 8 + zr_length + g1_length + g1_length + g1_length + (structure->getM()->row() * g1_length);
    unsigned char* str = (unsigned char*)malloc(n_total + 1);
    int str_index = 0;

    // add y of pk_ch
    element_to_bytes(str + str_index, pk_ch->getComponent("y"));
    str_index += g1_length;
//    cout << "y" << endl;

    // add C
    element_to_bytes(str + str_index, ct->getComponent("C"));
    str_index += g1_length;
//    cout << "C" << endl;

    // add C*
    for (signed long int i = 0; i < 8 + zr_length; ++i) {
        str[str_index] = ct->Cstar[i];
        str_index++;
    }
//    cout << "Cstar" << endl;

    // add C0
    element_to_bytes(str + str_index, ct->getComponent("C0"));
    str_index += g1_length;
//    cout << "C0" << endl;

    // add C0'
    element_to_bytes(str + str_index, ct->getComponent("C0_"));
    str_index += g1_length;
//    cout << "C0_" << endl;

    // add Cj03
    element_to_bytes(str + str_index, ct->getComponent("C" + *(structure->getName()) + "03"));
    str_index += g1_length;
//    cout << "Cj03" << endl;

    // add Cjtau3
    for (signed long int i = 0; i < structure->getM()->row(); ++i) {
        map<signed long int, string>::iterator it = structure->getRho()->find(i);
        string attr = it->second;
        element_to_bytes(str + str_index, ct->getComponent("C" + *(structure->getName()) + attr + "3"));
        str_index += g1_length;
    }

    str[str_index] = '\0';
//    cout << "Cjtau3" << endl;

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

OHCET::OHCET() {
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

vector<Key*>* OHCET::setUp(signed long int q) {
    this->q = q;

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

Key* OHCET::authKeyGen(Key *public_key, Key *master_key, element_t_vector *ID) {
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

    // compute K0'=g2^alpha'*(h1^I1*...*hj^Ij*g3*w)^r'
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

Key* OHCET::authDelegate(Key *public_key, Key *SKID, element_t_vector *ID) {
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

vector<SecretKey*>* OHCET::userKeyGen(Key *public_key, Key *SKID, element_t_vector *ID, string *kgc_name,
                                      vector<string> *attributes) {
    vector<SecretKey*> *res = new vector<SecretKey*>(2);

    SecretKey *res1 = new SecretKey(attributes, kgc_name);
    SecretKey *res2 = new SecretKey();

    // randomly choose rtilde, rtilde_
    element_t rtilde, rtilde_;
    element_init_Zr(rtilde, pairing);
    element_init_Zr(rtilde_, pairing);
    element_random(rtilde);
    element_random(rtilde_);

    // randomly choose o, o'
    element_t o, o_;
    element_init_Zr(o, pairing);
    element_init_Zr(o_, pairing);
    element_random(o);
    element_random(o_);

    // compute o^(-1), o'^(-1)
    element_t inv_o, inv_o_;
    element_init_Zr(inv_o, pairing);
    element_init_Zr(inv_o_, pairing);
    element_invert(inv_o, o);
    element_invert(inv_o_, o_);

    // compute rtilde/o, rtilde'/o'
    element_t rtilde_o, rtilde__o_;
    element_init_Zr(rtilde_o, pairing);
    element_init_Zr(rtilde__o_, pairing);
    element_div(rtilde_o, rtilde, o);
    element_div(rtilde__o_, rtilde_, o_);

    // compute -rtilde/o, -rtilde'/o'
    element_t neg_rtilde_o, neg_rtilde__o_;
    element_init_Zr(neg_rtilde_o, pairing);
    element_init_Zr(neg_rtilde__o_, pairing);
    element_neg(neg_rtilde_o, rtilde_o);
    element_neg(neg_rtilde__o_, rtilde__o_);

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

    // compute K0bar^(1/o), K0bar'^(1/o')
    element_t K0bar_inv_o, K0bar__inv_o_;
    element_init_G1(K0bar_inv_o, pairing);
    element_init_G1(K0bar__inv_o_, pairing);
    element_pow_zn(K0bar_inv_o, K0bar, inv_o);
    element_pow_zn(K0bar__inv_o_, K0bar_, inv_o_);

    // compute K1bar^(1/o), K1bar'^(1/o')
    element_t K1bar_inv_o, K1bar__inv_o_;
    element_init_G1(K1bar_inv_o, pairing);
    element_init_G1(K1bar__inv_o_, pairing);
    element_pow_zn(K1bar_inv_o, K1bar, inv_o);
    element_pow_zn(K1bar__inv_o_, K1bar_, inv_o_);

    // compute R0bar^(1/o), R0bar'^(1/o')
    element_t R0bar_inv_o, R0bar__inv_o_;
    element_init_G1(R0bar_inv_o, pairing);
    element_init_G1(R0bar__inv_o_, pairing);
    element_pow_zn(R0bar_inv_o, R0bar, inv_o);
    element_pow_zn(R0bar__inv_o_, R0bar_, inv_o_);

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

    // compute (h1^I1*...*hj^Ij*g3*w)^(rtilde/o)
    element_t hs_Is_g3_w_rtilde_o;
    element_init_G1(hs_Is_g3_w_rtilde_o, pairing);
    element_pow_zn(hs_Is_g3_w_rtilde_o, hs_Is_g3_w, rtilde_o);

    // compute (h1^I1*...*hj^Ij*g3*w)^(rtilde'/o')
    element_t hs_Is_g3_w_rtilde__o_;
    element_init_G1(hs_Is_g3_w_rtilde__o_, pairing);
    element_pow_zn(hs_Is_g3_w_rtilde__o_, hs_Is_g3_w, rtilde__o_);

    // compute g^(rtilde/o)
    element_t g_rtilde_o;
    element_init_G1(g_rtilde_o, pairing);
    element_pow_zn(g_rtilde_o, g, rtilde_o);

    // compute g^(rtilde'/o')
    element_t g_rtilde__o_;
    element_init_G1(g_rtilde__o_, pairing);
    element_pow_zn(g_rtilde__o_, g, rtilde__o_);

    // compute K0
    element_t K0;
    element_init_G1(K0, pairing);
    element_mul(K0, K0bar_inv_o, hs_Is_g3_w_rtilde_o);
    res1->insertComponent("K0", "G1", K0);

    // compute K0'
    element_t K0_;
    element_init_G1(K0_, pairing);
    element_mul(K0_, K0bar__inv_o_, hs_Is_g3_w_rtilde__o_);
    res1->insertComponent("K0_", "G1", K0_);

    // compute K1
    element_t K1;
    element_init_G1(K1, pairing);
    element_mul(K1, K1bar_inv_o, g_rtilde_o);
    res1->insertComponent("K1", "G1", K1);

    // compute K1'
    element_t K1_;
    element_init_G1(K1_, pairing);
    element_mul(K1_, K1bar__inv_o_, g_rtilde__o_);
    res1->insertComponent("K1_", "G1", K1_);

    // compute v^(-rtilde/o)
    element_t v_neg_rtilde_o;
    element_init_G1(v_neg_rtilde_o, pairing);
    element_pow_zn(v_neg_rtilde_o, v, neg_rtilde_o);

    // compute v^(-rtilde'/o')
    element_t v_neg_rtilde__o_;
    element_init_G1(v_neg_rtilde__o_, pairing);
    element_pow_zn(v_neg_rtilde__o_, v, neg_rtilde__o_);

    // compute R0bar^(1/o)*v^(-rtilde/o)
    element_t R0bar_inv_o_v_neg_rtilde_o;
    element_init_G1(R0bar_inv_o_v_neg_rtilde_o, pairing);
    element_mul(R0bar_inv_o_v_neg_rtilde_o, R0bar_inv_o, v_neg_rtilde_o);

    // compute R0bar'^(1/o')*v^(-rtilde'/o')
    element_t R0bar__inv_o__v_neg_rtilde__o_;
    element_init_G1(R0bar__inv_o__v_neg_rtilde__o_, pairing);
    element_mul(R0bar__inv_o__v_neg_rtilde__o_, R0bar__inv_o_, v_neg_rtilde__o_);

    element_t rtau, rtau_;
    element_init_Zr(rtau, pairing);
    element_init_Zr(rtau_, pairing);
    element_t Ktau2, Ktau3, Ktau2_, Ktau3_;
    element_init_G1(Ktau2, pairing);
    element_init_G1(Ktau3, pairing);
    element_init_G1(Ktau2_, pairing);
    element_init_G1(Ktau3_, pairing);
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
        element_random(rtau_);

        // compute Ktau2
        element_pow_zn(Ktau2, g, rtau);
        res1->insertComponent("K" + (*attributes)[i] + "2", "G1", Ktau2);

        // compute Ktau2'
        element_pow_zn(Ktau2_, g, rtau_);
        res1->insertComponent("K" + (*attributes)[i] + "2_", "G1", Ktau2_);

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

        // compute (u^Atau*h)^rtau'
        element_pow_zn(u_Atau_h_rtau_, u_Atau_h, rtau_);

        // compute Ktau3
        element_mul(Ktau3, u_Atau_h_rtau, R0bar_inv_o_v_neg_rtilde_o);
        res1->insertComponent("K" + (*attributes)[i] + "3", "G1", Ktau3);

        // compute Ktau3'
        element_mul(Ktau3_, u_Atau_h_rtau_, R0bar__inv_o__v_neg_rtilde__o_);
        res1->insertComponent("K" + (*attributes)[i] + "3_", "G1", Ktau3_);
    }

    // DKs=(o,o')
    res2->insertComponent("o", "ZR", o);
    res2->insertComponent("o_", "ZR", o_);

    (*res)[0] = res1;
    (*res)[1] = res2;

    return res;
}

vector<SecretKey*>* OHCET::trapdoor(vector<SecretKey*> *secret_key) {
    vector<SecretKey*> *res = new vector<SecretKey*>(2);

    SecretKey *res1 = new SecretKey(secret_key->at(0)->getAttributes(), secret_key->at(0)->getKgcName());
    SecretKey *res2 = new SecretKey();

    // obtain K0
    element_t K0;
    element_init_same_as(K0, secret_key->at(0)->getComponent("K0"));
    element_set(K0, secret_key->at(0)->getComponent("K0"));
    res1->insertComponent("T0", "G1", K0);

    // obtain K1
    element_t K1;
    element_init_same_as(K1, secret_key->at(0)->getComponent("K1"));
    element_set(K1, secret_key->at(0)->getComponent("K1"));
    res1->insertComponent("T1", "G1", K1);

    // obtain Ktau2 and Ktau3
    element_t Ktau2, Ktau3;
    element_init_G1(Ktau2, pairing);
    element_init_G1(Ktau3, pairing);
    for (signed long int i = 0; i < secret_key->at(0)->getAttributes()->size(); ++i) {
        element_set(Ktau2, secret_key->at(0)->getComponent("K" + (*secret_key->at(0)->getAttributes())[i] + "2"));
        res1->insertComponent("T" + (*secret_key->at(0)->getAttributes())[i] + "2", "G1", Ktau2);
        element_set(Ktau3, secret_key->at(0)->getComponent("K" + (*secret_key->at(0)->getAttributes())[i] + "3"));
        res1->insertComponent("T" + (*secret_key->at(0)->getAttributes())[i] + "3", "G1", Ktau3);
    }

    // obtain o
    element_t o;
    element_init_same_as(o, secret_key->at(1)->getComponent("o"));
    element_set(o, secret_key->at(1)->getComponent("o"));
    res2->insertComponent("o", "ZR", o);

    (*res)[0] = res1;
    (*res)[1] = res2;

    return res;
}

Ciphertext_HCET* OHCET::encrypt(Key *public_key, map<string, access_structure *> *AA, unsigned char *message,
                                Key *sp_ch, Key *pk_ch) {
    Ciphertext_HCET *res = new Ciphertext_HCET(AA);

    utils util;

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

    // randomly choose s, z
    element_t s, z;
    element_init_Zr(s, pairing);
    element_init_Zr(z, pairing);
    element_random(s);
    element_random(z);

    element_printf("随机选择的z为：%B\n", z);

    element_t sj;
    element_init_Zr(sj, pairing);
    element_t s_sj;
    element_init_Zr(s_sj, pairing);

    extend_math_operation emo;

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

    // compute e(g1,g2)
    element_t e_g1g2;
    element_init_GT(e_g1g2, pairing);
    element_pairing(e_g1g2, g1, g2);

    // compute e(g1,g2)^s
    element_t e_g1g2_s;
    element_init_GT(e_g1g2_s, pairing);
    element_pow_zn(e_g1g2_s, e_g1g2, s);
//    element_printf("e(g1,g2)^s is %B\n", e_g1g2_s);

    // compute H1(e(g1,g2)^s)
    element_t H_1;
    element_init_G1(H_1, pairing);
    element_set(H_1, H1(e_g1g2_s));

    // compute C=m^z*H1(e(g1,g2)^s)
    element_t C;
    element_init_G1(C, pairing);
    element_mul(C, m_z, H_1);
    res->insertComponent("C", "G1", C);

    // compute C0=g^s
    element_t C0;
    element_init_G1(C0, pairing);
    element_pow_zn(C0, g, s);
    res->insertComponent("C0", "G1", C0);

    // compute C0'=g^z
    element_t C0_;
    element_init_G1(C0_, pairing);
    element_pow_zn(C0_, g, z);
    res->insertComponent("C0_", "G1", C0_);

    // compute e(g1',g2)
    element_t e_g1_g2;
    element_init_GT(e_g1_g2, pairing);
    element_pairing(e_g1_g2, g1_, g2);

    // compute e(g1',g2)^s
    element_t e_g1_g2_s;
    element_init_GT(e_g1_g2_s, pairing);
    element_pow_zn(e_g1_g2_s, e_g1_g2, s);
//    element_printf("e(g1',g2)^s is %B\n", e_g1_g2_s);

    // compute H2(e(g1',g2)^s)
    unsigned char *H_2 = H2(e_g1_g2_s);

    unsigned char *mz = (unsigned char*)malloc(8 + zr_length + 1);
    for (signed long int index = 0; index < 8; ++index) {
        mz[index] = message[index];
    }
    element_to_bytes(mz + 8, z);
    mz[8 + zr_length] = '\0';

    // compute C*
    res->Cstar = (unsigned char*)malloc(SHA256_DIGEST_LENGTH +1);
    for (signed long int i = 0; i < 8 + zr_length; ++i) {
        int Cvalue = (int)mz[i] ^ (int)H_2[i];
        res->Cstar[i] = (unsigned char)Cvalue;
    }
    res->Cstar[SHA256_DIGEST_LENGTH] = '\0';

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
    element_t tj0;
    element_init_Zr(tj0, pairing);
    element_t Cj03;
    element_init_G1(Cj03, pairing);
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
    element_t rchj;
    element_init_Zr(rchj, pairing);
    element_t Vj;
    element_init_Zr(Vj, pairing);
    element_t w_s_sj;
    element_init_G1(w_s_sj, pairing);
    element_t v_tj0;
    element_init_G1(v_tj0, pairing);
    element_t Cj01;
    element_init_G1(Cj01, pairing);
    element_t neg_tj0;
    element_init_Zr(neg_tj0, pairing);
    element_t u_Vj;
    element_init_G1(u_Vj, pairing);
    element_t u_Vj_h;
    element_init_G1(u_Vj_h, pairing);
    element_t Cj02;
    element_init_G1(Cj02, pairing);
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

        // randomly choose tj0
        element_random(tj0);

        // compute Cj03
        element_pow_zn(Cj03, g, tj0);
        res->insertComponent("C" + *(iterator1->second->getName()) + "03", "G1", Cj03);

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

        // randomly choose rchj
        element_random(rchj);
        res->insertComponent("rch" + *(iterator1->second->getName()), "ZR", rchj);

        // Vj
        element_set(Vj, computeVj(res, sp_ch, pk_ch, rchj, iterator1->second));

        // compute w^(s-sj)
        element_pow_zn(w_s_sj, w, s_sj);
        // compute v^tj0
        element_pow_zn(v_tj0, v, tj0);
        // compute Cj01
        element_mul(Cj01, w_s_sj, v_tj0);
        res->insertComponent("C" + *(iterator1->second->getName()) + "01", "G1", Cj01);

        // compute neg_tj0
        element_neg(neg_tj0, tj0);
        // compute u^Vj
        element_pow_zn(u_Vj, u, Vj);
        // compute u^Vj*h
        element_mul(u_Vj_h, u_Vj, h);
        // compute Cj02
        element_pow_zn(Cj02, u_Vj_h, neg_tj0);
        res->insertComponent("C" + *(iterator1->second->getName()) + "02", "G1", Cj02);
    }

    return res;
}

Ciphertext_HCET* OHCET::transform(Key *public_key, SecretKey *key_x, string *key_type, Ciphertext_HCET *CT,
                                 Key *sp_ch, Key *pk_ch) {
    Ciphertext_HCET *res = new Ciphertext_HCET();

    // add C
    res->insertComponent("C", "G1", CT->getComponent("C"));

    // add C*
    res->Cstar = (unsigned char*)malloc(SHA256_DIGEST_LENGTH +1);
    for (signed long int i = 0; i <= SHA256_DIGEST_LENGTH + 1; ++i) {
        res->Cstar[i] = CT->Cstar[i];
    }

    // add C0'
    res->insertComponent("C0_", "G1", CT->getComponent("C0_"));

//    cout << "C, Cstar, C0_" << endl;

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

    utils util;

    // step one
    // init
    //------------------------------------------------------------------------------------------------------------------
    element_t Cj02, Cj03;
    element_init_G1(Cj02, pairing);
    element_init_G1(Cj03, pairing);

    element_t u_Vj;
    element_init_G1(u_Vj, pairing);

    element_t u_Vj_h;
    element_init_G1(u_Vj_h, pairing);

    element_t e_gCj02;
    element_init_GT(e_gCj02, pairing);

    element_t e_Cj03uVjh;
    element_init_GT(e_Cj03uVjh, pairing);

    element_t inv_e_Cj03uVjh;
    element_init_GT(inv_e_Cj03uVjh, pairing);
    //------------------------------------------------------------------------------------------------------------------
    element_t Cji2, Cji3;
    element_init_G1(Cji2, pairing);
    element_init_G1(Cji3, pairing);

    element_t e_gCji2;
    element_init_GT(e_gCji2, pairing);

    element_t Aji;
    element_init_Zr(Aji, pairing);
    unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];

    element_t u_Aji;
    element_init_G1(u_Aji, pairing);

    element_t u_Aji_h;
    element_init_G1(u_Aji_h, pairing);

    element_t e_Cji3uAjih;
    element_init_GT(e_Cji3uAjih, pairing);

    element_t inv_e_Cji3uAjih;
    element_init_GT(inv_e_Cji3uAjih, pairing);
    //------------------------------------------------------------------------------------------------------------------
    map<string, access_structure*>::iterator iterator1;
    for (iterator1 = CT->getAA()->begin(); iterator1 != CT->getAA()->end(); ++iterator1) {
        // compute Vj
        element_s *Vj = computeVj(CT, sp_ch, pk_ch, CT->getComponent("rch" + *(iterator1->second->getName())), iterator1->second);
//        cout << "Vj" << endl;

        // obtain Cj02 and Cj03
        element_set(Cj02, CT->getComponent("C" + *(iterator1->second->getName()) + "02"));
//        cout << "Cj02" << endl;
        element_set(Cj03, CT->getComponent("C" + *(iterator1->second->getName()) + "03"));
//        cout << "Cj03" << endl;

        // compute u^VAj
        element_pow_zn(u_Vj, u, Vj);
//        cout << "u^Vj" << endl;

        // compute u^VAj*h
        element_mul(u_Vj_h, u_Vj, h);
//        cout << "u^Vj*h" << endl;

        // compute e(g,Cj02)
        element_pairing(e_gCj02, g, Cj02);
//        cout << "e(g,Cj02)" << endl;

        // compute e(Cj03,u^Vj*h)
        element_pairing(e_Cj03uVjh, Cj03, u_Vj_h);
//        cout << "e(Cj03,u^Vj*h)" << endl;

        // compute e(Cj03,u^Vj*h)^(-1)
        element_invert(inv_e_Cj03uVjh, e_Cj03uVjh);

        if (element_cmp(e_gCj02, inv_e_Cj03uVjh) != 0) {
            cout << "A-1-1" << endl;
            return NULL;
        }

        for (signed long int ji = 0; ji < iterator1->second->getM()->row(); ++ji) {
            map<signed long int, string>::iterator it = iterator1->second->getRho()->find(ji);
            string attr = it->second;

            // obtain Cji2 and Cji3
            element_set(Cji2, CT->getComponent("C" +  *(iterator1->second->getName()) + attr + "2"));
            element_set(Cji3, CT->getComponent("C" +  *(iterator1->second->getName()) + attr + "3"));

            // compute e(g,Cji2)
            element_pairing(e_gCji2, g, Cji2);
//            cout << "e(g,Cji2)" << endl;

            // compute Aji
            SHA256_CTX sha256;
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, attr.c_str(), attr.size());
            SHA256_Final(hash_str_byte, &sha256);
            element_from_hash(Aji, hash_str_byte, SHA256_DIGEST_LENGTH);
//            cout << "Aji" << endl;

            // compute u^Aji
            element_pow_zn(u_Aji, u, Aji);
//            cout << "u^Aji" << endl;

            // compute u^Aji*h
            element_mul(u_Aji_h, u_Aji, h);
//            cout << "u^Aji*h" << endl;

            // compute e(Cji3,u^Aji*h)
            element_pairing(e_Cji3uAjih, Cji3, u_Aji_h);
//            cout << "e(Cji3,u^Aji*h)" << endl;

            // compute e(Cji3,u^Aji*h)^(-1)
            element_invert(inv_e_Cji3uAjih, e_Cji3uAjih);
//            cout << "e(Cji3,u^Aji*h)^(-1)" << endl;

            if (element_cmp(e_gCji2, inv_e_Cji3uAjih) != 0) {
                cout << "A-1-2" << endl;
                return NULL;
            }
        }
    }

    // step two
    element_t Cdelte, Cdelte_;
    element_init_GT(Cdelte, pairing);
    element_init_GT(Cdelte_, pairing);
    if (*key_type == "Td") {
        element_set(Cdelte, computeXdelte(CT, key_x, "T", ""));
        // add Cdelte
        res->insertComponent("Cdelte", "GT", Cdelte);
    } else {
        element_set(Cdelte, computeXdelte(CT, key_x, "K", ""));
        element_set(Cdelte_, computeXdelte(CT, key_x, "K", "_"));
        // add Cdelte
        res->insertComponent("Cdelte", "GT", Cdelte);
        // add Cdelte'
        res->insertComponent("Cdelte_", "GT", Cdelte_);
    }

    return res;
}

bool* OHCET::test(Key *public_key, Ciphertext_HCET *ITA, vector<SecretKey *> *TdSA, Ciphertext_HCET *ITB,
                  vector<SecretKey *> *TdSB) {
    bool *res = new bool();
    if (ITA == NULL || ITB == NULL) {
        *res = false;
        return res;
    }

    // compute CdelteA^oA
    element_t CdelteA_oA;
    element_init_GT(CdelteA_oA, pairing);
    element_pow_zn(CdelteA_oA, ITA->getComponent("Cdelte"), TdSA->at(1)->getComponent("o"));

    // compute XA
    element_t XA;
    element_init_G1(XA, pairing);
    element_div(XA, ITA->getComponent("C"), H1(CdelteA_oA));

    // compute CdelteB^oB
    element_t CdelteB_oB;
    element_init_GT(CdelteB_oB, pairing);
    element_pow_zn(CdelteB_oB, ITB->getComponent("Cdelte"), TdSB->at(1)->getComponent("o"));

    // compute XB
    element_t XB;
    element_init_G1(XB, pairing);
    element_div(XB, ITB->getComponent("C"), H1(CdelteB_oB));

    // compute e(C0'A,XB)
    element_t e_C0_A_XB;
    element_init_GT(e_C0_A_XB, pairing);
    element_pairing(e_C0_A_XB, ITA->getComponent("C0_"), XB);

    // compute e(C0'B,XA)
    element_t e_C0_B_XA;
    element_init_GT(e_C0_B_XA, pairing);
    element_pairing(e_C0_B_XA, ITB->getComponent("C0_"), XA);

    if (element_cmp(e_C0_A_XB, e_C0_B_XA) == 0) {
        *res = true;
        return res;
    } else {
        *res = false;
        return res;
    }
}

unsigned char* OHCET::decrypt(Ciphertext_HCET *IT, SecretKey *DK) {
    if (IT == NULL) {
        return NULL;
    }

    // compute Cdelte'^o'
    element_t Cdelte__o_;
    element_init_GT(Cdelte__o_, pairing);
    element_pow_zn(Cdelte__o_, IT->getComponent("Cdelte_"), DK->getComponent("o_"));

    unsigned char *H_2 = H2(Cdelte__o_);

    unsigned char *res = (unsigned char*)malloc(8 + 1);
    res[8] = '\0';
    unsigned char *z_bytes = (unsigned char*)malloc(zr_length + 1);
    z_bytes[zr_length] = '\0';

    for (signed long int i = 0; i < 8; ++i) {
        int mzvalue = (int)IT->Cstar[i] ^ (int)H_2[i];
        res[i] = (unsigned char)mzvalue;
    }
    for (signed long int i = 8; i < 8 + zr_length; ++i) {
        int mzvalue = (int)IT->Cstar[i] ^ (int)H_2[i];
        z_bytes[i - 8] = (unsigned char)mzvalue;
    }

    element_t z;
    element_init_Zr(z, pairing);
    element_from_bytes(z, z_bytes);
//    element_printf("恢复出来的z为：%B\n", z);

    // 添加验证！！！

    return res;
}