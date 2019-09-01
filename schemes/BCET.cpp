//
// Created by alan on 19-8-21.
//

#include "BCET.h"

element_s* BCET::H1(element_s *e) {
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

unsigned char* BCET::H2(element_s *e) {
    element_t *res = new element_t[1];
    element_init_G1(*res, pairing);

    signed long int n = element_length_in_bytes(e);
    unsigned char *bytes = (unsigned char*)malloc(n);
    element_to_bytes(bytes, e);

    unsigned char *hash_str_byte = (unsigned char*)malloc(SHA256_DIGEST_LENGTH + 116 + 1);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, bytes, n);
    SHA256_Final(hash_str_byte, &sha256);
    for (signed long int i = 0; i < 116; ++i) {
        hash_str_byte[SHA256_DIGEST_LENGTH + i] = '0';
    }
    hash_str_byte[SHA256_DIGEST_LENGTH + 116] = '\0';

    return hash_str_byte;
}

element_s* BCET::computeXdelte(Ciphertext_CET *ciphertext, Key *key_x, vector<string> *attributes, string pre_s, string post_s) {
    // get M and rho
    element_t sample_element;
    element_init_Zr(sample_element, pairing);
    policy_resolution pr;
    policy_generation pg;
    vector<string>* postfix_expression = pr.infixToPostfix(ciphertext->getPolicy());
    binary_tree* binary_tree_expression = pr.postfixToBinaryTree(postfix_expression, sample_element);
    pg.generatePolicyInMatrixForm(binary_tree_expression);
    element_t_matrix* M = pg.getPolicyInMatrixFormFromTree(binary_tree_expression);
    map<signed long int, string>* rho = pg.getRhoFromTree(binary_tree_expression);

    // compute wi
    utils util;
    map<signed long int, signed long int>* matchedAttributes = util.attributesMatching(attributes, rho);
    element_t_matrix* attributesMatrix = util.getAttributesMatrix(M, matchedAttributes);
    map<signed long int, signed long int>* x_to_attributes = util.xToAttributes(M, matchedAttributes);
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

    map<signed long int, signed long int>::iterator it;
    for (it = matchedAttributes->begin(); it != matchedAttributes->end(); ++it) {
        // get attribute
        string attr = (*attributes)[it->second];

        // get Ci1, K1, Ci2, Ktau2, Ci3, Ktau3
        element_t Ci1, K1, Ci2, Ktau2, Ci3, Ktau3;
        element_init_G1(Ci1, pairing);
        element_init_G1(K1, pairing);
        element_init_G1(Ci2, pairing);
        element_init_G1(Ktau2, pairing);
        element_init_G1(Ci3, pairing);
        element_init_G1(Ktau3, pairing);
        element_set(Ci1, ciphertext->getComponent("C" + attr + "1"));
        element_set(K1, key_x->getComponent(pre_s + "1" + post_s));
        element_set(Ci2, ciphertext->getComponent("C" + attr + "2"));
        element_set(Ktau2, key_x->getComponent(pre_s + attr + "2" + post_s));
        element_set(Ci3, ciphertext->getComponent("C" + attr + "3"));
        element_set(Ktau3, key_x->getComponent(pre_s + attr + "3" + post_s));

        // compute e_Ci1_K1, e_Ci2_Ktau2, e_Ci3_Ktau3
        element_t e_Ci1_K1, e_Ci2_Ktau2, e_Ci3_Ktau3;
        element_init_GT(e_Ci1_K1, pairing);
        element_init_GT(e_Ci2_Ktau2, pairing);
        element_init_GT(e_Ci3_Ktau3, pairing);
        element_pairing(e_Ci1_K1, Ci1, K1);
        element_pairing(e_Ci2_Ktau2, Ci2, Ktau2);
        element_pairing(e_Ci3_Ktau3, Ci3, Ktau3);

        // compute factor_denominator
        element_t e_e, e_e_e, factor_denominator;
        element_init_GT(e_e, pairing);
        element_init_GT(e_e_e, pairing);
        element_init_GT(factor_denominator, pairing);
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

element_s* BCET::computeV(Ciphertext_CET *ct, Key *sp_ch, Key *pk_ch, element_s *r_ch, element_t_matrix *M, map<signed long int, string> *rho) {
    element_t *res = new element_t[1];
    element_init_Zr(*res, pairing);

    element_t g1, gt, zr;
    element_init_G1(g1, pairing);
    element_init_GT(gt, pairing);
    element_init_Zr(zr, pairing);
    int n_1 = element_length_in_bytes(g1);
    int n_z = element_length_in_bytes(zr);
    int n_total = n_1 + n_1 + n_1 + n_z + n_1 + n_1 + n_1 + (M->row() * n_1);
    unsigned char* str = (unsigned char*)malloc(n_total + 1);
    int str_index = 0;

    // add y of pk_ch
    element_to_bytes(str + str_index, pk_ch->getComponent("y"));
    str_index += n_1;

    // add C
    element_to_bytes(str + str_index, ct->getComponent("C"));
    str_index += n_1;

    // add C*
    for (signed long int i = 0; i < n_1 + n_z; ++i) {
        str[str_index] = ct->Cstar[i];
        str_index++;
    }

    // add C0
    element_to_bytes(str + str_index, ct->getComponent("C0"));
    str_index += n_1;

    // add C0'
    element_to_bytes(str + str_index, ct->getComponent("C0_"));
    str_index += n_1;

    // add C03
    element_to_bytes(str + str_index, ct->getComponent("C03"));
    str_index += n_1;

    // add Ctau3
    for (signed long int i = 0; i < M->row(); ++i) {
        map<signed long int, string>::iterator it = rho->find(i);
        string attr = it->second;
        element_to_bytes(str + str_index, ct->getComponent("C" + attr + "3"));
        str_index += n_1;
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
    element_s *Vg = ch->hash(sp_ch, pk_ch, m_ch, r_ch);
    unsigned char* Vg_data = (unsigned char*)malloc(n_1 + 1);
    element_to_bytes(Vg_data, Vg);
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, Vg_data, n_1);
    SHA256_Final(hash_str_byte, &sha256);
    element_from_hash(*res, hash_str_byte, SHA256_DIGEST_LENGTH);

    return *res;
}

vector<Key*>* BCET::setUp() {
    // init pairing
    pbc_param_t par;
    curve_param curves;
    pbc_param_init_set_str(par, curves.a_param.c_str());
    pairing_init_pbc_param(pairing, par);

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

Ciphertext_CET* BCET::encrypt(Key *public_key, string policy, element_s *m, Key *sp_ch, Key *pk_ch) {
    element_t sample_element;
    element_init_Zr(sample_element, pairing);
    Ciphertext_CET *res = new Ciphertext_CET(policy);

    policy_resolution pr;
    policy_generation pg;
    utils util;
    vector<string>* postfix_expression = pr.infixToPostfix(policy);
    binary_tree* binary_tree_expression = pr.postfixToBinaryTree(postfix_expression, sample_element);
    pg.generatePolicyInMatrixForm(binary_tree_expression);
    element_t_matrix* M = pg.getPolicyInMatrixFormFromTree(binary_tree_expression);
    map<signed long int, string>* rho = pg.getRhoFromTree(binary_tree_expression);

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
    element_t_vector *y = new element_t_vector(M->col(), sample_element);
    element_set(y->getElement(0), s);
    for (signed long int i = 1; i < y->length(); ++i) {
        element_random(y->getElement(i));
    }

    // compute shares
    extend_math_operation emo;
    element_t_vector *shares = emo.multiply(M, y);

    // randomly choose u and t0
    element_t uu, t0;
    element_init_Zr(uu, pairing);
    element_init_Zr(t0, pairing);
    element_random(uu);
    element_random(t0);

    // compute m^uu
    element_t m_uu;
    element_init_G1(m_uu, pairing);
    element_pow_zn(m_uu, m, uu);

    // compute e(g,g)^(alpha*s)
    element_t e_gg_alpha_s;
    element_init_GT(e_gg_alpha_s, pairing);
    element_pow_zn(e_gg_alpha_s, e_gg_alpha, s);
    element_printf("e_gg_alpha_s is %B\n", e_gg_alpha_s);

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
    element_printf("e_gg_alpha__s is %B\n", e_gg_alpha__s);

    int n1 = element_length_in_bytes(m);
    int n2 = element_length_in_bytes(uu);
    unsigned char *muu = (unsigned char*)malloc(n1 + n2 + 1);
    element_to_bytes(muu, m);
    element_to_bytes(muu + n1, uu);
    muu[n1 + n2] = '\0';
//    printf("muu is %s\n", muu);
    unsigned char *H_2 = H2(e_gg_alpha__s);

    // compute C*
    res->Cstar = (unsigned char*)malloc(n1 + n2 +1);
    for (signed long int i = 0; i < n1 + n2; ++i) {
        int Cvalue = (int)muu[i] ^ (int)H_2[i];
        res->Cstar[i] = (unsigned char)Cvalue;
    }

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

    for (signed long int i = 0; i < M->row(); ++i) {
        // get ttau
        element_t ttau;
        element_init_Zr(ttau, pairing);
        element_random(ttau);

        // get rhotau
        element_t rhotau;
        element_init_Zr(rhotau, pairing);
        map<signed long int, string>::iterator it = rho->find(i);
        string attr = it->second;
        element_set(rhotau, util.stringToElementT(attr, "ZR", &pairing));

        // compute Ctau1, Ctau2, Ctau3
        element_t Ctau1, Ctau2, Ctau3;
        element_init_G1(Ctau1, pairing);
        element_init_G1(Ctau2, pairing);
        element_init_G1(Ctau3, pairing);
        element_t w_lambdatau, v_ttau;
        element_init_G1(w_lambdatau, pairing);
        element_init_G1(v_ttau, pairing);
        element_pow_zn(w_lambdatau, w, shares->getElement(i));
        element_pow_zn(v_ttau, v, ttau);
        element_mul(Ctau1, w_lambdatau, v_ttau);
        element_t neg_ttau;
        element_t u_rhotau, u_rhotau_h;
        element_init_Zr(neg_ttau, pairing);
        element_init_G1(u_rhotau, pairing);
        element_init_G1(u_rhotau_h, pairing);
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
    element_t w_s;
    element_init_G1(w_s, pairing);
    element_pow_zn(w_s, w, s);

    // compute v^t0
    element_t v_t0;
    element_init_G1(v_t0, pairing);
    element_pow_zn(v_t0, v, t0);

    // compute C01=w^s*v^t0
    element_t C01;
    element_init_G1(C01, pairing);
    element_mul(C01, w_s, v_t0);
    res->insertComponent("C01", "G1", C01);

    // randomly choose rnd
    element_t r_ch;
    element_init_Zr(r_ch, pairing);
    element_random(r_ch);
    res->insertComponent("r_ch", "ZR", r_ch);

    // compute V
    element_s *V = computeV(res, sp_ch, pk_ch, r_ch, M, rho);
    element_printf("V is %B\n", V);

//    element_s *test_V = computeV(res, sp_ch, pk_ch, r_ch, M, rho);
//    element_printf("%B\n", test_V);

    // compute u^V
    element_t u_V;
    element_init_G1(u_V, pairing);
    element_pow_zn(u_V, u, V);

    // compute u^V*h
    element_t u_V_h;
    element_init_G1(u_V_h, pairing);
    element_mul(u_V_h, u_V, h);

    // compute -t0
    element_t neg_t0;
    element_init_Zr(neg_t0, pairing);
    element_neg(neg_t0, t0);

    // compute C02
    element_t C02;
    element_init_G1(C02, pairing);
    element_pow_zn(C02, u_V_h, neg_t0);
    res->insertComponent("C02", "G1", C02);

    return res;
}

bool* BCET::test(Key *public_key, Ciphertext_CET *CTA, Key *TdSA, vector<string> *SA, Ciphertext_CET *CTB, Key *TdSB, vector<string> *SB, Key *sp_ch, Key *pk_ch) {
    // get M and rho
    element_t sample_element;
    element_init_Zr(sample_element, pairing);
    policy_resolution pr;
    policy_generation pg;
    vector<string>* postfix_expression_A = pr.infixToPostfix(CTA->getPolicy());
    binary_tree* binary_tree_expression_A = pr.postfixToBinaryTree(postfix_expression_A, sample_element);
    pg.generatePolicyInMatrixForm(binary_tree_expression_A);
    element_t_matrix* M_A = pg.getPolicyInMatrixFormFromTree(binary_tree_expression_A);
    map<signed long int, string>* rho_A = pg.getRhoFromTree(binary_tree_expression_A);

    // get M and rho
    vector<string>* postfix_expression_B = pr.infixToPostfix(CTB->getPolicy());
    binary_tree* binary_tree_expression_B = pr.postfixToBinaryTree(postfix_expression_B, sample_element);
    pg.generatePolicyInMatrixForm(binary_tree_expression_B);
    element_t_matrix* M_B = pg.getPolicyInMatrixFormFromTree(binary_tree_expression_B);
    map<signed long int, string>* rho_B = pg.getRhoFromTree(binary_tree_expression_B);

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
    element_s *VA = computeV(CTA, sp_ch, pk_ch, CTA->getComponent("r_ch"), M_A, rho_A);

    // VB
    element_s *VB = computeV(CTB, sp_ch, pk_ch, CTB->getComponent("r_ch"), M_B, rho_B);

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
    for (signed long int i = 0; i < M_A->row(); ++i) {
        map<signed long int, string>::iterator it = rho_A->find(i);
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
    for (signed long int i = 0; i < M_B->row(); ++i) {
        map<signed long int, string>::iterator it = rho_B->find(i);
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

    // test the second structure
    element_s *XdelteA = computeXdelte(CTA, TdSA, SA, "T", "");
    element_s *XdelteB = computeXdelte(CTB, TdSB, SB, "T", "");

    // compute XA
    element_t XA;
    element_init_Zr(XA, pairing);
    element_div(XA, CTA->getComponent("C"), H1(XdelteA));

    // compute XB
    element_t XB;
    element_init_Zr(XB, pairing);
    element_div(XB, CTB->getComponent("C"), H1(XdelteB));

    // compute e(C0'A,XB)
    element_t e_C0_A_XB;
    element_init_GT(e_C0_A_XB, pairing);
    element_pairing(e_C0_A_XB, CTA->getComponent("C0_"), XB);

    // compute e(C0'B, XA)
    element_t e_C0_B_XA;
    element_init_GT(e_C0_B_XA, pairing);
    element_pairing(e_C0_B_XA, CTB->getComponent("C0_"), XA);

    bool *res = new bool();

    if (element_cmp(e_C0_A_XB, e_C0_B_XA) == 0) {
        *res = true;
        return res;
    } else {
        *res = false;
        return res;
    }
}

element_s* BCET::decrypt(Ciphertext_CET *ciphertext_cet, Key *secret_key, vector<string> *attributes) {
    element_s *Xdelta = computeXdelte(ciphertext_cet, secret_key, attributes, "K", "");
    element_s *Xdelta_ = computeXdelte(ciphertext_cet, secret_key, attributes, "K", "_");

    element_t g1, gt, zr;
    element_init_G1(g1, pairing);
    element_init_GT(gt, pairing);
    element_init_Zr(zr, pairing);
    int n_g1 = element_length_in_bytes(g1);
    int n_zr = element_length_in_bytes(zr);

    unsigned char *H_2 = H2(Xdelta_);
    unsigned char *mz = (unsigned char*)malloc(n_g1 + n_zr + 1);
    mz[n_g1 + n_zr] = '\0';

    for (signed long int i = 0; i < n_g1 + n_zr; ++i) {
        int mzvalue = (int)ciphertext_cet->Cstar[i] ^ (int)H_2[i];
        mz[i] = (unsigned char)mzvalue;
    }

    element_t *res = new element_t[1];
    element_init_G1(*res, pairing);
    element_from_bytes(*res, mz);

    return *res;
}