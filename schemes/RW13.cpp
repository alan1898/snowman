//
// Created by alan on 19-4-26.
//

#include "RW13.h"

RW13::RW13() {
    // init pairing
    pbc_param_t par;
    curve_param curves;
    pbc_param_init_set_str(par, curves.a_param.c_str());
//    pbc_param_init_a_gen(par, 3, 3);
    pairing_init_pbc_param(pairing, par);
}

vector<Key*>* RW13::setUp() {
    element_t g, u, h, w, v;
    element_t alpha;
    element_t e_gg, e_gg_alpha;

    element_init_G1(g, pairing);
    element_init_G1(u, pairing);
    element_init_G1(h, pairing);
    element_init_G1(w, pairing);
    element_init_G1(v, pairing);

    element_init_Zr(alpha, pairing);

    element_init_GT(e_gg, pairing);
    element_init_GT(e_gg_alpha, pairing);

    element_random(g);
    element_random(u);
    element_random(h);
    element_random(w);
    element_random(v);
    element_random(alpha);
    element_pairing(e_gg, g, g);
    element_pow_zn(e_gg_alpha, e_gg, alpha);

    Key *master_key = new Key(Key::MASTER);
    Key *public_key = new Key(Key::PUBLIC);

    master_key->insertComponent("alpha", "ZR", alpha);
    public_key->insertComponent("g", "G1", g);
    public_key->insertComponent("u", "G1", u);
    public_key->insertComponent("h", "G1", h);
    public_key->insertComponent("w", "G1", w);
    public_key->insertComponent("v", "G1", v);
    public_key->insertComponent("e_gg_alpha", "GT", e_gg_alpha);

    vector<Key*> *res = new vector<Key*>(2);
    (*res)[0] = master_key;
    (*res)[1] = public_key;

    return res;
}

Key* RW13::keyGen(Key *public_key, Key *master_key, vector<string> *attributes) {
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
    element_t alpha;
    element_init_same_as(alpha, master_key->getComponent("alpha"));
    element_set(alpha, master_key->getComponent("alpha"));

    // generate r and -r
    element_t r;
    element_init_Zr(r, pairing);
    element_random(r);
    element_t neg_r;
    element_init_Zr(neg_r, pairing);
    element_neg(neg_r, r);

    // compute K0, K1
    element_t K0, K1;
    element_t g_alpha, w_r;
    element_init_G1(K0, pairing);
    element_init_G1(K1, pairing);
    element_init_G1(g_alpha, pairing);
    element_init_G1(w_r, pairing);
    element_pow_zn(g_alpha, g, alpha);
    element_pow_zn(w_r, w, r);
    element_mul(K0, g_alpha, w_r);
    element_pow_zn(K1, g, r);

    res->insertComponent("K0", "G1", K0);
    res->insertComponent("K1", "G1", K1);

    // compute Ktau2 and Ktau3
    element_t rtau;
    element_init_Zr(rtau, pairing);
    element_t Ktau2, Ktau3;
    element_init_G1(Ktau2, pairing);
    element_init_G1(Ktau3, pairing);
    element_t Atau;
    element_init_Zr(Atau, pairing);
    element_t u_Atau, u_Atau_h, u_Atau_h_rtau;
    element_t v_neg_r;
    element_init_G1(u_Atau, pairing);
    element_init_G1(u_Atau_h, pairing);
    element_init_G1(u_Atau_h_rtau, pairing);
    element_init_G1(v_neg_r, pairing);
    for (signed long int i = 0; i < attributes->size(); ++i) {
        // generate random r tau
        element_random(rtau);

        // compute Ktau2
        element_pow_zn(Ktau2, g, rtau);

        // compute Atau
        unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, (*attributes)[i].c_str(), (*attributes)[i].size());
        SHA256_Final(hash_str_byte, &sha256);
        element_from_hash(Atau, hash_str_byte, SHA256_DIGEST_LENGTH);

        // compute Ktau3
        element_pow_zn(u_Atau, u, Atau);
        element_mul(u_Atau_h, u_Atau, h);
        element_pow_zn(u_Atau_h_rtau, u_Atau_h, rtau);
        element_pow_zn(v_neg_r, v, neg_r);
        element_mul(Ktau3, u_Atau_h_rtau, v_neg_r);

        res->insertComponent("K" + (*attributes)[i] + "2", "G1", Ktau2);
        res->insertComponent("K" + (*attributes)[i] + "3", "G1", Ktau3);
    }

    return res;
}

Ciphertext* RW13::encrypt(element_s *m, string policy, Key *public_key) {
    element_t sample_element;
    element_init_Zr(sample_element, pairing);
    Ciphertext *res = new Ciphertext(policy);

    policy_resolution pr;
    policy_generation pg;
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

    // generate s
    element_t s;
    element_init_Zr(s, pairing);
    element_random(s);
//    cout << "secret is" << endl;
//    element_printf("%B\n", s);

    // generate vector y
    element_t_vector *y = new element_t_vector(M->col(), sample_element);
    element_set(y->getElement(0), s);
    for (signed long int i = 1; i < y->length(); ++i) {
        element_random(y->getElement(i));
    }

    // compute shares
    extend_math_operation emo;
    element_t_vector *shares = emo.multiply(M, y);
//    cout << "shares are" << endl;
//    shares->printVector();

    // compute C
    element_t e_gg_alpha;
    element_init_GT(e_gg_alpha, pairing);
    element_set(e_gg_alpha, public_key->getComponent("e_gg_alpha"));
    element_t e_gg_alpha_s;
    element_init_GT(e_gg_alpha_s, pairing);
    element_pow_zn(e_gg_alpha_s, e_gg_alpha, s);
    element_t C;
    element_init_GT(C, pairing);
    element_mul(C, m, e_gg_alpha_s);

    // compute C0
    element_t C0;
    element_init_G1(C0, pairing);
    element_pow_zn(C0, g, s);

    res->insertComponent("C", "GT", C);
    res->insertComponent("C0", "G1", C0);

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
        unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, attr.c_str(), attr.size());
        SHA256_Final(hash_str_byte, &sha256);
        element_from_hash(rhotau, hash_str_byte, SHA256_DIGEST_LENGTH);

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

    return res;
}

element_s* RW13::decrypt(Ciphertext *ciphertext, Key *secret_key, vector<string> *attributes) {
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

    // compute e_C0_K0
    element_t e_C0_K0;
    element_init_GT(e_C0_K0, pairing);
    element_pairing(e_C0_K0, ciphertext->getComponent("C0"), secret_key->getComponent("K0"));

    // compute wi
    utils util;
    map<signed long int, signed long int>* matchedAttributes = util.attributesMatching(attributes, rho);
//    cout << "matched attributes is" << endl;
//    map<signed long int, signed long int>::iterator iterator1;
//    for (iterator1 = matchedAttributes->begin(); iterator1 != matchedAttributes->end(); ++iterator1) {
//        cout << "key: " << iterator1->first << ", value: " << iterator1->second << endl;
//    }
    element_t_matrix* attributesMatrix = util.getAttributesMatrix(M, matchedAttributes);
//    cout << "attributes matrix is" << endl;
//    attributesMatrix->printMatrix();
    map<signed long int, signed long int>* x_to_attributes = util.xToAttributes(M, matchedAttributes);
//    cout << "x to attributes is" << endl;
//    map<signed long int, signed long int>::iterator iterator2;
//    for (iterator2 = x_to_attributes->begin(); iterator2 != x_to_attributes->end(); ++iterator2) {
//        cout << "key: " << iterator2->first << ", value: " << iterator2->second << endl;
//    }
    element_t_matrix* inverse_M = util.inverse(attributesMatrix);
//    cout << "inverse attributes matrix is" << endl;
//    inverse_M->printMatrix();
    element_t_vector* unit = util.getCoordinateAxisUnitVector(inverse_M);
//    cout << "unit vector is" << endl;
//    unit->printVector();
    element_t_vector* x= new element_t_vector(inverse_M->col(), inverse_M->getElement(0, 0));
    extend_math_operation emo;
    signed long int type = emo.gaussElimination(x, inverse_M, unit);
    if (-1 == type) {
        return NULL;
    }
//    cout << "wi vector is" << endl;
//    x->printVector();

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
        element_set(K1, secret_key->getComponent("K1"));
        element_set(Ci2, ciphertext->getComponent("C" + attr + "2"));
        element_set(Ktau2, secret_key->getComponent("K" + attr + "2"));
        element_set(Ci3, ciphertext->getComponent("C" + attr + "3"));
        element_set(Ktau3, secret_key->getComponent("K" + attr + "3"));

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
//        cout << "attribute is " << secret_key->getAttribute(it->second) << endl;
//        element_printf("wi is %B\n", x->getElement(x_index));

        if (it == matchedAttributes->begin()) {
            element_set(denominator, factor_denominator);
        } else {
            element_mul(denominator, denominator, factor_denominator);
        }
    }

    element_t B;
    element_init_GT(B, pairing);
    element_div(B, e_C0_K0, denominator);

    // get C
    element_t C;
    element_init_GT(C, pairing);
    element_set(C, ciphertext->getComponent("C"));

    element_t *res = new element_t[1];
    element_init_GT(*res, pairing);
    element_div(*res, C, B);

    return *res;
}