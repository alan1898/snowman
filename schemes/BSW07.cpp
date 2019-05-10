//
// Created by alan on 19-4-26.
//

#include "BSW07.h"

BSW07::BSW07() {
    // init pairing
    pbc_param_t par;
    curve_param curves;
    pbc_param_init_set_str(par, curves.a_param.c_str());
    pairing_init_pbc_param(pairing, par);
}

vector<Key*>* BSW07::setUp() {
    element_t g;
    element_init_G1(g, pairing);
    element_random(g);

    element_t alpha, beta;
    element_init_Zr(alpha, pairing);
    element_init_Zr(beta, pairing);
    element_random(alpha);
    element_random(beta);

    element_t inv_beta;
    element_init_Zr(inv_beta, pairing);
    element_invert(inv_beta, beta);

    element_t h, f, g_alpha;
    element_init_G1(h, pairing);
    element_init_G1(f, pairing);
    element_init_G1(g_alpha, pairing);
    element_pow_zn(h, g, beta);
    element_pow_zn(f, g, inv_beta);
    element_pow_zn(g_alpha, g, alpha);

    element_t e_gg, e_gg_alpha;
    element_init_GT(e_gg, pairing);
    element_init_GT(e_gg_alpha, pairing);
    element_pairing(e_gg, g, g);
    element_pow_zn(e_gg_alpha, e_gg, alpha);

    Key *master_key = new Key(Key::MASTER);
    Key *public_key = new Key(Key::PUBLIC);

    master_key->insertComponent("beta", "ZR", beta);
    master_key->insertComponent("g_alpha", "G1", g_alpha);
    public_key->insertComponent("g", "G1", g);
    public_key->insertComponent("h", "G1", h);
    public_key->insertComponent("f", "G1", f);
    public_key->insertComponent("e_gg_alpha", "GT", e_gg_alpha);

    public_key->insertComponent("e_gg", "GT", e_gg);

    vector<Key*> *res = new vector<Key*>(2);
    (*res)[0] = master_key;
    (*res)[1] = public_key;

    return res;
}

Key* BSW07::keyGen(Key *public_key, Key *master_key, vector<string> *attributes) {
    Key *res = new Key();

    // get g
    element_t g;
    element_init_G1(g, pairing);
    element_set(g, public_key->getComponent("g"));

    // get master key
    element_t beta, g_alpha;
    element_init_Zr(beta, pairing);
    element_init_G1(g_alpha, pairing);
    element_set(beta, master_key->getComponent("beta"));
    element_set(g_alpha, master_key->getComponent("g_alpha"));

    // randomly choose r
    element_t r;
    element_init_Zr(r, pairing);
    element_random(r);

    res->insertComponent("r", "ZR", r);

    // compute g_r
    element_t g_r;
    element_init_G1(g_r, pairing);
    element_pow_zn(g_r, g, r);

    // compute inv_beta
    element_t inv_beta;
    element_init_Zr(inv_beta, pairing);
    element_invert(inv_beta, beta);

    // compute g_alpha_r
    element_t g_alpha_r;
    element_init_G1(g_alpha_r, pairing);
    element_mul(g_alpha_r, g_alpha, g_r);

    // compute D
    element_t D;
    element_init_G1(D, pairing);
    element_pow_zn(D, g_alpha_r, inv_beta);

    res->insertComponent("D", "G1", D);

    for (signed long int i = 0; i < attributes->size(); ++i) {
        // randomly choose rj
        element_t rj;
        element_init_Zr(rj, pairing);
        element_random(rj);

        // compute Hj
        element_t Hj;
        element_init_G1(Hj, pairing);
        unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, (*attributes)[i].c_str(), (*attributes)[i].size());
        SHA256_Final(hash_str_byte, &sha256);
        element_from_hash(Hj, hash_str_byte, SHA256_DIGEST_LENGTH);

        // compute Hj_rj
        element_t Hj_rj;
        element_init_G1(Hj_rj, pairing);
        element_pow_zn(Hj_rj, Hj, rj);

        // compute Dj
        element_t Dj;
        element_init_G1(Dj, pairing);
        element_mul(Dj, g_r, Hj_rj);

        res->insertComponent("D" + (*attributes)[i], "G1", Dj);

        // compute Dj'
        element_t Dj_;
        element_init_G1(Dj_, pairing);
        element_pow_zn(Dj_, g, rj);

        res->insertComponent("D" + (*attributes)[i] + "_", "G1", Dj_);
    }

    return res;
}

Key* BSW07::delegate(Key *public_key, Key *secret_key, vector<string> *attributes_tilde) {
    Key *res = new Key();

    // get g and f
    element_t g, f;
    element_init_G1(g, pairing);
    element_init_G1(f, pairing);
    element_set(g, public_key->getComponent("g"));
    element_set(f, public_key->getComponent("f"));

    // get D
    element_t D;
    element_init_G1(D, pairing);
    element_set(D, secret_key->getComponent("D"));

    // randomly choose r_tilde
    element_t r_tilde;
    element_init_Zr(r_tilde, pairing);
    element_random(r_tilde);

    // compute f_r_tilde
    element_t f_r_tilde;
    element_init_G1(f_r_tilde, pairing);
    element_pow_zn(f_r_tilde, f, r_tilde);

    // compute g_r_tilde
    element_t g_r_tilde;
    element_init_G1(g_r_tilde, pairing);
    element_pow_zn(g_r_tilde, g, r_tilde);

    // compute D_tilde
    element_t D_tilde;
    element_init_G1(D_tilde, pairing);
    element_mul(D_tilde, D, f_r_tilde);

    res->insertComponent("D_tilde", "G1", D_tilde);

    for (signed long int i = 0; i < attributes_tilde->size(); ++i) {
        // randomly choose rk_tilde
        element_t rk_tilde;
        element_init_Zr(rk_tilde, pairing);
        element_random(rk_tilde);

        // compute g_rk_tilde
        element_t g_rk_tilde;
        element_init_G1(g_rk_tilde, pairing);
        element_pow_zn(g_rk_tilde, g, rk_tilde);

        // get Dk and Dk_
        element_t Dk, Dk_;
        element_init_G1(Dk, pairing);
        element_init_G1(Dk_, pairing);
        element_set(Dk, secret_key->getComponent("D" + (*attributes_tilde)[i]));
        element_set(Dk_, secret_key->getComponent("D" + (*attributes_tilde)[i] + "_"));

        // compute Hk
        element_t Hk;
        element_init_G1(Hk, pairing);
        unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, (*attributes_tilde)[i].c_str(), (*attributes_tilde)[i].size());
        SHA256_Final(hash_str_byte, &sha256);
        element_from_hash(Hk, hash_str_byte, SHA256_DIGEST_LENGTH);

        // compute Hk_rk_tilde
        element_t Hk_rk_tilde;
        element_init_G1(Hk_rk_tilde, pairing);
        element_pow_zn(Hk_rk_tilde, Hk, rk_tilde);

        // compute Dk_g_r_tilde
        element_t Dk_g_r_tilde;
        element_init_G1(Dk_g_r_tilde, pairing);
        element_mul(Dk_g_r_tilde, Dk, g_r_tilde);

        // compute Dk_tilde
        element_t Dk_tilde;
        element_init_G1(Dk_tilde, pairing);
        element_mul(Dk_tilde, Dk_g_r_tilde, Hk_rk_tilde);

        res->insertComponent("D_tilde" + (*attributes_tilde)[i], "G1", Dk_tilde);

        // compute Dk_tilde_
        element_t Dk_tilde_;
        element_init_G1(Dk_tilde_, pairing);
        element_mul(Dk_tilde_, Dk_, g_rk_tilde);

        res->insertComponent("D_tilde" + (*attributes_tilde)[i] + "_", "G1", Dk_tilde_);
    }

    return res;
}

Ciphertext* BSW07::encrypt(element_s *m, string policy, Key *public_key) {
    policy_resolution pr;
    policy_generation pg;
    utils util;

    element_t sample_element;
    element_init_Zr(sample_element, pairing);
    element_random(sample_element);

    Ciphertext *res = new Ciphertext(policy);

    element_t e_gg;
    element_init_GT(e_gg, pairing);
    element_set(e_gg, public_key->getComponent("e_gg"));
    res->insertComponent("e_gg", "GT", e_gg);

    // get g, h and e_gg_alpha
    element_t g, h, e_gg_alpha;
    element_init_G1(g, pairing);
    element_init_G1(h, pairing);
    element_init_GT(e_gg_alpha, pairing);
    element_set(g, public_key->getComponent("g"));
    element_set(h, public_key->getComponent("h"));
    element_set(e_gg_alpha, public_key->getComponent("e_gg_alpha"));

    // randomly choose s
    element_t s;
    element_init_Zr(s, pairing);
    element_random(s);

    res->insertComponent("s", "ZR", s);

    // compute access structure
    multiway_tree *T = pr.ThresholdExpressionToMultiwayTree(policy, sample_element);
    pg.generatePolicyInMultiwayTreeForm(T, s);

    // compute C_tilde
    element_t e_gg_alpha_s;
    element_init_GT(e_gg_alpha_s, pairing);
    element_pow_zn(e_gg_alpha_s, e_gg_alpha, s);
    element_t C_tilde;
    element_init_GT(C_tilde, pairing);
    element_mul(C_tilde, m, e_gg_alpha_s);

    res->insertComponent("C_tilde", "GT", C_tilde);

    // compute C
    element_t C;
    element_init_G1(C, pairing);
    element_pow_zn(C, h, s);

    res->insertComponent("C", "G1", C);

    // compute Cy and Cy_
    queue<multiway_tree_node*> q;
    q.push(T->getRoot());
    while (!q.empty()) {
        if (q.front()->getType() == multiway_tree_node::LEAF) {
            // get qy0
            element_t qy0;
            element_init_Zr(qy0, pairing);
            element_set(qy0, q.front()->getValue());

            // get atty
            string atty = q.front()->getName();

            // compute Hatty
            element_t Hatty;
            element_init_G1(Hatty, pairing);
            element_set(Hatty, util.stringToElementT(atty, "G1", &pairing));

            // compute Cy
            element_t Cy;
            element_init_G1(Cy, pairing);
            element_pow_zn(Cy, g, qy0);

            res->insertComponent("C" + atty, "G1", Cy);

            // compute Cy_
            element_t Cy_;
            element_init_G1(Cy_, pairing);
            element_pow_zn(Cy_, Hatty, qy0);

            res->insertComponent("C" + atty + "_", "G1", Cy_);
        }
        if (q.front()->getFirstChild() != NULL) {
            multiway_tree_node* child = q.front()->getFirstChild();
            while (NULL != child) {
                q.push(child);
                child = child->getNextSibling();
            }
        }
        q.pop();
    }

    return res;
}

element_s* BSW07::decryptNode(Ciphertext *ciphertext, Key *secret_key, multiway_tree_node *x) {
    if (x->getType() == multiway_tree_node::LEAF) {
        // get Di and Di_
        element_s *Di = secret_key->getComponent("D" + x->getName());
        if (Di == NULL) {
            return NULL;
        }
        element_s *Di_ = secret_key->getComponent("D" + x->getName() + "_");
        if (Di_ == NULL) {
            return NULL;
        }

        // get Cx and Cx_
        element_s *Cx = ciphertext->getComponent("C" + x->getName());
        element_s *Cx_ = ciphertext->getComponent("C" + x->getName() + "_");

        // compute e_Di_Cx
        element_t e_Di_Cx;
        element_init_GT(e_Di_Cx, pairing);
        element_pairing(e_Di_Cx, Di, Cx);

        // compute e_Di__Cx_
        element_t e_Di__Cx_;
        element_init_GT(e_Di__Cx_, pairing);
        element_pairing(e_Di__Cx_, Di_, Cx_);

        element_t *res = new element_t[1];
        element_init_GT(*res, pairing);
        element_div(*res, e_Di_Cx, e_Di__Cx_);

        return *res;
    }

    signed long int child_index = 1;
    multiway_tree_node *child_node = x->getFirstChild();
    map<signed long int, element_s*> available_Fzs;
    while (child_node != NULL) {
        element_s *Fz = decryptNode(ciphertext, secret_key, child_node);
        if (Fz != NULL) {
            element_t *insert_Fz = new element_t[1];
            element_init_same_as(*insert_Fz, Fz);
            element_set(*insert_Fz, Fz);
            available_Fzs.insert(pair<signed long int, element_s*>(child_index, *insert_Fz));
        }
        ++child_index;
        child_node = child_node->getNextSibling();
    }

    if (available_Fzs.size() < x->getThreshold()) {
        return NULL;
    }

    element_t *result = new element_t[1];
    element_init_GT(*result, pairing);
    map<signed long int, element_s*>::iterator iterator1;
    for (iterator1 = available_Fzs.begin(); iterator1 != available_Fzs.end(); ++iterator1) {
        element_t i;
        element_init_Zr(i, pairing);
        element_set_si(i, iterator1->first);

        // compute lagrange_coefficient
        element_t lagrange_coefficient;
        element_init_Zr(lagrange_coefficient, pairing);
        element_set1(lagrange_coefficient);
        map<signed long int, element_s*>::iterator iterator2;
        for (iterator2 = available_Fzs.begin(); iterator2 != available_Fzs.end(); ++iterator2) {
            if (iterator2->first == iterator1->first) {
                continue;
            }
            element_t j;
            element_init_Zr(j, pairing);
            element_set_si(j, iterator2->first);
            element_t j_i;
            element_init_Zr(j_i, pairing);
            element_sub(j_i, j, i);
            element_t item;
            element_init_Zr(item, pairing);
            element_div(item, j, j_i);
            element_mul(lagrange_coefficient, lagrange_coefficient, item);
        }

        // compute Fz_delta
        element_t Fz_delta;
        element_init_GT(Fz_delta, pairing);
        element_pow_zn(Fz_delta, iterator1->second, lagrange_coefficient);

        if (iterator1 == available_Fzs.begin()) {
            element_set(*result, Fz_delta);
        } else {
            element_mul(*result, *result, Fz_delta);
        }
    }
    return *result;
}

element_s* BSW07::decrypt(Ciphertext *ciphertext, Key *secret_key, vector<string> *attributes) {
    // compute access structure
    policy_resolution pr;
    element_t sample_element;
    element_init_Zr(sample_element, pairing);
    multiway_tree *T = pr.ThresholdExpressionToMultiwayTree(ciphertext->getPolicy(), sample_element);
    element_s *A = decryptNode(ciphertext, secret_key, T->getRoot());
//    element_printf("A is \n%B\n", A);
//    element_t A_;
//    element_init_GT(A_,pairing);
//    element_t e_gg;
//    element_init_GT(e_gg, pairing);
//    element_set(e_gg, ciphertext->getComponent("e_gg"));
//    element_t r, s;
//    element_init_Zr(r, pairing);
//    element_init_Zr(s, pairing);
//    element_set(r, secret_key->getComponent("r"));
//    element_set(s, ciphertext->getComponent("s"));
//    element_t rs;
//    element_init_Zr(rs, pairing);
//    element_mul(rs, r, s);
//    element_pow_zn(A_, e_gg, rs);
//    element_printf("A_ is \n%B\n", A_);
    if (A == NULL) {
        return NULL;
    }

    // get C_tilde
    element_t C_tilde;
    element_init_GT(C_tilde, pairing);
    element_set(C_tilde, ciphertext->getComponent("C_tilde"));

    // get C
    element_t C;
    element_init_G1(C, pairing);
    element_set(C, ciphertext->getComponent("C"));

    // get D
    element_t D;
    element_init_G1(D, pairing);
    element_set(D, secret_key->getComponent("D"));

    // compute e_CD
    element_t e_CD;
    element_init_GT(e_CD, pairing);
    element_pairing(e_CD, C, D);

    // compute e_CD_A
    element_t e_CD_A;
    element_init_GT(e_CD_A, pairing);
    element_div(e_CD_A, e_CD, A);

    element_t *res = new element_t[1];
    element_init_GT(*res, pairing);
    element_div(*res, C_tilde, e_CD_A);

    return *res;
}