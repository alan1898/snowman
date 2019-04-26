//
// Created by alan on 19-4-26.
//

#include "SR02.h"

void SR02::element_F(element_s *f_t, element_s *u, element_s *h, element_s *t) {
    element_t u_t;
    element_init_same_as(u_t, u);

    element_pow_zn(u_t, u, t);

    element_mul(f_t, u_t, h);
}

vector<abe_key*>* SR02::setUp() {
    // init pairing
    pbc_param_t par;
    curve_param curves;
    pbc_param_init_set_str(par, curves.a_param.c_str());
    pairing_init_pbc_param(pairing, par);

    // generate the master private key and the public parameter
    element_t alpha;
    element_t g, w, v, u, h, u0, h0, e_gg_alpha;
    // the median
    element_t e_gg;
    // init elements
    element_init_Zr(alpha, pairing);
    element_init_G1(g, pairing);
    element_init_G1(w, pairing);
    element_init_G1(v, pairing);
    element_init_G1(u, pairing);
    element_init_G1(h, pairing);
    element_init_G1(u0, pairing);
    element_init_G1(h0, pairing);
    element_init_GT(e_gg_alpha, pairing);
    element_init_GT(e_gg, pairing);
    // randomly generate
    element_random(alpha);
    element_random(g);
    element_random(w);
    element_random(v);
    element_random(u);
    element_random(h);
    element_random(u0);
    element_random(h0);
    // compute
    element_pairing(e_gg, g, g);
    element_pow_zn(e_gg_alpha, e_gg, alpha);

    // get the public key and the master key
    abe_key *master_key = new abe_key(abe_key::MASTER);
    abe_key *public_key = new abe_key(abe_key::PUBLIC);

    master_key->insertComponent("alpha", alpha);
    public_key->insertComponent("g", g);
    public_key->insertComponent("w", w);
    public_key->insertComponent("v", v);
    public_key->insertComponent("u", u);
    public_key->insertComponent("h", h);
    public_key->insertComponent("u0", u0);
    public_key->insertComponent("h0", h0);
    public_key->insertComponent("e_gg_alpha", e_gg_alpha);

    vector<abe_key*> *res = new vector<abe_key*>(2);
    (*res)[0] = master_key;
    (*res)[1] = public_key;

    return res;
}

vector<abe_key*>* SR02::userKG(abe_key *public_key, string user_id) {
    // obtain g
    element_t g;
    element_init_same_as(g, public_key->getComponent("g"));
    element_set(g, public_key->getComponent("g"));

    // randomly select the user's secret key
    element_t betaid;
    element_init_Zr(betaid, pairing);
    element_random(betaid);

    // compute the user's public key
    element_t g_betaid;
    element_init_same_as(g_betaid, g);
    element_pow_zn(g_betaid, g, betaid);

    // get the secret key and the public key
    abe_key *sk = new abe_key(abe_key::SECRET);
    abe_key *pk = new abe_key(abe_key::PUBLIC);

    sk->insertComponent("sk" + user_id, betaid);
    pk->insertComponent("pk" + user_id, g_betaid);

    vector<abe_key*> *res = new vector<abe_key*>(2);
    (*res)[0] = sk;
    (*res)[1] = pk;

    return res;
}

void SR02::pubKG(abe_key *public_key, abe_key *master_key, string user_id, abe_key *pk, vector<string> *attributes,
                 sar_kgc *kgc) {
    // obtain the public parameters
    element_t g, w, v, u, h, u0, h0, e_gg_alpha;
    element_init_same_as(g, public_key->getComponent("g"));
    element_set(g, public_key->getComponent("g"));
    element_init_same_as(w, public_key->getComponent("w"));
    element_set(w, public_key->getComponent("w"));
    element_init_same_as(v, public_key->getComponent("v"));
    element_set(v, public_key->getComponent("v"));
    element_init_same_as(u, public_key->getComponent("u"));
    element_set(u, public_key->getComponent("u"));
    element_init_same_as(h, public_key->getComponent("h"));
    element_set(h, public_key->getComponent("h"));
    element_init_same_as(u0, public_key->getComponent("u0"));
    element_set(u0, public_key->getComponent("u0"));
    element_init_same_as(h0, public_key->getComponent("h0"));
    element_set(h0, public_key->getComponent("h0"));
    element_init_same_as(e_gg_alpha, public_key->getComponent("e_gg_alpha"));
    element_set(e_gg_alpha, public_key->getComponent("e_gg_alpha"));

    // obtain the master key
    element_t alpha;
    element_init_same_as(alpha, master_key->getComponent("alpha"));
    element_set(alpha, master_key->getComponent("alpha"));

    // obtain the pkid
    element_t pkid;
    element_init_same_as(pkid, pk->getComponent("pk" + user_id));
    element_set(pkid, pk->getComponent("pk" + user_id));

    // util
    utils util;

    // expand if full
    if (kgc->getUserTree()->getUndefinedLeaves()->empty()) {
        util.expandSarTree(kgc->getUserTree());
    }

    // choose a undefined leaf
    sar_tree_node *selected_node = kgc->getUserTree()->getUndefinedLeaves()->front();
    kgc->getUserTree()->getUndefinedLeaves()->pop();

    // store user id in this node
    selected_node->setUserId(user_id);
    kgc->insertIdToUserTreeNode(user_id, selected_node);

    // compute Px1, Px2, Px3 and Px4
    sar_tree_node *p = selected_node;
    while ((NULL != p) && (!(p->isRevoked()))) {
        // get gx
        element_t gx;
        element_init_G1(gx, pairing);
        if (p->gxIsDefined()) {
            element_set(gx, p->getGx());
        } else {
            element_random(gx);
            p->setGx(gx);
        }

        // compute gx'
        element_t gx_;
        element_init_G1(gx_, pairing);
        element_t pkid_alpha;
        element_init_G1(pkid_alpha, pairing);
        element_pow_zn(pkid_alpha, pkid, alpha);
        element_div(gx_, pkid_alpha, gx);

        // randomly choose rx
        element_t rx;
        element_init_Zr(rx, pairing);
        element_random(rx);
        // compute w_rx
        element_t w_rx;
        element_init_G1(w_rx, pairing);
        element_pow_zn(w_rx, w, rx);

        // compute neg_rx
        element_t neg_rx;
        element_init_Zr(neg_rx, pairing);
        element_neg(neg_rx, rx);
        // compute v_neg_rx
        element_t v_neg_rx;
        element_init_G1(v_neg_rx, pairing);
        element_pow_zn(v_neg_rx, v, neg_rx);

        // compute Px1 and Px2
        element_t Px1, Px2;
        element_init_G1(Px1, pairing);
        element_init_G1(Px2, pairing);
        element_mul(Px1, gx_, w_rx);
        element_pow_zn(Px2, g, rx);

        p->insertValue("Px" + user_id + "1", Px1);
        p->insertValue("Px" + user_id + "2", Px2);

        // compute Px3i and Px4i
        for (signed long int i = 0; i < attributes->size(); ++i) {
            // randomly choose rxi
            element_t rxi;
            element_init_Zr(rxi, pairing);
            element_random(rxi);

            // compute Ai
            element_t Ai;
            element_init_Zr(Ai, pairing);
            unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
            SHA256_CTX sha256;
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, (*attributes)[i].c_str(), (*attributes)[i].size());
            SHA256_Final(hash_str_byte, &sha256);
            element_from_hash(Ai, hash_str_byte, SHA256_DIGEST_LENGTH);
            // compute F1_Ai
            element_t F1_Ai;
            element_init_G1(F1_Ai, pairing);
            element_F(F1_Ai, u, h, Ai);
            // compute F1_Ai_rxi
            element_t F1_Ai_rxi;
            element_init_G1(F1_Ai_rxi, pairing);
            element_pow_zn(F1_Ai_rxi, F1_Ai, rxi);

            element_t Px3i, Px4i;
            element_init_G1(Px3i, pairing);
            element_init_G1(Px4i, pairing);
            element_pow_zn(Px3i, g, rxi);
            element_mul(Px4i, F1_Ai_rxi, v_neg_rx);

            p->insertValue("Px" + user_id + "3i" + (*attributes)[i], Px3i);
            p->insertValue("Px" + user_id + "4i" + (*attributes)[i], Px4i);
        }

        p = p->getParent();
    }
}

void SR02::tKeyUp(abe_key *public_key, abe_key *master_key, sar_kgc *kgc) {
    utils util;

    // obtain the public parameters
    element_t g, w, v, u, h, u0, h0, e_gg_alpha;
    element_init_same_as(g, public_key->getComponent("g"));
    element_set(g, public_key->getComponent("g"));
    element_init_same_as(w, public_key->getComponent("w"));
    element_set(w, public_key->getComponent("w"));
    element_init_same_as(v, public_key->getComponent("v"));
    element_set(v, public_key->getComponent("v"));
    element_init_same_as(u, public_key->getComponent("u"));
    element_set(u, public_key->getComponent("u"));
    element_init_same_as(h, public_key->getComponent("h"));
    element_set(h, public_key->getComponent("h"));
    element_init_same_as(u0, public_key->getComponent("u0"));
    element_set(u0, public_key->getComponent("u0"));
    element_init_same_as(h0, public_key->getComponent("h0"));
    element_set(h0, public_key->getComponent("h0"));
    element_init_same_as(e_gg_alpha, public_key->getComponent("e_gg_alpha"));
    element_set(e_gg_alpha, public_key->getComponent("e_gg_alpha"));

    // obtain the master key
    element_t alpha;
    element_init_same_as(alpha, master_key->getComponent("alpha"));
    element_set(alpha, master_key->getComponent("alpha"));

    // get KUNodes
    map<sar_tree_node*, bool> *kunodes = util.sarKUNodes(kgc->getUserTree());

    // get t
    element_t t;
    element_init_Zr(t, pairing);
    string t_string(kgc->getTString());
    unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, t_string.c_str(), t_string.size());
    SHA256_Final(hash_str_byte, &sha256);
    element_from_hash(t, hash_str_byte, SHA256_DIGEST_LENGTH);

    // compute F2_t
    element_t F2_t;
    element_init_G1(F2_t, pairing);
    element_F(F2_t, u0, h0, t);

    map<sar_tree_node*, bool>::iterator iterator1;
    for (iterator1 = kunodes->begin(); iterator1 != kunodes->end(); ++iterator1) {
        // get gx
        element_t gx;
        element_init_G1(gx, pairing);
        if (iterator1->first->gxIsDefined()) {
            element_set(gx, iterator1->first->getGx());
        } else {
            element_random(gx);
            iterator1->first->setGx(gx);
        }

        // randomly choose sx
        element_t sx;
        element_init_Zr(sx, pairing);
        element_random(sx);

        // compute Qx1 and Qx2
        element_t F2_t_sx;
        element_init_G1(F2_t_sx, pairing);
        element_pow_zn(F2_t_sx, F2_t, sx);
        element_t Qx1, Qx2;
        element_init_G1(Qx1, pairing);
        element_init_G1(Qx2, pairing);
        element_mul(Qx1, gx, F2_t_sx);
        element_pow_zn(Qx2, g, sx);

        map<string, element_s*>::iterator iterator2 = iterator1->first->getValue()->find("Qx1");
        if (iterator2 != iterator1->first->getValue()->end()) {
            iterator1->first->getValue()->erase(iterator2);
        }
        map<string, element_s*>::iterator iterator3 = iterator1->first->getValue()->find("Qx2");
        if (iterator3 != iterator1->first->getValue()->end()) {
            iterator1->first->getValue()->erase(iterator3);
        }
        iterator1->first->insertValue("Qx1", Qx1);
        iterator1->first->insertValue("Qx2", Qx2);
    }
}

abe_key* SR02::tranKG(abe_key *public_key, string user_id, vector<string> *attributes, sar_kgc *kgc) {
    utils util;

    abe_key *res = new abe_key();

    // obtain the public parameters
    element_t g, w, v, u, h, u0, h0, e_gg_alpha;
    element_init_same_as(g, public_key->getComponent("g"));
    element_set(g, public_key->getComponent("g"));
    element_init_same_as(w, public_key->getComponent("w"));
    element_set(w, public_key->getComponent("w"));
    element_init_same_as(v, public_key->getComponent("v"));
    element_set(v, public_key->getComponent("v"));
    element_init_same_as(u, public_key->getComponent("u"));
    element_set(u, public_key->getComponent("u"));
    element_init_same_as(h, public_key->getComponent("h"));
    element_set(h, public_key->getComponent("h"));
    element_init_same_as(u0, public_key->getComponent("u0"));
    element_set(u0, public_key->getComponent("u0"));
    element_init_same_as(h0, public_key->getComponent("h0"));
    element_set(h0, public_key->getComponent("h0"));
    element_init_same_as(e_gg_alpha, public_key->getComponent("e_gg_alpha"));
    element_set(e_gg_alpha, public_key->getComponent("e_gg_alpha"));

    // get KUNodes
    map<sar_tree_node*, bool> *kunodes = util.sarKUNodes(kgc->getUserTree());

    // get the node stored user id
    map<string, sar_tree_node*>::iterator iterator1 = kgc->getIdToUserTreeNode()->find(user_id);
    if (iterator1 == kgc->getIdToUserTreeNode()->end()) {
        return NULL;
    }
    sar_tree_node *user_node = iterator1->second;

    // get pair(i, j)
    sar_tree_node *p = user_node;
    while (p != NULL) {
        map<sar_tree_node*, bool>::iterator iterator2 = kunodes->find(p);
        if (iterator2 != kunodes->end()) {
            break;
        }
        p = p->getParent();
    }
    if (p == NULL) {
        return NULL;
    }

    // get Px1 and Px2
    element_t Px1, Px2;
    element_init_G1(Px1, pairing);
    element_init_G1(Px2, pairing);
    element_set(Px1, p->getValue("Px" + user_id + "1"));
    element_set(Px2, p->getValue("Px" + user_id + "2"));
    // get Qx1 and Qx2
    element_t Qx1, Qx2;
    element_init_G1(Qx1, pairing);
    element_init_G1(Qx2, pairing);
    element_set(Qx1, p->getValue("Qx1"));
    element_set(Qx2, p->getValue("Qx2"));

    // get t
    element_t t;
    element_init_Zr(t, pairing);
    string t_string(kgc->getTString());
    unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, t_string.c_str(), t_string.size());
    SHA256_Final(hash_str_byte, &sha256);
    element_from_hash(t, hash_str_byte, SHA256_DIGEST_LENGTH);
    // compute F2_t
    element_t F2_t;
    element_init_G1(F2_t, pairing);
    element_F(F2_t, u0, h0, t);

    // randomly choose rx_ and sx_
    element_t rx_, sx_;
    element_init_Zr(rx_, pairing);
    element_init_Zr(sx_, pairing);
    element_random(rx_);
    element_random(sx_);

    // compute neg_rx_
    element_t neg_rx_;
    element_init_Zr(neg_rx_, pairing);
    element_neg(neg_rx_, rx_);
    // compute v_neg_rx_
    element_t v_neg_rx_;
    element_init_G1(v_neg_rx_, pairing);
    element_pow_zn(v_neg_rx_, v, neg_rx_);

    // compute w_rx_
    element_t w_rx_;
    element_init_G1(w_rx_, pairing);
    element_pow_zn(w_rx_, w, rx_);
    // compute g_rx_
    element_t g_rx_;
    element_init_G1(g_rx_, pairing);
    element_pow_zn(g_rx_, g, rx_);
    // compute F2_t_sx_
    element_t F2_t_sx_;
    element_init_G1(F2_t_sx_, pairing);
    element_pow_zn(F2_t_sx_, F2_t, sx_);
    // compute g_sx_
    element_t g_sx_;
    element_init_G1(g_sx_, pairing);
    element_pow_zn(g_sx_, g, sx_);

    // compute tk1, tk2, tk5
    element_t P_Q;
    element_init_G1(P_Q, pairing);
    element_mul(P_Q, Px1, Qx1);
    element_t P_Q_w;
    element_init_G1(P_Q_w, pairing);
    element_mul(P_Q_w, P_Q, w_rx_);
    element_t tk1;
    element_init_G1(tk1, pairing);
    element_mul(tk1, P_Q_w, F2_t_sx_);
    element_t tk2;
    element_init_G1(tk2, pairing);
    element_mul(tk2, Px2, g_rx_);
    element_t tk5;
    element_init_G1(tk5, pairing);
    element_mul(tk5, Qx2, g_sx_);

    res->insertComponent("tk1", tk1);
    res->insertComponent("tk2", tk2);
    res->insertComponent("tk5", tk5);

    for (signed long int i = 0; i < attributes->size(); ++i) {
        // get Px3i and Px4i
        element_t Px3i, Px4i;
        element_init_G1(Px3i, pairing);
        element_init_G1(Px4i, pairing);
        element_set(Px3i, p->getValue("Px" + user_id + "3i" + (*attributes)[i]));
        element_set(Px4i, p->getValue("Px" + user_id + "4i" + (*attributes)[i]));

        // randomly choose rxi_
        element_t rxi_;
        element_init_Zr(rxi_, pairing);
        element_random(rxi_);

        // compute g_rxi_
        element_t g_rxi_;
        element_init_G1(g_rxi_, pairing);
        element_pow_zn(g_rxi_, g, rxi_);

        // compute Ai
        element_t Ai;
        element_init_Zr(Ai, pairing);
        unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, (*attributes)[i].c_str(), (*attributes)[i].size());
        SHA256_Final(hash_str_byte, &sha256);
        element_from_hash(Ai, hash_str_byte, SHA256_DIGEST_LENGTH);
        // compute F1_Ai
        element_t F1_Ai;
        element_init_G1(F1_Ai, pairing);
        element_F(F1_Ai, u, h, Ai);
        // compute F1_Ai_rxi_
        element_t F1_Ai_rxi_;
        element_init_G1(F1_Ai_rxi_, pairing);
        element_pow_zn(F1_Ai_rxi_, F1_Ai, rxi_);

        // compute tk3i
        element_t tk3i;
        element_init_G1(tk3i, pairing);
        element_mul(tk3i, Px3i, g_rxi_);
        // compute tk4i
        element_t F_v;
        element_init_G1(F_v, pairing);
        element_mul(F_v, F1_Ai_rxi_, v_neg_rx_);
        element_t tk4i;
        element_init_G1(tk4i, pairing);
        element_mul(tk4i, Px4i, F_v);

        res->insertComponent("tk" + (*attributes)[i] + "3i", tk3i);
        res->insertComponent("tk" + (*attributes)[i] + "4i", tk4i);
    }

    return res;
}

abe_ciphertext* SR02::encrypt(abe_key *public_key, string policy, element_s *t, element_s *m) {
    element_t sample_element;
    element_init_Zr(sample_element, pairing);
    abe_ciphertext *res = new abe_ciphertext(policy, sample_element);

    policy_resolution pr;
    policy_generation pg;
    vector<string>* postfix_expression = pr.infixToPostfix(policy);
    binary_tree* binary_tree_expression = pr.postfixToBinaryTree(postfix_expression, sample_element);
    pg.generatePolicyInMatrixForm(binary_tree_expression);
    element_t_matrix* M = pg.getPolicyInMatrixFormFromTree(binary_tree_expression);
    map<signed long int, string>* rho = pg.getRhoFromTree(binary_tree_expression);

    // obtain the public parameters
    element_t g, w, v, u, h, u0, h0, e_gg_alpha;
    element_init_same_as(g, public_key->getComponent("g"));
    element_set(g, public_key->getComponent("g"));
    element_init_same_as(w, public_key->getComponent("w"));
    element_set(w, public_key->getComponent("w"));
    element_init_same_as(v, public_key->getComponent("v"));
    element_set(v, public_key->getComponent("v"));
    element_init_same_as(u, public_key->getComponent("u"));
    element_set(u, public_key->getComponent("u"));
    element_init_same_as(h, public_key->getComponent("h"));
    element_set(h, public_key->getComponent("h"));
    element_init_same_as(u0, public_key->getComponent("u0"));
    element_set(u0, public_key->getComponent("u0"));
    element_init_same_as(h0, public_key->getComponent("h0"));
    element_set(h0, public_key->getComponent("h0"));
    element_init_same_as(e_gg_alpha, public_key->getComponent("e_gg_alpha"));
    element_set(e_gg_alpha, public_key->getComponent("e_gg_alpha"));

    // generate s
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

    // compute C0, C1, C5
    element_t e_gg_alpha_s;
    element_init_GT(e_gg_alpha_s, pairing);
    element_pow_zn(e_gg_alpha_s, e_gg_alpha, s);
    element_t C0, C1;
    element_init_GT(C0, pairing);
    element_init_G1(C1, pairing);
    element_mul(C0, e_gg_alpha_s, m);
    element_pow_zn(C1, g, s);
    element_t F2_t;
    element_init_G1(F2_t, pairing);
    element_F(F2_t, u0, h0, t);
    element_t C5;
    element_init_G1(C5, pairing);
    element_pow_zn(C5, F2_t, s);

    res->insertComponent("C0", C0);
    res->insertComponent("C1", C1);
    res->insertComponent("C5", C5);

    // compute C2i, C3i, C4i
    for (signed long int i = 0; i < M->row(); ++i) {
        // randomly choose ri and get neg_ri
        element_t ri;
        element_init_Zr(ri, pairing);
        element_random(ri);
        element_t neg_ri;
        element_init_Zr(neg_ri, pairing);
        element_neg(neg_ri, ri);

        // compute w_vi, v_ri
        element_t w_vi, v_ri;
        element_init_G1(w_vi, pairing);
        element_init_G1(v_ri, pairing);
        element_pow_zn(w_vi, w, shares->getElement(i));
        element_pow_zn(v_ri, v, ri);

        // get attribute
        map<signed long int, string>::iterator it = rho->find(i);
        string attr = it->second;

        // get Ai
        element_t Ai;
        element_init_Zr(Ai, pairing);
        unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, attr.c_str(), attr.size());
        SHA256_Final(hash_str_byte, &sha256);
        element_from_hash(Ai, hash_str_byte, SHA256_DIGEST_LENGTH);

        // compute F1_Ai
        element_t F1_Ai;
        element_init_G1(F1_Ai, pairing);
        element_F(F1_Ai, u, h, Ai);

        // compute
        element_t C2i, C3i, C4i;
        element_init_G1(C2i, pairing);
        element_init_G1(C3i, pairing);
        element_init_G1(C4i, pairing);
        element_mul(C2i, w_vi, v_ri);
        element_pow_zn(C3i, F1_Ai, neg_ri);
        element_pow_zn(C4i, g, ri);

        res->insertComponent("C" + attr + "2i", C2i);
        res->insertComponent("C" + attr + "3i", C3i);
        res->insertComponent("C" + attr + "4i", C4i);
    }

    return res;
}

abe_key* SR02::transform(abe_key *public_key, string user_id, vector<string> *attributes, abe_ciphertext *CT,
                         abe_key *tkid, element_s *t) {
    // compute wi
    utils util;
//    map<signed long int, string>::iterator test_it;
//    for (test_it = CT->getRho()->begin(); test_it != CT->getRho()->end(); ++test_it) {
//        cout << "key = " << test_it->first << ", value = " << test_it->second << endl;
//    }
    map<signed long int, signed long int>* matchedAttributes = util.attributesMatching(attributes, CT->getRho());
//    cout << "matched attributes is" << endl;
//    map<signed long int, signed long int>::iterator iterator1;
//    for (iterator1 = matchedAttributes->begin(); iterator1 != matchedAttributes->end(); ++iterator1) {
//        cout << "key: " << iterator1->first << ", value: " << iterator1->second << endl;
//    }
    element_t_matrix* attributesMatrix = util.getAttributesMatrix(CT->getM(), matchedAttributes);
//    cout << "attributes matrix is" << endl;
//    attributesMatrix->printMatrix();
    map<signed long int, signed long int>* x_to_attributes = util.xToAttributes(CT->getM(), matchedAttributes);
//    cout << "x to attributes is" << endl;
//    map<signed long int, signed long int>::iterator iterator2;
//    for (iterator2 = x_to_attributes->begin(); iterator2 != x_to_attributes->end(); ++iterator2) {
//        cout << "key: " << iterator2->first << ", value: " << iterator2->second << endl;
//    }
    element_t_matrix* inverse_M = util.inverse(attributesMatrix);
//    cout << "inverse attributes matrix is" << endl;
//    inverse_M->printMatrix();
    element_t_vector* unit = util.getCoordinateAxisUnitVector(inverse_M);
    element_t_vector* x= new element_t_vector(inverse_M->col(), inverse_M->getElement(0, 0));
    extend_math_operation emo;
    signed long int type = emo.gaussElimination(x, inverse_M, unit);
    if (-1 == type) {
        return NULL;
    }

    // get tk1, tk2, tk5
    element_t tk1, tk2, tk5;
    element_init_G1(tk1, pairing);
    element_init_G1(tk2, pairing);
    element_init_G1(tk5, pairing);
    element_set(tk1, tkid->getComponent("tk1"));
    element_set(tk2, tkid->getComponent("tk2"));
    element_set(tk5, tkid->getComponent("tk5"));

    // get C0, C1, C5
    element_t C0, C1, C5;
    element_init_GT(C0, pairing);
    element_init_G1(C1, pairing);
    element_init_G1(C5, pairing);
    element_set(C0, CT->getComponent("C0"));
    element_set(C1, CT->getComponent("C1"));
    element_set(C5, CT->getComponent("C5"));

    // compute e_C1_tk1
    element_t e_C1_tk1;
    element_init_GT(e_C1_tk1, pairing);
    element_pairing(e_C1_tk1, C1, tk1);
    // compute e_C5_tk5
    element_t e_C5_tk5;
    element_init_GT(e_C5_tk5, pairing);
    element_pairing(e_C5_tk5, C5, tk5);

    // molecular
    element_t molecular;
    element_init_GT(molecular, pairing);

    map<signed long int, signed long int>::iterator it;
    for (it = matchedAttributes->begin(); it != matchedAttributes->end(); ++it) {
        // get attribute
        string attr = (*attributes)[it->second];

        // get C2i, C3i, C4i
        element_t C2i, C3i, C4i;
        element_init_G1(C2i, pairing);
        element_init_G1(C3i, pairing);
        element_init_G1(C4i, pairing);
        element_set(C2i, CT->getComponent("C" + attr + "2i"));
        element_set(C3i, CT->getComponent("C" + attr + "3i"));
        element_set(C4i, CT->getComponent("C" + attr + "4i"));

        // get tk3i, tk4i
        element_t tk3i, tk4i;
        element_init_G1(tk3i, pairing);
        element_init_G1(tk4i, pairing);
        element_set(tk3i, tkid->getComponent("tk" + attr + "3i"));
        element_set(tk4i, tkid->getComponent("tk" + attr + "4i"));

        // compute pairings
        element_t e_C2i_tk2, e_C3i_tk3i, e_C4i_tk4i;
        element_init_GT(e_C2i_tk2, pairing);
        element_init_GT(e_C3i_tk3i, pairing);
        element_init_GT(e_C4i_tk4i, pairing);
        element_pairing(e_C2i_tk2, C2i, tk2);
        element_pairing(e_C3i_tk3i, C3i, tk3i);
        element_pairing(e_C4i_tk4i, C4i, tk4i);

        element_t e_e, e_e_e, item_molecular;
        element_init_GT(e_e, pairing);
        element_init_GT(e_e_e, pairing);
        element_init_GT(item_molecular, pairing);
        element_mul(e_e, e_C2i_tk2, e_C3i_tk3i);
        element_mul(e_e_e, e_e, e_C4i_tk4i);
        signed long int attribute_index = it->second;
        map<signed long int, signed long int>::iterator itt = x_to_attributes->find(attribute_index);
        signed long int x_index = itt->second;
        element_pow_zn(item_molecular, e_e_e, x->getElement(x_index));

        if (it == matchedAttributes->begin()) {
            element_set(molecular, item_molecular);
        } else {
            element_mul(molecular, molecular, item_molecular);
        }
    }

    element_mul(molecular, molecular, e_C5_tk5);

    element_t C0_;
    element_init_GT(C0_, pairing);
    element_div(C0_, molecular, e_C1_tk1);

    abe_key *res = new abe_key();

    res->insertComponent("C0_", C0_);
    res->insertComponent("C0", C0);

    return res;
}

element_s* SR02::decrypt(string user_id, abe_key *sk, abe_key *CT_) {
    // obtain the skid and compute inv_skid
    element_t skid;
    element_init_same_as(skid, sk->getComponent("sk" + user_id));
    element_set(skid, sk->getComponent("sk" + user_id));
    element_t inv_skid;
    element_init_same_as(inv_skid, skid);
    element_invert(inv_skid, skid);

    // obtain C0, C0_
    element_t C0, C0_;
    element_init_GT(C0, pairing);
    element_init_GT(C0_, pairing);
    element_set(C0, CT_->getComponent("C0"));
    element_set(C0_, CT_->getComponent("C0_"));

    // compute C0__inv_skid
    element_t C0__inv_skid;
    element_init_GT(C0__inv_skid, pairing);
    element_pow_zn(C0__inv_skid, C0_, inv_skid);

    element_t *res = new element_t[1];
    element_init_GT(*res, pairing);
    element_mul(*res, C0, C0__inv_skid);

    return *res;
}