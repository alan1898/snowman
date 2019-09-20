//
// Created by alan on 19-9-20.
//

#include "DET_test.h"

DET_test::DET_test() {
    // init pairing
    pbc_param_t par;
    curve_param curves;
    pbc_param_init_set_str(par, curves.a_param.c_str());
    pairing_init_pbc_param(pairing, par);
}

void DET_test::setup_test(signed long int N, signed long int count, signed long int L1, signed long int L2, signed long int L3) {
    clock_t start, end;
    double execution_time;
    double sum_time_count = 0;

    for (signed long int i = 0; i < count; ++i) {
        start = clock();
        DET *det = new DET(L1, L2, L3);
        det->setUp(N);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_count += execution_time;
    }

    execution_time = sum_time_count / count;

    printf("N-%ld, L1-%ld, L2-%ld, L3-%ld, Setup: ", N, L1, L2, L3);
    cout << execution_time << "ms" << endl;
}

void DET_test::keygen_test(signed long int N, signed long int X__size, signed long int Y__size, signed long int count, signed long int L1,
                           signed long int L2, signed long int L3) {
    clock_t start, end;
    double execution_time;
    double sum_time_count = 0;

    DET det(L1, L2, L3);

    // Y_
    vector<signed long int> *Y_ = new vector<signed long int>();
    for (signed long int i = 1; i <= Y__size; ++i) {
        Y_->push_back(i);
    }
    cout << "Y_: ";
    for (signed long int i = 0; i < Y_->size(); ++i) {
        cout << Y_->at(i) << " ";
    }
    cout << endl;

    // X_
    vector<signed long int> *X_ = new vector<signed long int>();
    for (signed long int i = Y__size + 1; i <= Y__size + X__size; ++i) {
        X_->push_back(i);
    }
    cout << "X_: ";
    for (signed long int i = 0; i < X_->size(); ++i) {
        cout << X_->at(i) << " ";
    }
    cout << endl;

    // set up
    vector<Key*> *psk = det.setUp(N);

    for (signed long int i = 0; i < count; ++i) {
        start = clock();
        det.keyGen(psk->at(1), psk->at(0), X_, Y_);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_count += execution_time;
    }

    execution_time = sum_time_count / count;

    printf("N-%ld, X__size-%ld, Y__size-%ld, L1-%ld, L2-%ld, L3-%ld, KeyGen: ", N, X__size, Y__size, L1, L2, L3);
    cout << execution_time << "ms" << endl;
}

void DET_test::trapdoor_test(signed long int N, signed long int X__size, signed long int Y__size, signed long int count,
                             signed long int L1, signed long int L2, signed long int L3) {
    clock_t start, end;
    double execution_time;
    double sum_time_count = 0;

    DET det(L1, L2, L3);

    // Y_
    vector<signed long int> *Y_ = new vector<signed long int>();
    for (signed long int i = 1; i <= Y__size; ++i) {
        Y_->push_back(i);
    }
    cout << "Y_: ";
    for (signed long int i = 0; i < Y_->size(); ++i) {
        cout << Y_->at(i) << " ";
    }
    cout << endl;

    // X_
    vector<signed long int> *X_ = new vector<signed long int>();
    for (signed long int i = Y__size + 1; i <= Y__size + X__size; ++i) {
        X_->push_back(i);
    }
    cout << "X_: ";
    for (signed long int i = 0; i < X_->size(); ++i) {
        cout << X_->at(i) << " ";
    }
    cout << endl;

    // set up
    vector<Key*> *psk = det.setUp(N);

    // key gen
    Key *sk = det.keyGen(psk->at(1), psk->at(0), X_, Y_);

    for (signed long int i = 0; i < count; ++i) {
        start = clock();
        det.trapdoor(sk, X_, Y_);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_count += execution_time;
    }

    execution_time = sum_time_count / count;

    printf("N-%ld, X__size-%ld, Y__size-%ld, L1-%ld, L2-%ld, L3-%ld, Trapdoor: ", N, X__size, Y__size, L1, L2, L3);
    cout << execution_time << "ms" << endl;
}

void DET_test::encrypt_test(signed long int N, signed long int J_size, signed long int X_size, signed long int Y_size,
                            signed long int count, signed long int L1, signed long int L2, signed long int L3) {
    clock_t start, end;
    double execution_time;
    double sum_time_count = 0;

    DET det(L1, L2, L3);

    // Y
    vector<signed long int> *Y = new vector<signed long int>();
    for (signed long int i = 1; i <= Y_size; ++i) {
        Y->push_back(i);
    }
    cout << "Y: ";
    for (signed long int i = 0; i < Y->size(); ++i) {
        cout << Y->at(i) << " ";
    }
    cout << endl;

    // J
    vector<signed long int> *J = new vector<signed long int>();
    for (signed long int i = Y_size + 1; i <= Y_size + J_size; ++i) {
        J->push_back(i);
    }
    cout << "J: ";
    for (signed long int i = 0; i < J->size(); ++i) {
        cout << J->at(i) << " ";
    }
    cout << endl;

    // X
    vector<signed long int> *X = new vector<signed long int>();
    for (signed long int i = Y_size + J_size + 1; i <= Y_size + J_size + X_size; ++i) {
        X->push_back(i);
    }
    cout << "X: ";
    for (signed long int i = 0; i < X->size(); ++i) {
        cout << X->at(i) << " ";
    }
    cout << endl;

    unsigned char *message = (unsigned char*)malloc(9);
    message[0] = 'L';
    message[1] = 'a';
    message[2] = 'n';
    message[3] = 's';
    message[4] = 'e';
    message[5] = 'o';
    message[6] = 'n';
    message[7] = '!';
    message[8] = '\0';

    // set up
    vector<Key*> *psk = det.setUp(N);

    for (signed long int i = 0; i < count; ++i) {
        start = clock();
        det.encrypt(psk->at(1), J, X, Y, message);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_count += execution_time;
    }

    printf("N-%ld, J_size-%ld, X_size-%ld, Y_size-%ld, L1-%ld, L2-%ld, L3-%ld, Encrypt: ", N, J_size, X_size, Y_size, L1, L2, L3);
    cout << execution_time << "ms" << endl;
}