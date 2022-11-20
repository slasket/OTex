//
// Created by a on 16/11/2022.
//

#include <iostream>
#include "cryptopp./elgamal.h"
#include "cryptopp./osrng.h"
#include "cassert"


#ifndef OTEX_ELGAMAL_H
#define OTEX_ELGAMAL_H
using namespace CryptoPP;
using namespace std;

class elgamal {


public:
    static ElGamal::PrivateKey KeyGen(int keySize);

    static tuple<Integer, Integer> OGen(const Integer& mod, int keySize);




};

#endif //OTEX_ELGAMAL_H
