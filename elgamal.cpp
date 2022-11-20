//
// Created by a on 16/11/2022.
//

#include "elgamal.h"
#include "cryptopp/elgamal.h"
#include "cryptopp/osrng.h"


ElGamal::PrivateKey elgamal::KeyGen(int keySize) {
    AutoSeededRandomPool prng;
    ElGamal::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(prng, keySize);
    return privateKey;
}


tuple<Integer, Integer> elgamal::OGen(const Integer& mod, int keySize) {
    AutoSeededRandomPool prng;
    Integer g = CryptoPP::Integer(prng, 2, mod);
    Integer r = CryptoPP::Integer(prng, 1, Integer::Power2(2*keySize));
    Integer h = a_exp_b_mod_c(r, 2, mod);
    return {g, h};

}
