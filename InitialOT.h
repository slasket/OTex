//
// Created by a on 20/11/2022.
//

#ifndef OTEX_INITIALOT_H
#define OTEX_INITIALOT_H


#include <string>
#include <utility>
#include "cryptopp/elgamal.h"
#include "cryptopp/osrng.h"
#include "OTExtension.h"

using namespace CryptoPP;
using namespace std;

class InitialOT {


public:
    class Alice{
        int bitVal;
        ElGamal::PrivateKey privateKey;
        public:
            explicit Alice(int decisionBit){
                bitVal = decisionBit;
            };

            tuple<uint64_t, uint64_t> receiveCipherArr(string *cpArr);

            tuple<Integer, Integer, Integer> *genPKArray(int keySize, Integer mod, Integer g);
    };

    class Bob{
        tuple<uint64_t , uint64_t> str0;
        tuple<uint64_t , uint64_t> str1;
        public:
            explicit Bob(const tuple<uint64_t , uint64_t>& string0, const tuple<uint64_t , uint64_t>& string1){
                str0 = string0;
                str1 = string1;
            };

            //receive public key arr and encrypt l-bit strings
            string* receivePKArray(tuple<Integer, Integer,Integer> pkArray[]);
    };

    static tuple<uint64_t, uint64_t> GenerateKbitString(const int keysize);

    static tuple<uint64_t, uint64_t> *
    BaseOT(int const elgamalkeysize, int symmetricKeysize, OTExtension::Sender& sender, OTExtension::Receiver& receiver);

    static tuple<uint64_t, uint64_t> OT1out2(int keySize, const Integer& mod, const Integer& g, int choicebit, const tuple<uint64_t, uint64_t>& string0, const tuple<uint64_t, uint64_t>& string1);

    static int findUIntBit(int idx, const tuple<uint64_t, uint64_t>& uint);
};


#endif //OTEX_INITIALOT_H
