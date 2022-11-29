//
// Created by a on 20/11/2022.
//

#ifndef OTEX_INITIALOT_H
#define OTEX_INITIALOT_H


#include <string>
#include <utility>
#include "cryptopp/elgamal.h"
#include "cryptopp/osrng.h"

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

            string receiveCipherArr(std::string cpArr[]);

            tuple<Integer, Integer, Integer> *genPKArray(int keySize, Integer mod, Integer g);
    };

    class Bob{
        string str0;
        string str1;
        public:
            explicit Bob(string string0, string string1){
                str0 = move(string0);
                str1 = move(string1);
            };

            //recive public key arr and encrypt l-bit strings
            string* receivePKArray(tuple<Integer, Integer,Integer> pkArray[]);



    };

    static string GenerateKbitString(int keysize);

    static string** BaseOT(int elgamalkeysize, int symmetricKeysize);

    static string OT1out2(int keySize, const Integer& mod, const Integer& g, int choicebit, string string0, string string1);
};


#endif //OTEX_INITIALOT_H
