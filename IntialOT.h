//
// Created by a on 20/11/2022.
//

#ifndef OTEX_INTIALOT_H
#define OTEX_INTIALOT_H


#include <string>
#include <utility>
#include "cryptopp/elgamal.h"
#include "cryptopp/osrng.h"

using namespace CryptoPP;
using namespace std;

class IntialOT {


public:
    class Alice{
        int bitVal;
        ElGamal::PrivateKey privateKey;
        public:
            explicit Alice(int decisionBit){
                bitVal = decisionBit;
            };

            tuple<Integer, Integer,Integer>* genPKArray(int keySize);

            string receiveCipherArr(std::string cpArr[]);


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
};


#endif //OTEX_INTIALOT_H