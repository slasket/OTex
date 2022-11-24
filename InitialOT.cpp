//
// Created by a on 20/11/2022.
//

#include "InitialOT.h"
#include "elgamal.h"
#include "cryptopp/elgamal.h"
#include "cryptopp/osrng.h"
#include <bitset>
#include <utility>

using namespace std;

tuple<Integer, Integer,Integer>* InitialOT::Alice::genPKArray(int keySize) {
    auto begin = chrono::steady_clock::now();
    privateKey = elgamal::KeyGen(keySize);
    auto end = chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<chrono::nanoseconds>(end - begin);
    printf("Private key time: %.3f seconds.\n", elapsed.count() * 1e-9);
    Integer mod = privateKey.GetGroupParameters().GetModulus();
    Integer g = privateKey.GetGroupParameters().GetGenerator();

    ElGamal::PublicKey publicKey;
    publicKey.AssignFrom(privateKey);

    Integer h = publicKey.GetPublicElement();

    tuple<Integer, Integer,Integer> ogenVals = elgamal::OGen(mod, keySize);

    auto* pkArr = new tuple<Integer, Integer,Integer>[2];
    if (bitVal == 0){
        pkArr[0] = {mod, g,h};
        pkArr[1] = {get<0>(ogenVals),get<1>(ogenVals) ,get<2>(ogenVals)};

    } else{
        pkArr[0] = {get<0>(ogenVals),get<1>(ogenVals) ,get<2>(ogenVals)};
        pkArr[1] = {mod, g,h};
    }
    return pkArr;
}

string InitialOT::Alice::receiveCipherArr(std::string *cpArr) {
    Integer mod = privateKey.GetGroupParameters().GetModulus();
    Integer g = privateKey.GetGroupParameters().GetGenerator();
    Integer x = privateKey.GetPrivateExponent();

    auto begin = chrono::steady_clock::now();
    auto res = elgamal::Decrypt(cpArr[bitVal], mod, g, x);
    auto end = chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<chrono::nanoseconds>(end - begin);
    printf("decryption time: %.3f seconds.\n", elapsed.count() * 1e-9);
    return res;

}

string* InitialOT::Bob::receivePKArray(tuple<Integer, Integer,Integer> *pkArray) {

    auto* cipherArr= new string[2];

    auto begin = chrono::steady_clock::now();
    cipherArr[0] = elgamal::Encrypt(str0, get<0>(pkArray[0]), get<1>(pkArray[0]), get<2>(pkArray[0]));
    cipherArr[1] = elgamal::Encrypt(str1, get<0>(pkArray[1]), get<1>(pkArray[1]), get<2>(pkArray[1]));

    auto end = chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<chrono::nanoseconds>(end - begin);
    printf("Encryption time: %.3f seconds.\n", elapsed.count() * 1e-9);
    return cipherArr;
}

string InitialOT::OT1out2(int keysize, int choicebit, string string0, string string1) {
    Alice alice(choicebit);
    Bob bob(std::move(string0), std::move(string1));

    auto pkarr = alice.genPKArray(keysize);
    string *cipherArr = bob.receivePKArray(pkarr);

    return alice.receiveCipherArr(cipherArr);
}


string InitialOT::GenerateKbitString(int const k) {
    AutoSeededRandomPool prng;
    string res;
    for (int i = 0; i < k; ++i) {
        res += to_string(prng.GenerateBit());
    }
    return res;
}


string** InitialOT::BaseOT(int const elgamalkeysize, int symmetricKeysize) {

    string SenderString = GenerateKbitString(symmetricKeysize);

    auto* receiverPairs = new tuple<string,string>[symmetricKeysize];
    for (int i = 0; i < symmetricKeysize; ++i) {
        receiverPairs[i] = {GenerateKbitString(symmetricKeysize),GenerateKbitString(symmetricKeysize)};
    }

    for (int i = 0; i < symmetricKeysize; ++i) {
        cout<< i <<endl;
        int senderChoiceBit = (int)(SenderString[i]-'0');

        auto begin = chrono::steady_clock::now();
        string xd = OT1out2(elgamalkeysize, senderChoiceBit,get<0>(receiverPairs[i]),get<1>(receiverPairs[i]));
        auto end = chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<chrono::nanoseconds>(end - begin);
        printf("Protocol time: %.3f seconds.\n", elapsed.count() * 1e-9);

        cout<< xd<<endl;
    }


    return nullptr;
}

