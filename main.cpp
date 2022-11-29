#include <iostream>
#include <cryptopp/elgamal.h>
#include "cryptopp/sha.h"
#include "cryptopp/filters.h"
#include "cryptopp/base64.h"
#include "elgamal.h"
#include "cryptopp/nbtheory.h"
#include "InitialOT.h"

void sampleEncryption();

void timing1Of2OT();

void testGroupParaInit();

std::string SHA256HashString(std::string aString){
    std::string digest;
    CryptoPP::SHA256 hash;

    CryptoPP::StringSource foo(aString, true,
                               new CryptoPP::HashFilter(hash,
                                                        new CryptoPP::Base64Encoder (
                                                                new CryptoPP::StringSink(digest))));

    return digest;
}

/*void sampleEncryption() {
    ElGamal::PrivateKey privateKey = elgamal::KeyGen(128);
    ElGamal::PublicKey publicKey;
    publicKey.AssignFrom(privateKey);
    tuple<Integer, Integer, Integer> ogenStuff = elgamal::OGen(privateKey.GetGroupParameters().GetModulus(), 128);
    string c = elgamal::Encrypt("banan",
                                publicKey.GetGroupParameters().GetModulus(),
                                publicKey.GetGroupParameters().GetGenerator(),
                                publicKey.GetPublicElement());
    cout << c << endl;
    string d = elgamal::Decrypt(c,
                                privateKey.GetGroupParameters().GetModulus(),
                                privateKey.GetGroupParameters().GetGenerator(),
                                privateKey.GetPrivateExponent());
    cout << d << endl;
}*/

/*void InitialOTExample(int keysize, int choiceBit, string string0, string string1){
    InitialOT::Alice alice(choiceBit);
    InitialOT::Bob bob(string0, string1);

    auto pkarr = alice.genPKArray(keysize);
    string* cipherArr = bob.receivePKArray(pkarr);
    cout<< alice.receiveCipherArr(cipherArr)<< endl;
}

void timing1Of2OT() {
    auto begin = chrono::steady_clock::now();
    for (int i = 0; i < 128; ++i) {
        InitialOT::OT1out2(128, 0, "xd", "haha");//cout<< <<endl;
    }
    //cout<< InitialOT::OT1out2(128,1,"xd","haha")<<endl;
    auto end = chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<chrono::nanoseconds>(end - begin);
    printf("Time measured: %.3f seconds.\n", elapsed.count() * 1e-9);

    begin = chrono::steady_clock::now();
    for (int i = 0; i < 256; ++i) {
        InitialOT::OT1out2(256, 0, "xd", "haha");//cout<< <<endl;
    }
    end = chrono::steady_clock::now();
    elapsed = std::chrono::duration_cast<chrono::nanoseconds>(end - begin);
    printf("Time measured: %.3f seconds.\n", elapsed.count() * 1e-9);
}*/


int main() {
    InitialOT::BaseOT(2048,128);

    //timing1Of2OT();

    //sampleEncryption();

    //testGroupParaInit();

    return 0;
}

void testGroupParaInit() {
    auto privateKey = elgamal::InitializeGroupParameters(
            128);

    Integer mod = privateKey.GetGroupParameters().GetModulus();
    Integer g = privateKey.GetGroupParameters().GetGenerator();

    for (int i = 0; i < 10000; ++i) {
        const tuple<Integer, Integer> &keyValues = elgamal::KeyGen(128, mod, g);
        string c = elgamal::Encrypt(("banan" + to_string(i)), mod, g, get<0>(keyValues));
        //cout << c << endl;
        string d = elgamal::Decrypt(c, mod, g, get<1>(keyValues));
        //cout << d << endl;
    }
}



