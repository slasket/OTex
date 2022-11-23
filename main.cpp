#include <iostream>
#include <cryptopp/elgamal.h>
#include "cryptopp/sha.h"
#include "cryptopp/filters.h"
#include "cryptopp/base64.h"
#include "elgamal.h"
#include "cryptopp/nbtheory.h"
#include "InitialOT.h"

void sampleEncryption();

std::string SHA256HashString(std::string aString){
    std::string digest;
    CryptoPP::SHA256 hash;

    CryptoPP::StringSource foo(aString, true,
                               new CryptoPP::HashFilter(hash,
                                                        new CryptoPP::Base64Encoder (
                                                                new CryptoPP::StringSink(digest))));

    return digest;
}

void sampleEncryption() {
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
}

void InitialOTExample(int keysize, int choiceBit, string string0, string string1){
    InitialOT::Alice alice(choiceBit);
    InitialOT::Bob bob(string0, string1);

    auto pkarr = alice.genPKArray(keysize);
    string* cipherArr = bob.receivePKArray(pkarr);
    cout<< alice.receiveCipherArr(cipherArr)<< endl;
}


int main() {
    cout<< InitialOT::initialOT(1024,0,"xd","haha")<<endl;
    cout<< InitialOT::initialOT(1024,1,"xd","haha")<<endl;


    auto begin = std::chrono::high_resolution_clock::now();
    InitialOTExample(1024,0, "hej", "farvel");
    InitialOTExample(1024,1, "hej", "farvel");
    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    printf("Time measured: %.3f seconds.\n", elapsed.count() * 1e-9);

    begin = std::chrono::high_resolution_clock::now();
    InitialOTExample(2048,0, "hej", "farvel");
    InitialOTExample(2048,1, "hej", "farvel");
    end = std::chrono::high_resolution_clock::now();
    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    printf("Time measured: %.3f seconds.\n", elapsed.count() * 1e-9);
    //sampleEncryption();




    return 0;
}

