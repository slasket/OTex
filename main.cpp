#include <iostream>
#include <cryptopp/elgamal.h>
#include "cryptopp/sha.h"
#include "cryptopp/filters.h"
#include "cryptopp/base64.h"
#include "elgamal.h"
#include "cryptopp/nbtheory.h"
#include "IntialOT.h"

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

void InitialOTExample(int choiceBit, int keysize, string string0, string string1){
    IntialOT::Alice alice(choiceBit);
    IntialOT::Bob bob(string0,string1);

    auto pkarr = alice.genPKArray(keysize);
    auto cipherArr = bob.receivePKArray(pkarr);
    cout<< alice.receiveCipherArr(cipherArr)<< endl;
}

int main() {
    InitialOTExample(0,128, "hej", "farvel");
    InitialOTExample(1,128, "hej", "farvel");

    //sampleEncryption();


    return 0;
}

