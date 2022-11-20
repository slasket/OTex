#include <iostream>
#include "cryptopp/sha.h"
#include "cryptopp/filters.h"
#include "cryptopp/base64.h"
#include "elgamal.h"
#include "cryptopp/nbtheory.h"

std::string SHA256HashString(std::string aString){
    std::string digest;
    CryptoPP::SHA256 hash;

    CryptoPP::StringSource foo(aString, true,
                               new CryptoPP::HashFilter(hash,
                                                        new CryptoPP::Base64Encoder (
                                                                new CryptoPP::StringSink(digest))));

    return digest;
}

int main() {
    ElGamal::PrivateKey privateKey = elgamal::KeyGen(128);
    ElGamal::PublicKey publicKey;
    publicKey.AssignFrom(privateKey);
    tuple<Integer, Integer> ogenStuff = elgamal::OGen(privateKey.GetGroupParameters().GetModulus(), 128);
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
    return 0;
}
