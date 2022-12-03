//
// Created by a on 03/12/2022.
//

#include <vector>
#include <iostream>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <bitset>
#include <cryptopp/osrng.h>
#include <cryptopp/seckey.h>
#include <cryptopp/modes.h>
#include <sstream>
#include "util.h"
using namespace std;
using namespace CryptoPP;


vector<uint64_t> util::mbitXOR(vector<uint64_t> pInt, vector<uint64_t> pInt1, int m) {
    auto res = vector<uint64_t>((m+64-1)/64);
    for (int i = 0; i < (m+64-1)/64; ++i) {
        //Xor two 64 bit uint64_t integers
        res[i] = pInt[i] ^ pInt1[i];
    }
    return res;
}

int util::findithBit(vector<uint64_t> ui, int i) {
    //find number of blocks
    int block = (i / 64);
    int bit = i % 64;
    uint64_t ithblock = ui[block];
    uint64_t mask = 1 << bit;
    return (ithblock & mask) >> bit;
}


string util::hFunction(int i, vector<uint64_t> qmatrixi) {
    //convert qmatrixi to string
    string qmatrixiString;
    for (int j = 0; j < qmatrixi.size(); ++j) {
        qmatrixiString += to_string(qmatrixi[j]);
    }
    qmatrixiString = to_string(i) + qmatrixiString;
    //hash qmatrixiString
    string hash = SHA256HashString(qmatrixiString);
    return hash;
}

vector<uint64_t> util::randomGenerator(tuple<uint64_t, uint64_t> ki, int m) {
    //TODO: make sure the ith block corresponds to the iths least significant block of bits
    return extendKey(ki,m);
}

string util::stringXor(string x, string y) //taken from https://stackoverflow.com/questions/18830505/bitxor-on-c-strings
{
    stringstream ss;

    // works properly only if they have same length!
    for(int i = 0; i < x.length(); i++)
    {
        ss <<  (x.at(i) ^ y.at(i));
    }

    return ss.str();
}


vector<uint64_t> util::extendKey(const tuple<uint64_t, uint64_t>& key, int m) {
    int size = (m+64-1)/64;
    vector<uint64_t> res = vector<uint64_t>(size);
    int counter = 0;
    for (int i = 0; i < size; i = i + 2) {
        auto keyi = AES128CounterMode(key);
        res[i] = get<0>(keyi);
        res[i+1] = get<1>(keyi);
        if(res[i] == res[i+1]){
            cout << "ERROR: AES128CounterMode returned same key twice" << endl;
        }
        counter++;
    }
    return res;
}


vector<vector<uint64_t>> util::tranposeMatrix(vector<vector<uint64_t>> matrix) {
    return matrix; //TODO: implement
}

string util::SHA256HashString(const string& aString){
    string digest;
    SHA256 hash;

    StringSource foo(aString, true,
                     new HashFilter(hash,
                                    new Base64Encoder (
                                            new StringSink(digest))));

    return digest;
}


string util::bin2str(const string& t_){
    std::stringstream bStream(t_);
    std::string ret;
    bitset<8> t;
    while(bStream >> t) {
        ret += static_cast<char>(t.to_ulong());
    }
    return ret;
}

tuple<uint64_t, uint64_t> util::str2bin(std::string t_){
    std::string ret;
    for (char c : t_) {
        ret += bitset<8>(c).to_string();
    }
    return {std::stoull(ret.substr(0, 64), nullptr, 2), std::stoull(ret.substr(64, 64), nullptr, 2)};
}

//AES-128 counter mode encryption
tuple<uint64_t, uint64_t> util::AES128CounterMode(tuple<uint64_t, uint64_t> plaintext) {
    AutoSeededRandomPool prng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock( key, key.size() );

    CryptoPP::byte ctr[ AES::BLOCKSIZE ];
    prng.GenerateBlock( ctr, sizeof(ctr) );


    //convert plaintext to bitset
    string a0 = bitset<64>(get<0>(plaintext)).to_string();
    string a1 = bitset<64>(get<1>(plaintext)).to_string();

    string a0bin = bin2str(a0);
    string a1bin = bin2str(a1);

    string plain;
    //convert plaintext to string
    plain += a0bin;
    plain += a1bin;
    string cipher, encoded, recovered;

    /*********************************\
    \*********************************/

    try
    {

        CTR_Mode< AES >::Encryption e;
        e.SetKeyWithIV( key, key.size(), ctr );

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher. CTR does not.
        StringSource ss1( plain, true,
                          new StreamTransformationFilter( e,
                                                          new StringSink( cipher )
                          ) // StreamTransformationFilter
        ); // StringSource
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << e.what() << endl;
        exit(1);
    }

    auto result = str2bin(cipher);


    //convert result to bitset
    string result0 = bitset<64>(get<0>(result)).to_string();
    string result1 = bitset<64>(get<1>(result)).to_string();


    return result;
}


vector<uint64_t> util::entryWiseAnd(int si, const vector<uint64_t>& umatrixi, int m) {
    auto res = vector<uint64_t>((m+64-1)/64);
    uint64_t andBit;
    if (si == 0){
        andBit = 0;
    } else{
        andBit = UINT64_MAX;
    }
    for (int i = 0; i < (m+64-1)/64; ++i) {
        auto qi = umatrixi[i];
        //and two 64 bit uint64_t integers
        res[i] = qi & andBit;
    }
    return res;
}