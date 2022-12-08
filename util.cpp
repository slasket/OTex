//
// Created by a on 03/12/2022.
//

#include <vector>
#include <iostream>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <cryptopp/hex.h>
#include <bitset>
#include <cryptopp/osrng.h>
#include <cryptopp/seckey.h>
#include <cryptopp/modes.h>
#include <sstream>
#include "util.h"
#include <random>
using namespace std;
using namespace CryptoPP;



vector<uint64_t> util::mbitXOR(vector<uint64_t> &pInt, vector<uint64_t> &pInt1) {
    auto res = vector<uint64_t>(pInt.size());
    for (int i = 0; i < pInt.size(); ++i) {
        //Xor two 64 bit uint64_t integers
        res[i] =0;
        res[i] = pInt[i] ^ pInt1[i];
    }
    return res;
}

int util::findithBit(vector<uint64_t> ui, int i) {
    int size = ui.size();
    //ith bit
    int bit = i % 64;
    //find block
    int block = i / 64;
    string blockStr = bitset<64>(ui[block]).to_string();
    return blockStr[bit] - '0';
    //for (int j = 0; j < size; ++j) {
    //    string block = bitset<64>(ui[j]).to_string();
    //    uiString += block;
    //}
    ////find number of blocks
    //int block = (i / 64);
    //int bit = i % 64;
    //uint64_t ithblock = ui[block];
    //return bitset<64>(ithblock)[bit];
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
    //make sure the ith block corresponds to the iths least significant block of bits
    return extendKey(ki,m);
}

string util::stringXor(string x, string y) //taken from https://stackoverflow.com/questions/18830505/bitxor-on-c-strings
{
    stringstream ss;
    auto xlen = x.length();
    auto ylen = y.length();
    //check if the strings are of equal length
    if (xlen != ylen) {
        cout << "x " << x << " and y " << y << " are not of equal length" << endl;
        return "";
    }
    //else{
    //    cout << "x " << x << " and y " << y << " are of equal length" << endl;
    //}
    // works properly only if they have same length!
    for(int i = 0; i < x.length(); i++)
    {
        ss << (x[i] ^ y[i]);
    }

    return ss.str();
}


vector<uint64_t> util::extendKey(const tuple<uint64_t, uint64_t>& key, int m) {
    int size = (m+64-1)/64;
    vector<uint64_t> res = vector<uint64_t>(size);
    int counter = 0;
    for (int i = 0; i < size; i = i + 2) {
        auto keyi = AES128CounterMode(key, i);
        res[i] = get<0>(keyi);
        res[i+1] = get<1>(keyi);
        if(res[i] == res[i+1]){
            cout << "ERROR: AES128CounterMode returned same key twice" << endl;
        }
        counter++;
    }
    return res;
}


vector<vector<uint64_t>> util::transposeMatrix(vector<vector<uint64_t>>& matrix) {
    //transposition by making one key at a time
    bitset<64> higherbits;
    bitset<64> lowerbits;
    int k = matrix.size();
    int m = matrix[0].size()*64;
    vector<vector<uint64_t>> transposedMat = vector<vector<uint64_t>>(m, vector<uint64_t>((k/64)));
    for (int i = 0; i < m; ++i) {
        for (int j = 0; j < k; ++j) {
            if (j < 64) {
                auto ithHigher = findithBit(matrix[j], i);
                higherbits[63 - j] = ithHigher;
            } else {
                auto ithLower = findithBit(matrix[j], i);
                lowerbits[127 - j] = ithLower;
            }
        }
        transposedMat[i] = {higherbits.to_ullong(), lowerbits.to_ullong()};
    }

    return transposedMat;
}

vector<vector<uint64_t>> util::fastTranspose(vector<vector<uint64_t>>& matrix) {
    int k = matrix.size();
    int m = matrix[0].size()*64;
    int amountOfUints= matrix[0].size();
        vector<vector<uint64_t>> transposedMat = vector<vector<uint64_t>>(m, vector<uint64_t>(k/64));
    int windowSize = 2;
    while(windowSize<=m){
        if (windowSize<=64){
            //generate masks
            string andMask1;
            string andMask2;
            for (int l = 0; l < 64; l+=windowSize) {
                for (int n = 0; n < windowSize/2; ++n) {
                    andMask1+= "0";
                    andMask2+= "1";
                }
                for (int n = 0; n < windowSize/2; ++n) {
                    andMask1+= "1";
                    andMask2+= "0";
                }
            }
            //cout<< "andmasks for size " << windowSize <<endl;
            //cout<< andMask1<<endl;
            //cout<< andMask2<<endl;

            uint64_t mask1 = stoull(andMask1, nullptr,2);
            uint64_t mask2 = stoull(andMask2, nullptr,2);
            for (int j = 0; j < k; j+=windowSize) {
                for (int i = 0; i < amountOfUints; ++i) {
                    //get the uint to be masked
                    auto intToBeMasked = vector<uint64_t>(windowSize);
                    auto maskingVals = vector<uint64_t>(windowSize);
                    for (int l = 0; l < windowSize; ++l) {
                        intToBeMasked[l]= matrix[j+l][i];

                        if (l<(windowSize/2)){
                            maskingVals[l] = (intToBeMasked[l] & mask1)<<(windowSize/2);
                        } else{
                            maskingVals[l] = (intToBeMasked[l] & mask2)>>(windowSize/2);
                        }
                    }
                    for (int l = 0; l < windowSize; ++l) {
                        if (l<(windowSize/2)){
                            //pair up l and l+windowssize/
                            intToBeMasked[l]=(intToBeMasked[l] & mask2) ^ maskingVals[(l+(windowSize/2))];
                        }else{
                            //pair up l and l-windowssize/2
                            intToBeMasked[l]=(intToBeMasked[l]&mask1) ^maskingVals[(l-(windowSize/2))];
                        }
                    }

                    for (int l = 0; l < windowSize; ++l) {
                        matrix[j + l][i]=intToBeMasked[l];
                    }
                }
            }
        }
        if (windowSize==128){
            //move the block of 64x64 bits around
            //|a|b|->|a|c|
            //|c|d|  |b|d|
            for (int i = 0; i < amountOfUints; i+=2) {
                auto IntsToMove = vector<uint64_t>(windowSize);
                for (int j = 0; j < k; ++j) {
                    if (j<(windowSize/2)){
                        IntsToMove[(j+64)]= matrix[j][i+1];
                    }else{
                        IntsToMove[(j-64)]= matrix[j][i];
                    }
                }
                for (int j = 0; j < k; ++j) {
                    if (j<(windowSize/2)){
                        matrix[j][i+1]=IntsToMove[j];
                    }else{
                        matrix[j][i]=IntsToMove[j];
                    }
                }
            }
        }
        if (windowSize>k){
            int amountOf128keysHandled =0;
            for (int i = 0; i < amountOfUints; i+=2) {
                auto IntToMove = vector<uint64_t>(k/64);
                for (int j = 0; j < k; ++j) {
                    transposedMat[(j+amountOf128keysHandled)] = {matrix[j][i],matrix[j][i+1]};
                }
                amountOf128keysHandled+=128;
            }
            windowSize=m;
        }
        windowSize=windowSize*2;
    }
    return transposedMat;
}

string util::SHA256HashString(const string& aString){
    string digest;
    SHA256 hash;

    StringSource foo(aString, true,
                     new HashFilter(hash,
                                    new HexEncoder (
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

string util::str2bitstr(std::string t_){
    std::string ret;
    for (char c : t_) {
        ret += bitset<8>(c).to_string();
    }
    return ret;
}

string util::printBitsetofVectorofUints(vector<uint64_t> uints){
    string res;
    for (int i = 0; i < uints.size(); ++i) {
        res += bitset<64>(uints[i]).to_string();
    }
    return res;
}

//AES-128 counter mode encryption
tuple<uint64_t, uint64_t> util::AES128CounterMode(tuple<uint64_t, uint64_t> key, int counter) {
    word32 seed = 0x12345678; //TODO: change to random
    LC_RNG prng = LC_RNG(seed);
    //AutoSeededRandomPool prng;
    string plaintext = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    //convert key to CryptoPP::byte
    CryptoPP::byte keyByte[AES::DEFAULT_KEYLENGTH];
    auto key0 = get<0>(key);
    auto key1 = get<1>(key);
    for (int i = 0; i < 8; ++i) {
        keyByte[i] = (key0 >> (8 * i)) & 0xFF;
    }
    for (int i = 8; i < 16; ++i) {
        keyByte[i] = (key1 >> (8 * (i-8))) & 0xFF;
    }
    //cout << "got so far" << endl;



    //CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
    //prng.GenerateBlock( key, sizeof(key) );

    CryptoPP::byte ctr[ AES::BLOCKSIZE ];
    prng.GenerateBlock( ctr, sizeof(ctr) );
    //add counter to ctr
    for (int i = 0; i < 4; ++i) {
        ctr[i] = (counter >> (8 * i)) & 0xFF;
    }


    //convert plaintext to bitset
    //string a0 = bitset<64>(get<0>(plaintext)).to_string();
    //string a1 = bitset<64>(get<1>(plaintext)).to_string();

    //string a0bin = bin2str(a0);
    //string a1bin = bin2str(a1);

    string plain = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";;
    //convert plaintext to string
    //plain += a0bin;
    //plain += a1bin;
    string cipher, encoded, recovered;

    /*********************************\
    \*********************************/

    try
    {

        CTR_Mode< AES >::Encryption e;
        e.SetKeyWithIV( keyByte, sizeof(keyByte), ctr );

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
    //string result0 = bitset<64>(get<0>(result)).to_string();
    //string result1 = bitset<64>(get<1>(result)).to_string();


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

vector<tuple<vector<uint64_t>, vector<uint64_t>>> util::genMPairsOfLbitStrings(int pairs, int strLen) {
    //since we use sha256 we should always use 256bit string length
    AutoSeededRandomPool prng;
    auto senderPairs =  vector<tuple<vector<uint64_t>, vector<uint64_t>>>(pairs);
    auto amountOfBitsets = strLen/64;

    auto bs0vec = vector<uint64_t>(4);
    auto bs1vec = vector<uint64_t>(4);
    for (int j = 0; j < amountOfBitsets; ++j) {
        auto bs0 = random_bitset<64>();
        auto bs1 = random_bitset<64>();
        bs0vec[j]= bs0.to_ullong();
        bs1vec[j]=bs1.to_ullong();
    }
    for (int i = 0; i < pairs; ++i) {
        senderPairs[i] = {bs0vec,bs1vec};
    }

    return senderPairs;
}

vector<uint64_t> util::genRcvSelectionBits(int bits) {
   AutoSeededRandomPool prng;
   auto res = vector<uint64_t>((bits+64-1)/64);
    for (int blockNum = 0; blockNum <(bits+64-1)/64; ++blockNum) {
        res[blockNum] = random_bitset<64>().to_ullong();
        //for (int i = 0; i < 64; ++i) {bitset[i]=(prng.GenerateBit());}
        //res[blockNum]=bitset.to_ullong();
    }
   return res;
}

string util::str2binVector(const string &t_) {
    std::string temp;
    for (auto c : t_) {
        temp += bitset<8>(c).to_string();
    }
    string ret;
    for (int i = 0; i < temp.length(); i = i + 4) {
        string fourbits = temp.substr(i, 4);
        if (fourbits == "0000") {
            ret += "0";
        } else if (fourbits == "0001") {
            ret += "1";
        } else if (fourbits == "0010") {
            ret += "2";
        } else if (fourbits == "0011") {
            ret += "3";
        } else if (fourbits == "0100") {
            ret += "4";
        } else if (fourbits == "0101") {
            ret += "5";
        } else if (fourbits == "0110") {
            ret += "6";
        } else if (fourbits == "0111") {
            ret += "7";
        } else if (fourbits == "1000") {
            ret += "8";
        } else if (fourbits == "1001") {
            ret += "9";
        } else if (fourbits == "1010") {
            ret += "A";
        } else if (fourbits == "1011") {
            ret += "B";
        } else if (fourbits == "1100") {
            ret += "C";
        } else if (fourbits == "1101") {
            ret += "D";
        } else if (fourbits == "1110") {
            ret += "E";
        } else if (fourbits == "1111") {
            ret += "F";
        }
    }

    return ret;
}

//reverse str2binVector
string util::reversestr2binVector(const string &t_) {
    std::string temp;
    for (auto c : t_) {
        if (c == '0') {
            temp += "0000";
        } else if (c == '1') {
            temp += "0001";
        } else if (c == '2') {
            temp += "0010";
        } else if (c == '3') {
            temp += "0011";
        } else if (c == '4') {
            temp += "0100";
        } else if (c == '5') {
            temp += "0101";
        } else if (c == '6') {
            temp += "0110";
        } else if (c == '7') {
            temp += "0111";
        } else if (c == '8') {
            temp += "1000";
        } else if (c == '9') {
            temp += "1001";
        } else if (c == 'A') {
            temp += "1010";
        } else if (c == 'B') {
            temp += "1011";
        } else if (c == 'C') {
            temp += "1100";
        } else if (c == 'D') {
            temp += "1101";
        } else if (c == 'E') {
            temp += "1110";
        } else if (c == 'F') {
            temp += "1111";
        }
    }
    string ret;
    for (int i = 0; i < temp.length(); i = i + 8) {
        string eightbits = temp.substr(i, 8);
        ret += (char) bitset<8>(eightbits).to_ulong();
    }
    return temp;
}

bitset<64> util::reverseBitset(bitset<64> bitset1) {
    bitset<64> bitset2;
    for (int i = 0; i < 64; ++i) {
        bitset2[i] = bitset1[63 - i];
    }
    return bitset2;
}

vector<uint64_t> util::bitstringToVUnit64(const string& bitstring){
    int amoutOfChars = bitstring.size();
    vector<uint64_t> res;//= vector<uint64_t>(0)
    for (int i = 0; i < amoutOfChars; i+=64) {
        res.emplace_back(stoull(bitstring.substr(i,64), nullptr,2));
    }
    return res;
}