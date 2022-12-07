//
// Created by a on 03/12/2022.
//

#ifndef OTEX_UTIL_H
#define OTEX_UTIL_H

#include <string>
#include <bitset>
#include <random>

using namespace std;

class util {

public:
    static string SHA256HashString(const string& aString);
    static vector<uint64_t> extendKey(const tuple<uint64_t, uint64_t>& key, int m);
    static vector<uint64_t> randomGenerator(tuple<uint64_t, uint64_t> ki, int m);
    static string stringXor(string x, string y);
    static string hFunction(int i, vector<uint64_t> qmatrixi);
    static vector<uint64_t> mbitXOR(vector<uint64_t> &pInt, vector<uint64_t> &pInt1);
    static vector<vector<uint64_t>> transposeMatrix(vector<vector<uint64_t>>& matrix);
    static int findithBit(vector<uint64_t> ui, int i);
    static tuple<uint64_t, uint64_t> AES128CounterMode(tuple<uint64_t, uint64_t> plaintext);
    static string bin2str(const string &t_);

    static tuple<uint64_t, uint64_t> str2bin(string t_);

    static vector<uint64_t> entryWiseAnd(int si, const vector<uint64_t> &umatrixi, int m);
    static vector<tuple<vector<uint64_t>, vector<uint64_t>>> genMPairsOfLbitStrings(int pairs, int strLen);
    static vector<uint64_t> genRcvSelectionBits(int bits);

    static string printBitsetofVectorofUints(vector<uint64_t> uints);

    static string str2bitstr(string t_);

    static string str2binVector(const string &t_);

    static bitset<64> reverseBitset(bitset<64> bitset1);

    static string reversestr2binVector(const string &t_);

    //static int findithBitinvectorofuint64_t(vector<uint64_t> ui, int i);

    //taken from https://www.appsloveworld.com/cplus/100/112/c-efficient-way-to-generate-random-bitset-with-configurable-mean-1s-to-0s-r
    template< size_t size>
    static typename std::bitset<size> random_bitset( double p = 0.5) {

        typename std::bitset<size> bits;
        std::random_device rd;
        std::mt19937 gen( rd());
        std::bernoulli_distribution d( p);

        for( int n = 0; n < size; ++n) {
            bits[ n] = d( gen);
        }

        return bits;
    }

    static vector<uint64_t> bitstringToVUnit64(const string& bitstring);

    static vector<vector<uint64_t>> fastTranspose(vector<vector<uint64_t>> &matrix);
};


#endif //OTEX_UTIL_H
