//
// Created by a on 03/12/2022.
//

#ifndef OTEX_UTIL_H
#define OTEX_UTIL_H

#include <string>

using namespace std;

class util {

public:
    static string SHA256HashString(const string& aString);
    static vector<uint64_t> extendKey(const tuple<uint64_t, uint64_t>& key, int m);
    static vector<uint64_t> randomGenerator(tuple<uint64_t, uint64_t> ki, int m);
    static string stringXor(string x, string y);
    static string hFunction(int i, vector<uint64_t> qmatrixi);
    static vector<uint64_t> mbitXOR(vector<uint64_t> pInt, vector<uint64_t> pInt1, int m);
    static vector<vector<uint64_t>> tranposeMatrix(vector<vector<uint64_t>> matrix);
    static int findithBit(vector<uint64_t> ui, int i);
    static tuple<uint64_t, uint64_t> AES128CounterMode(tuple<uint64_t, uint64_t> plaintext);
    static string bin2str(const string &t_);

    static tuple<uint64_t, uint64_t> str2bin(string t_);

    static vector<uint64_t> entryWiseAnd(int si, const vector<uint64_t> &umatrixi, int m);
};


#endif //OTEX_UTIL_H
