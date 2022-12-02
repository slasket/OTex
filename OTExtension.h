//
// Created by svend on 030, 30-11-2022.
//

#ifndef OTEX_OTEXTENSION_H
#define OTEX_OTEXTENSION_H

#include <string>
#include <utility>
#include <iostream>
#include <vector>

using namespace std;


class OTExtension {
public:
    class Receiver{
        vector<vector<uint64_t>> tmatrix;
        vector<uint64_t> selectionBits;
        tuple<tuple<uint64_t, uint64_t>, tuple<uint64_t, uint64_t>>* kpairs;

    public:
        explicit Receiver(vector<uint64_t> sb){
            selectionBits = sb;
        };

        void setKpairs(tuple<tuple<uint64_t, uint64_t>, tuple<uint64_t, uint64_t>> *kpairs) {
            Receiver::kpairs = kpairs;
        }
        vector<vector<uint64_t>> computeTandUMatricies(int symmetricKeysize, int m);

        vector<string> computeResult(vector<tuple<string, string>> yPairs, int m);

    };

    class Sender{
        vector<vector<uint64_t>> qmatrix;
        tuple<string,string>* senderStrings;
        tuple<uint64_t, uint64_t> initialOTChoiceBits;
    public:
        explicit Sender(tuple<string,string>* ss){
            senderStrings = ss;
        };
        void setInitialOTChoiceBits(tuple<uint64_t, uint64_t> initialOTChoiceBits){
            Sender::initialOTChoiceBits = initialOTChoiceBits;
        }
        void computeQMatrix(int symmetricKeysize, vector<vector<uint64_t>> umatrix,
                            tuple<uint64_t, uint64_t> *kresults, int m);
        vector<tuple<string, string>> generateYpairs(int m, int k);


        vector<uint64_t> entryWiseAnd(int si, const vector<uint64_t>& umatrixi, int m);


    };
public:
    static vector<string>
    OTExtensionProtocol(tuple<string,string>* senderStrings, vector<uint64_t> selectionBits, int elgamalkeysize, int symmetricKeySize);
    static string SHA256HashString(const string& aString);
    static vector<uint64_t> extendKey(const tuple<uint64_t, uint64_t>& key, int m);
private:
    static vector<uint64_t> randomGenerator(tuple<uint64_t, uint64_t> ki, int m);

    static string stringXor(std::string x, std::string y);

    static string hFunction(int i, vector<uint64_t> qmatrixi);

    static vector<uint64_t> mbitXOR(vector<uint64_t> pInt, vector<uint64_t> pInt1, int m);

    static vector<vector<uint64_t>> tranposeMatrix(vector<vector<uint64_t>> matrix);

    static int findithBit(vector<uint64_t> ui, int i);


    static tuple<uint64_t, uint64_t> AES128CounterMode(tuple<uint64_t, uint64_t> plaintext);
};


#endif //OTEX_OTEXTENSION_H
