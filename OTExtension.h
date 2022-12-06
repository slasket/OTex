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

    public:
        vector<tuple<tuple<uint64_t, uint64_t>, tuple<uint64_t, uint64_t>>> kpairs;
        vector<vector<uint64_t>> tmatrix;
        vector<uint64_t> selectionBits;
        explicit Receiver(vector<uint64_t> sb){
            selectionBits = sb;
        };

        void setKpairs(vector<tuple<tuple<uint64_t, uint64_t>, tuple<uint64_t, uint64_t>>> chosenRandPairs) {
            Receiver::kpairs = std::move(chosenRandPairs);
        }
        vector<vector<uint64_t>> computeTandUMatricies(int symmetricKeysize, int m);

        vector<string> computeResult(vector<tuple<string, string>> yPairs, int m);

    };

    class Sender{
        vector<tuple<string,string>> senderStrings;
    public:
        vector<vector<uint64_t>> qmatrix;
        tuple<uint64_t, uint64_t> initialOTChoiceBits;
        explicit Sender(vector<tuple<string,string>> ss){
            senderStrings = ss;
        };
        void setInitialOTChoiceBits(tuple<uint64_t, uint64_t> initialOTChoiceBits){
            Sender::initialOTChoiceBits = initialOTChoiceBits;
        }
        void computeQMatrix(int symmetricKeysize, vector<vector<uint64_t>> umatrix,
                            tuple<uint64_t, uint64_t> *kresults, int m);
        vector<tuple<string, string>> generateYpairs(int m, int k);


    };
public:
    static vector<string> OTExtensionProtocol(vector<tuple<string, string>> senderStrings, vector<uint64_t> selectionBits,
                                              int symmetricKeySize, int elgamalkeysize);

    static void sanityCheck(Sender sender, Receiver receiver, int size, int m);
};


#endif //OTEX_OTEXTENSION_H
