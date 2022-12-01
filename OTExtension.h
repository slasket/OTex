//
// Created by svend on 030, 30-11-2022.
//

#ifndef OTEX_OTEXTENSION_H
#define OTEX_OTEXTENSION_H

#include <string>
#include <utility>

using namespace std;


class OTExtension {
public:
    class Receiver{
        int* tmatrix;
        string selectionBits;
        tuple<tuple<uint64_t, uint64_t>, tuple<uint64_t, uint64_t>>* kpairs;

    public:
        explicit Receiver(string sb){
            selectionBits = std::move(sb);
        };

        void setKpairs(tuple<tuple<uint64_t, uint64_t>, tuple<uint64_t, uint64_t>> *kpairs) {
            Receiver::kpairs = kpairs;
        }
        int * computeTandUMatricies(int symmetricKeysize, const tuple<string, string> *receiverPairs);

        string* computeResult( tuple<string, string> *yPairs);
    };

    class Sender{
        int* qmatrix;
        tuple<string,string>* senderStrings;
        tuple<uint64_t, uint64_t> initialOTChoiceBits;
    public:
        explicit Sender(tuple<string,string>* ss){
            senderStrings = ss;
        };
        void setInitialOTChoiceBits(tuple<uint64_t, uint64_t> initialOTChoiceBits){
            Sender::initialOTChoiceBits = initialOTChoiceBits;
        }
        void computeQMatrix(const int* umatrix, string* kresults, string initalSenderString);
        tuple<string,string>* generateYpairs(string initalSenderString);


        int fuckdig(int si, const int umatrixi);
    };
public:
    static string* OTExtensionProtocol(tuple<string,string>* senderStrings, const string& selectionBits, int k, int elgamalkeysize);
private:
    static int randomGenerator(const string& ki);

    static int hFunction(int i, int i1);
};


#endif //OTEX_OTEXTENSION_H
