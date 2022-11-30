//
// Created by svend on 030, 30-11-2022.
//

#ifndef OTEX_OTEXTENSION_H
#define OTEX_OTEXTENSION_H

#include <string>
#include <utility>

using namespace std;


class OTExtension {

    class Receiver{
        tuple<string,string>* kbitSeeds;
        int* tmatrix;
        string selectionBits;
    public:
        explicit Receiver(string sb){
            selectionBits = std::move(sb);
        };

        //saves kbitSeeds to receiver
        void setKbitSeeds(tuple<string, string>* pTuple){
            kbitSeeds = pTuple;
        }
        int * computeTandUMatricies(int symmetricKeysize, const tuple<string, string> *receiverPairs);

        string* computeResult( tuple<string, string> *yPairs);
    };

    class Sender{
        int* qmatrix;
        tuple<string,string>* senderStrings;
    public:
        explicit Sender(tuple<string,string>* ss){
            senderStrings = ss;
        };
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
