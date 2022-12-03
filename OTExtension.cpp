//
// Created by svend on 030, 30-11-2022.
//


#include <sstream>
#include "OTExtension.h"
#include "InitialOT.h"
#include "util.h"
#include <bitset>

using namespace std;
using namespace CryptoPP;

vector<vector<uint64_t>> OTExtension::Receiver::computeTandUMatricies(int symmetricKeysize, int m) {
    tuple<tuple<uint64_t, uint64_t>, tuple<uint64_t, uint64_t>>* receiverPairs = kpairs;
    //Generate t matrix
    tmatrix = vector<vector<uint64_t>>(symmetricKeysize, vector<uint64_t>((m+64-1)/64));
    vector<vector<uint64_t>> umatrix = vector<vector<uint64_t>>(symmetricKeysize, vector<uint64_t>((m+64-1)/64));
    for (int i = 0; i < symmetricKeysize; ++i) {
        vector<uint64_t> t = util::randomGenerator(get<0>(receiverPairs[i]), m); //collumn t
        tmatrix[i] = t;

        //int u = t ^ randomGenerator(get<1>(receiverPairs[i])) ^ stoi(selectionBits);
        auto firstPart = util::mbitXOR(t, util::randomGenerator(get<1>(receiverPairs[i]), m), m);
        auto secondPart = util::mbitXOR(firstPart, selectionBits, m);
        umatrix[i] = secondPart;
    }
    return umatrix;
}

vector<string> OTExtension::Receiver::computeResult(vector<tuple<string, string>> yPairs, int m) {
    //transpose t matrix
    vector<vector<uint64_t>> tMatrixTransposed = util::tranposeMatrix(tmatrix);
    vector<string> result = vector<string>(m);
    for (int i = 0; i < m; ++i) {//m might be wrong lol
        int choiceBit = util::findithBit(selectionBits, i);
        string x;
        if(choiceBit == 0){
            x = util::stringXor(get<0>(yPairs[i]), util::hFunction(i, tMatrixTransposed[i]));
        } else{
            x = util::stringXor(get<1>(yPairs[i]), util::hFunction(i, tMatrixTransposed[i]));
        }
        result[i] = x;
    }
    return result;
}

void OTExtension::Sender::computeQMatrix(int symmetricKeysize, vector<vector<uint64_t>> umatrix,
                                         tuple<uint64_t, uint64_t> *kresults, int m) {
    tuple<uint64_t, uint64_t> &initalSenderString = initialOTChoiceBits;
    int k = sizeof(umatrix);
    qmatrix = vector<vector<uint64_t>>(symmetricKeysize, vector<uint64_t>());
    for (int i = 0; i < k; ++i) {
        //int si = int(initalSenderString[i]-'0');
        int si = InitialOT::findUIntBit(i, initalSenderString);
        auto siui = util::entryWiseAnd(si, umatrix[i], m);
        //qmatrix[i] = siui ^ randomGenerator(kresults[i], 0);
        qmatrix[i] = util::mbitXOR(siui, util::randomGenerator(kresults[i], m), m);
    }
}



//Extend 128 bit key to m bit key using AES-128 counter mode
//vector<uint64_t> OTExtension::extendKey(uint64_t key, int m) {
//    int size = (m+64-1)/64;
//    vector<uint64_t> res = vector<uint64_t>(size);
//    uint64_t counter = 0;
//    for (int i = 0; i < size; ++i) {
//        res[i] = AES128CounterMode(key, counter);
//        counter++;
//    }
//    return res;
//}

//Extend 128 bit key to m bit key using AES-128 counter mode



vector<tuple<string, string>> OTExtension::Sender::generateYpairs(int m, int k) {
    vector<tuple<string,string>> yPairs = vector<tuple<string,string>>(m);
    vector<vector<uint64_t>> transposedQMatrix = util::tranposeMatrix(qmatrix);
    for (int i = 0; i < m; ++i) {
        string y0 = util::stringXor(get<0>(senderStrings[i]), util::hFunction(i, transposedQMatrix[i]));
        vector<uint64_t> initialOTkbits = vector<uint64_t>({get<0>(initialOTChoiceBits), get<1>(initialOTChoiceBits)});
        auto qiXORs = util::mbitXOR(transposedQMatrix[i], initialOTkbits, k);
        string y1 = util::stringXor(get<1>(senderStrings[i]), util::hFunction(i, qiXORs));
        yPairs[i] = make_tuple(y0, y1);
    }
    return yPairs;
}




vector<string>
OTExtension::OTExtensionProtocol(tuple<string,string>* senderStrings, vector<uint64_t> selectionBits, int elgamalkeysize, int symmetricKeySize) {
    //Inputs
    cout<< "Starting OT Extension Protocol" << endl;
    OTExtension::Sender sender(senderStrings);
    OTExtension::Receiver receiver(selectionBits);

    //initial OT phase
    cout<< "Starting initial OT phase" << endl;
    auto kresult = InitialOT::BaseOT(elgamalkeysize, symmetricKeySize, sender, receiver);
    cout<< "Initial OT phase finished" << endl;

    //OT extension phase
    cout<< "Starting OT extension phase" << endl;
    int m = sizeof(senderStrings);
    vector<vector<uint64_t>> umatrix = receiver.computeTandUMatricies(symmetricKeySize, m);
    // receiver "sends" umatrix to sender
    cout << "Computing q matrix" << endl;
    sender.computeQMatrix(symmetricKeySize, umatrix, kresult, m);
    cout << "Computing y pairs" << endl;
    vector<tuple<string,string>> yPairs = sender.generateYpairs(m, symmetricKeySize);
    // sender "sends" yPairs to receiver
    cout << "Computing result" << endl;
    auto result = receiver.computeResult(yPairs, m);
    return result;
}




