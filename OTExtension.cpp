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
    vector<tuple<tuple<uint64_t, uint64_t>, tuple<uint64_t, uint64_t>>> receiverPairs = kpairs;
    //Generate t matrix
    tmatrix = vector<vector<uint64_t>>(symmetricKeysize, vector<uint64_t>((m+64-1)/64));
    vector<vector<uint64_t>> umatrix = vector<vector<uint64_t>>(symmetricKeysize, vector<uint64_t>((m+64-1)/64));
    for (int i = 0; i < symmetricKeysize; ++i) {
        auto currentpair=  receiverPairs[i];
        auto ki = get<0>(currentpair);
        vector<uint64_t> t = util::randomGenerator(ki, m); //collumn t
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
    vector<vector<uint64_t>> tMatrixTransposed = util::transposeMatrix(tmatrix);
    vector<string> result = vector<string>(m);
    string choicebits;
    for (int i = 0; i < m; ++i) {//m might be wrong lol
        int choiceBit = util::findithBit(selectionBits, i);
        //int choiceBit = rcvSelectionBitsBitset[i];
        choicebits += to_string(choiceBit);
        string x;
        if(choiceBit == 0){
            auto hfuck = util::hFunction(i, tMatrixTransposed[i]);
            x = util::stringXor(get<0>(yPairs[i]), util::reversestr2binVector(hfuck));
        } else{
            auto hfuck = util::hFunction(i, tMatrixTransposed[i]);
            x = util::stringXor(get<1>(yPairs[i]), util::reversestr2binVector(hfuck));
        }
        result[i] = x;
    }

    cout << "choicebits: " << choicebits << endl;
    return result;
}

void OTExtension::Sender::computeQMatrix(int symmetricKeysize, vector<vector<uint64_t>> umatrix,
                                         tuple<uint64_t, uint64_t> *kresults, int m) {
    tuple<uint64_t, uint64_t> &initalSenderString = initialOTChoiceBits;
    int k = umatrix.size();
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



vector<tuple<string, string>> OTExtension::Sender::generateYpairs(int m, int k, Receiver receiver) {
    vector<tuple<string,string>> yPairs = vector<tuple<string,string>>(m);
    vector<vector<uint64_t>> transposedQMatrix = util::transposeMatrix(qmatrix);
    auto transposedTMatrix = util::transposeMatrix(receiver.tmatrix);
    int counter = 0;
    for (int i = 0; i < m; ++i) {
        string y0 = util::stringXor(util::str2bitstr(get<0>(senderStrings[i])), util::reversestr2binVector(util::hFunction(i, transposedQMatrix[i])));
        vector<uint64_t> initialOTkbits = vector<uint64_t>({get<0>(initialOTChoiceBits), get<1>(initialOTChoiceBits)});
        cout << "initialOTkbits   " << util::printBitsetofVectorofUints(initialOTkbits) << endl;
        cout << "transposedTMatrix" << util::printBitsetofVectorofUints(transposedTMatrix[i]) << endl;
        auto qiXORs = util::mbitXOR(transposedQMatrix[i], initialOTkbits, k);
        auto qiXORsStringXOR = util::stringXor(util::printBitsetofVectorofUints(initialOTkbits), util::printBitsetofVectorofUints(transposedTMatrix[i]));
        cout << "qiXORs           " << util::printBitsetofVectorofUints(qiXORs) << endl;
        cout << "qiXORsStringXOR  " << qiXORsStringXOR << endl;
        //convert first 64 chars of qiXORsStringXOR to bitset
        bitset<64> qiXORsStringXORBitset0(qiXORsStringXOR.substr( 0, 64));
        bitset<64> qiXORsStringXORBitset1(qiXORsStringXOR.substr(64, 64));
        vector<uint64_t> qiXORsStringXORBitset = vector<uint64_t>({qiXORsStringXORBitset0.to_ullong(), qiXORsStringXORBitset1.to_ullong()});
        string x1 = util::str2bitstr(get<1>(senderStrings[i]));
        string hqXors = util::reversestr2binVector(util::hFunction(i, qiXORsStringXORBitset));
        string y1 = util::stringXor(x1, hqXors);
        string sanityy1 = util::stringXor(y1, util::reversestr2binVector(util::hFunction(i, transposedTMatrix[i])));
        if(sanityy1 != x1){
            cout << "y1 sanity check failed" << endl;
            cout << "y1:          " << y1 << endl;
            cout << "y1 sanity:   " << sanityy1 << endl;
            cout << "y1 original: " << util::str2bitstr(get<1>(senderStrings[i])) << endl;
            counter++;
        }
        yPairs[i] = make_tuple(y0, y1);
    }
    if(counter > 0){
        cout << "y1 sanity check failed " << counter << " times" << endl;
    }
    return yPairs;
}




vector<string>
OTExtension::OTExtensionProtocol(vector<tuple<string, string>> senderStrings, vector<uint64_t> selectionBits,
                                 int symmetricKeySize, int elgamalkeysize) {
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
    int m = selectionBits.size()*64;
    vector<vector<uint64_t>> umatrix = receiver.computeTandUMatricies(symmetricKeySize, m);
    // receiver "sends" umatrix to sender
    cout << "Computing q matrix" << endl;
    sender.computeQMatrix(symmetricKeySize, umatrix, kresult, m);
    sanityCheck(sender, receiver, symmetricKeySize, m);
    cout << "Computing y pairs" << endl;
    vector<tuple<string,string>> yPairs = sender.generateYpairs(m, symmetricKeySize, receiver);
    // sender "sends" yPairs to receiver
    cout << "Computing result" << endl;
    auto result = receiver.computeResult(yPairs, m);
    return result;
}

void OTExtension::sanityCheck(OTExtension::Sender sender, OTExtension::Receiver receiver, int size, int m) {
    auto kpairs = receiver.kpairs;
    auto qmatrix = sender.qmatrix;
    auto tmatrix = receiver.tmatrix;
    auto initalSenderString = sender.initialOTChoiceBits;
    auto noteqmatrix = vector<vector<uint64_t>>(size, vector<uint64_t>());
    int correctcounter = 0;
    int zeroes = 0;
    int ones = 0;
    for (int i = 0; i < size; ++i) {
        int si = InitialOT::findUIntBit(i, initalSenderString);
        int notsi = 1- si;
        //qmatrix[i] = siui ^ randomGenerator(kresults[i], 0);
        vector<uint64_t> notti;
        if (notsi == 0){
            notti = util::randomGenerator(get<0>(kpairs[i]), m);
        } else{
            notti = util::randomGenerator(get<0>(kpairs[i]), m);
        }
        auto sir = util::entryWiseAnd(si, receiver.selectionBits, m);
        noteqmatrix[i] = util::mbitXOR(sir, notti, m);
        if(noteqmatrix[i] == sender.qmatrix[i]){
            //cout << "qmatrix sanity check passed" << endl;
            correctcounter++;
            if (si == 0){
                zeroes++;
            } else{
                ones++;
            }
        } else{
            cout << "qmatrix sanity check failed" << endl;
            //convert sender.qmatrix[i] to bitset
            cout << "sender.qmatrix[i]" << endl;
            for (int j = 0; j < m/64; ++j) {
                cout << bitset<64>(sender.qmatrix[i][j]);
            }
            cout << endl;
            cout << "noteqmatrix[i]" << endl;
            for (int j = 0; j < m/64; ++j) {
                cout << bitset<64>(noteqmatrix[i][j]);
            }
            cout << endl;
        }
    }
    cout << "correctcounter: " << correctcounter << endl;
    cout << "zeroes: " << zeroes << endl;
    cout << "ones: " << ones << endl;
}




