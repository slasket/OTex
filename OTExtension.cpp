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
using namespace std::chrono;

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
        auto firstPart = util::mbitXOR(t, util::randomGenerator(get<1>(receiverPairs[i]), m));
        auto secondPart = util::mbitXOR(firstPart, selectionBits);
        umatrix[i] = secondPart;
    }
    return umatrix;
}

vector<vector<uint64_t>>
OTExtension::Receiver::computeResult(vector<tuple<vector<uint64_t>, vector<uint64_t>>> yPairs, int m) {
    //transpose t matrix
    vector<vector<uint64_t>> tMatrixTransposed = util::transposeMatrix(tmatrix);
    auto result = vector<vector<uint64_t>>(m);
    for (int i = 0; i < m; ++i) {//m might be wrong lol
        int choiceBit = util::findithBit(selectionBits, i);
        //int choiceBit = rcvSelectionBitsBitset[i];
        vector<uint64_t> x;
        if(choiceBit == 0){
            auto hfuck = util::hFunction(i, tMatrixTransposed[i]);
            //x = util::stringXor(get<0>(yPairs[i]), util::reversestr2binVector(hfuck));
            auto hashedResultAsUint = util::bitstringToVUnit64(util::reversestr2binVector(hfuck));
            x = util::mbitXOR(get<0>(yPairs[i]),hashedResultAsUint);
        } else{
            auto hfuck = util::hFunction(i, tMatrixTransposed[i]);
            //x = util::stringXor(get<1>(yPairs[i]), util::reversestr2binVector(hfuck));
            auto hashedResultAsUint = util::bitstringToVUnit64(util::reversestr2binVector(hfuck));
            x = util::mbitXOR(get<1>(yPairs[i]),hashedResultAsUint);
        }
        result[i] = x;
    }
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
        qmatrix[i] = util::mbitXOR(siui, util::randomGenerator(kresults[i], m));
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



vector<tuple<vector<uint64_t>, vector<uint64_t>>> OTExtension::Sender::generateYpairs(int m, int k) {
    auto yPairs = vector<tuple<vector<uint64_t>, vector<uint64_t>>>(m);
    cout << "transposing the qmatrix" << endl;
    auto start = high_resolution_clock::now();
    vector<vector<uint64_t>> transposedQMatrix = util::transposeMatrix(qmatrix);
    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<seconds>(stop - start);
    cout <<"transposing q took "  << duration.count() << " seconds" << endl;
    start = high_resolution_clock::now();

    for (int i = 0; i < m; ++i) {

        auto reversestr2bin= util::reversestr2binVector(util::hFunction(i, transposedQMatrix[i]));
        auto hfuncInts = util::bitstringToVUnit64(reversestr2bin);

        auto sendersuints = get<0>(senderStrings[i]);
        auto y0xor = util::mbitXOR(sendersuints, hfuncInts);
        //string y0 = util::stringXor(str2bitof0senderstring, reversestr2bin);

        //string y0 = util::printBitsetofVectorofUints(y0xor);
        auto y0 = y0xor;

        bitset<64> iniOTbits0(get<0>(initialOTChoiceBits));
        bitset<64> iniOTbits1(get<1>(initialOTChoiceBits));

        //reverse iniOTbits0 and iniOTbits1

        iniOTbits0 = util::reverseBitset(iniOTbits0);
        iniOTbits1 = util::reverseBitset(iniOTbits1);


        vector<uint64_t> initialOTkbits = vector<uint64_t>({iniOTbits1.to_ullong(), iniOTbits0.to_ullong()});

        auto stringUint1 = util::printBitsetofVectorofUints(transposedQMatrix[i]);
        auto stringUint2 = util::printBitsetofVectorofUints(initialOTkbits);

        //stringxor
        //auto qiXORsStringXOR = util::stringXor(stringUint1, stringUint2);
        auto qiXORsStringXOR = util::printBitsetofVectorofUints(util::mbitXOR(transposedQMatrix[i], initialOTkbits));

        //convert first 64 chars of qiXORsStringXOR to bitset
        bitset<64> qiXORsStringXORBitset0(qiXORsStringXOR.substr( 0, 64));
        bitset<64> qiXORsStringXORBitset1(qiXORsStringXOR.substr(64, 64));
        vector<uint64_t> qiXORsStringXORBitset = vector<uint64_t>({qiXORsStringXORBitset0.to_ullong(), qiXORsStringXORBitset1.to_ullong()});

        string x1 = util::printBitsetofVectorofUints(get<1>(senderStrings[i]));
        auto x1Uint = get<1>(senderStrings[i]);





        //string hqXors = util::reversestr2binVector(util::hFunction(i, qiXORsStringXORBitset));
        auto hqXorsUints = util::bitstringToVUnit64(util::reversestr2binVector(util::hFunction(i, qiXORsStringXORBitset)));
        //stringxor
        //string oldy1 = util::stringXor(x1, hqXors);
        string oldy1 =  util::printBitsetofVectorofUints(util::mbitXOR(x1Uint,hqXorsUints));
        auto y1 =  util::mbitXOR(x1Uint,hqXorsUints);

        yPairs[i] = make_tuple(y0, y1);
    }
    stop = high_resolution_clock::now();
    duration = duration_cast<seconds>(stop - start);

    cout <<"looping over y pairs "  << duration.count() << " seconds" << endl;
    return yPairs;
}




vector<vector<uint64_t>>
OTExtension::OTExtensionProtocol(vector<tuple<vector<uint64_t>, vector<uint64_t>>> senderStrings, vector<uint64_t> selectionBits,
                                 int symmetricKeySize, int elgamalkeysize) {
    //Inputs
    auto start = high_resolution_clock::now();
    cout<< "Starting OT Extension Protocol" << endl;
    OTExtension::Sender sender(senderStrings);
    OTExtension::Receiver receiver(selectionBits);

    //initial OT phase
    //cout<< "Starting initial OT phase" << endl;
    auto kresult = InitialOT::BaseOT(elgamalkeysize, symmetricKeySize, sender, receiver);
    cout<< "Initial OT phase finished" << endl;

    //OT extension phase
    cout<< "Starting OT extension phase" << endl;
    int m = selectionBits.size()*64;
    vector<vector<uint64_t>> umatrix = receiver.computeTandUMatricies(symmetricKeySize, m);
    // receiver "sends" umatrix to sender
    cout << "Computing q matrix" << endl;
    sender.computeQMatrix(symmetricKeySize, umatrix, kresult, m);

    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<seconds>(stop - start);
    cout <<"Initial OT and u and q matrix" << duration.count() << " seconds" << endl;
    //sanityCheck(sender, receiver, symmetricKeySize, m);
    cout << "Computing y pairs" << endl;
    start = high_resolution_clock::now();
    vector<tuple<vector<uint64_t>, vector<uint64_t>>> yPairs = sender.generateYpairs(m, symmetricKeySize);
    stop = high_resolution_clock::now();

    duration = duration_cast<seconds>(stop - start);
    cout <<"generate Y pairs took "  << duration.count() << " seconds" << endl;
    // sender "sends" yPairs to receiver
    cout << "Computing result" << endl;
    start = high_resolution_clock::now();
    auto result = receiver.computeResult(yPairs, m);
    stop = high_resolution_clock::now();
    duration = duration_cast<seconds>(stop - start);
    cout <<"compute result took"  << duration.count() << " seconds" << endl;
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
        noteqmatrix[i] = util::mbitXOR(sir, notti);
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
}




