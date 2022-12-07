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
    for (int i = 0; i < m; ++i) {//m might be wrong lol
        int choiceBit = util::findithBit(selectionBits, i);
        //int choiceBit = rcvSelectionBitsBitset[i];
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



vector<tuple<string, string>> OTExtension::Sender::generateYpairs(int m, int k) {
    vector<tuple<string,string>> yPairs = vector<tuple<string,string>>(m);
    cout << "transposing the qmatrix" << endl;
    auto start = high_resolution_clock::now();
    vector<vector<uint64_t>> transposedQMatrix = util::transposeMatrix(qmatrix);
    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<seconds>(stop - start);
    cout <<"transposing q took "  << duration.count() << " seconds" << endl;
    start = high_resolution_clock::now();

    int stringXor = 0;
    int str2bitstr =0;
    int reversestr2binVector=0;
    int reverseBitset =0;
    int printBitsetofVectorofUints =0;
    for (int i = 0; i < m; ++i) {
        //if (i %10000==0){cout << "ith iteration of loop: "<< i << endl;}

        auto hfuncOut1 = util::hFunction(i, transposedQMatrix[i]);


        auto startstr2bit = high_resolution_clock::now();
        auto str2bitof0senderstring =util::str2bitstr(get<0>(senderStrings[i]));
        auto stopstr2bit = high_resolution_clock::now();
        str2bitstr = str2bitstr +  duration_cast<seconds>(stopstr2bit - startstr2bit).count();

        auto starreversestr2bin = high_resolution_clock::now();
        auto reversestr2bin= util::reversestr2binVector(hfuncOut1);
        auto stopreversestr2bin = high_resolution_clock::now();
        reversestr2binVector = reversestr2binVector +  duration_cast<seconds>(stopreversestr2bin - starreversestr2bin).count();


        //hfunctime = hfunctime +  duration_cast<seconds>(stop - start).count();
        auto startstringxor = high_resolution_clock::now();
        string y0 = util::stringXor(str2bitof0senderstring, reversestr2bin);
        auto stopstringxor = high_resolution_clock::now();
        stringXor = stringXor + duration_cast<seconds>(stopstringxor - startstringxor).count();

        bitset<64> iniOTbits0(get<0>(initialOTChoiceBits));
        bitset<64> iniOTbits1(get<1>(initialOTChoiceBits));

        //reverse iniOTbits0 and iniOTbits1
        auto startrevbitset = high_resolution_clock::now();
        iniOTbits0 = util::reverseBitset(iniOTbits0);
        iniOTbits1 = util::reverseBitset(iniOTbits1);
        auto stoprevbitset = high_resolution_clock::now();
        reverseBitset = reverseBitset + duration_cast<seconds>(stoprevbitset - startrevbitset).count();

        vector<uint64_t> initialOTkbits = vector<uint64_t>({iniOTbits1.to_ullong(), iniOTbits0.to_ullong()});
        auto startstrinUint = high_resolution_clock::now();
        auto stringUint1 = util::printBitsetofVectorofUints(transposedQMatrix[i]);
        auto stringUint2 = util::printBitsetofVectorofUints(initialOTkbits);
        auto stopstringUint = high_resolution_clock::now();
        printBitsetofVectorofUints = printBitsetofVectorofUints + duration_cast<seconds>(stopstringUint - startstrinUint).count();

        startstringxor = high_resolution_clock::now();
        auto qiXORsStringXOR = util::stringXor(stringUint1, stringUint2);
        stopstringxor = high_resolution_clock::now();
        stringXor = stringXor + duration_cast<seconds>(stopstringxor - startstringxor).count();

        //convert first 64 chars of qiXORsStringXOR to bitset
        bitset<64> qiXORsStringXORBitset0(qiXORsStringXOR.substr( 0, 64));
        bitset<64> qiXORsStringXORBitset1(qiXORsStringXOR.substr(64, 64));
        vector<uint64_t> qiXORsStringXORBitset = vector<uint64_t>({qiXORsStringXORBitset0.to_ullong(), qiXORsStringXORBitset1.to_ullong()});
        startstr2bit = high_resolution_clock::now();
        string x1 = util::str2bitstr(get<1>(senderStrings[i]));
        stopstr2bit = high_resolution_clock::now();
        str2bitstr = str2bitstr +  duration_cast<seconds>(stopstr2bit - startstr2bit).count();

        auto hfuncOut2 = util::hFunction(i, qiXORsStringXORBitset);

        starreversestr2bin = high_resolution_clock::now();
        string hqXors = util::reversestr2binVector(hfuncOut2);
        stopreversestr2bin = high_resolution_clock::now();
        reversestr2binVector = reversestr2binVector +  duration_cast<seconds>(stopreversestr2bin - starreversestr2bin).count();

        startstringxor = high_resolution_clock::now();
        string y1 = util::stringXor(x1, hqXors);
        stopstringxor = high_resolution_clock::now();
        stringXor = stringXor + duration_cast<seconds>(stopstringxor - startstringxor).count();
        yPairs[i] = make_tuple(y0, y1);
    }
    stop = high_resolution_clock::now();
    duration = duration_cast<seconds>(stop - start);
    cout << "stringXor time " << stringXor << "seconds" <<endl;
    cout << "str2bitstr time " << str2bitstr << "seconds" <<endl;
    cout << "reversestr2binVector time " << reversestr2binVector << "seconds" <<endl;
    cout << "reverseBitset time " << reverseBitset << "seconds" <<endl;
    cout << "printBitsetofVectorofUints time " << printBitsetofVectorofUints << "seconds" <<endl;

    cout <<"looping over y pairs "  << duration.count() << " seconds" << endl;
    return yPairs;
}




vector<string>
OTExtension::OTExtensionProtocol(vector<tuple<string, string>> senderStrings, vector<uint64_t> selectionBits,
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
    vector<tuple<string,string>> yPairs = sender.generateYpairs(m, symmetricKeySize);
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
}




