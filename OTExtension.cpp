//
// Created by svend on 030, 30-11-2022.
//


#include "OTExtension.h"
#include "InitialOT.h"
#include "cryptopp/integer.h"

using namespace std;
using namespace CryptoPP;

int * OTExtension::Receiver::computeTandUMatricies(int symmetricKeysize, const tuple<string, string> *receiverPairs) {
    //Generate t matrix
    tmatrix = new int[symmetricKeysize];
    int* umatrix = new int[symmetricKeysize];
    for (int i = 0; i < symmetricKeysize; ++i) {
        int t = randomGenerator(get<0>(receiverPairs[i]));
        tmatrix[i] = t;

        int u = t ^ randomGenerator(get<1>(receiverPairs[i])) ^ stoi(selectionBits);
        umatrix[i] = u;
    }
    return umatrix;
}

string* OTExtension::Receiver::computeResult(tuple<string, string> *yPairs) {
    auto* result = new string[selectionBits.length()];
    for (int i = 0; i < sizeof(yPairs); ++i) {
        int choiceBit = int(selectionBits[i]-'0');
        int x;
        if(choiceBit == 0){
            x = stoi(get<0>(yPairs[i])) ^ hFunction(i,tmatrix[i]);
        } else{
            x = stoi(get<1>(yPairs[i])) ^ hFunction(i,tmatrix[i]);
        }
        result[i] = std::to_string(x);
    }
    return result;
}



int OTExtension::Sender::fuckdig(int si, const int umatrixi) { //TODO: skal ikke hedde fuckdig
    int* res = new int[sizeof(umatrixi)];
    for (int i = 0; i < sizeof(umatrixi); ++i) {
        int qi = umatrixi; //TODO: convert to bit string and index into it
        res[i] = si & qi;
    }

    return 0;
}

void OTExtension::Sender::computeQMatrix(const int* umatrix, string* kresults, string initalSenderString) {
    int size = sizeof(umatrix);
    qmatrix = new int[size];
    for (int i = 0; i < size; ++i) {
        int si = int(initalSenderString[i]-'0');
        int mellemregning = fuckdig(si , umatrix[i]);
        qmatrix[i] = mellemregning ^ randomGenerator(kresults[i]);
    }
}

int OTExtension::hFunction(int i, int qmatrixi) {
    return 0; //TODO: implement
}

int OTExtension::randomGenerator(const string& ki) {
    return 0; //TODO: implement
}

tuple<string, string>* OTExtension::Sender::generateYpairs(string initalSenderString) {
    int m = sizeof(senderStrings);
    auto* yPairs = new tuple<string,string>[m];
    for (int i = 0; i < m; ++i) {
        cout << "i: " << i << endl;
        int y0 = stoi(get<0>(senderStrings[i])) ^ hFunction(i , qmatrix[i]);
        cout << "y0: " << y0 << endl;
        cout << "qmatrix[i]: " << qmatrix[i] << endl;
        cout << "initialSenderString" << initalSenderString << endl;
        char* string1 = const_cast<char *>(initalSenderString.c_str());
        Integer a = Integer(string1);
        cout << "stoi(initalSenderString): " << a << endl;  //TODO: this string to too big to convert to int for XORing with qmatrix[i]
        auto qiXORs = qmatrix[i] ^ 1;
        cout << "qiXORs: " << qiXORs << endl;
        int y1 = stoi(get<1>(senderStrings[i])) ^ hFunction(i , qiXORs);
        cout << "y1: " << y1 << endl;
        yPairs[i] = make_tuple(to_string(y0), to_string(y1));
    }
    return yPairs;
}

string* OTExtension::OTExtensionProtocol(tuple<string,string>* senderStrings, const string& selectionBits, int k, int elgamalkeysize) {
    //Inputs
    cout<< "Starting OT Extension Protocol" << endl;
    OTExtension::Sender sender(senderStrings);
    OTExtension::Receiver receiver(selectionBits);

    //initial OT phase
    cout<< "Starting initial OT phase" << endl;
    auto kresult = InitialOT::BaseOT(elgamalkeysize, k, sender, receiver);
    cout<< "Initial OT phase finished" << endl;

    ////OT extension phase
    //cout<< "Starting OT extension phase" << endl;
    //int* umatrix = receiver.computeTandUMatricies(k, receiverPairs);
    //// receiver "sends" umatrix to sender
    //cout << "Computing q matrix" << endl;
    //sender.computeQMatrix(umatrix, kresult, initalSenderString);
    //cout << "Computing y pairs" << endl;
    //tuple<string, string> *yPairs = sender.generateYpairs(initalSenderString);
    //// sender "sends" yPairs to receiver
    //cout << "Computing result" << endl;
    //auto result = receiver.computeResult(yPairs);
    return nullptr;
}


