//
// Created by svend on 030, 30-11-2022.
//


#include <sstream>
#include <cryptopp/base64.h>
#include "OTExtension.h"
#include "InitialOT.h"
#include "cryptopp/integer.h"
#include "cryptopp/modes.h"
#include <bitset>

using namespace std;
using namespace CryptoPP;

vector<vector<uint64_t>> OTExtension::Receiver::computeTandUMatricies(int symmetricKeysize, int m) {
    tuple<tuple<uint64_t, uint64_t>, tuple<uint64_t, uint64_t>>* receiverPairs = kpairs;
    //Generate t matrix
    tmatrix = vector<vector<uint64_t>>(symmetricKeysize, vector<uint64_t>((m+64-1)/64));
    vector<vector<uint64_t>> umatrix = vector<vector<uint64_t>>(symmetricKeysize, vector<uint64_t>((m+64-1)/64));
    for (int i = 0; i < symmetricKeysize; ++i) {
        vector<uint64_t> t = randomGenerator(get<0>(receiverPairs[i]), m); //collumn t
        tmatrix[i] = t;

        //int u = t ^ randomGenerator(get<1>(receiverPairs[i])) ^ stoi(selectionBits);
        auto firstPart = mbitXOR(t, randomGenerator(get<1>(receiverPairs[i]), m), m);
        auto secondPart = mbitXOR(firstPart, selectionBits, m);
        umatrix[i] = secondPart;
    }
    return umatrix;
}

vector<string> OTExtension::Receiver::computeResult(vector<tuple<string, string>> yPairs, int m) {
    //transpose t matrix
    vector<vector<uint64_t>> tMatrixTransposed = tranposeMatrix(tmatrix);
    vector<string> result = vector<string>(m);
    for (int i = 0; i < sizeof(yPairs); ++i) {
        int choiceBit = findithBit(selectionBits, i);
        string x;
        if(choiceBit == 0){
            x = stringXor(get<0>(yPairs[i]), hFunction(i, tMatrixTransposed[i]));
        } else{
            x = stringXor(get<1>(yPairs[i]), hFunction(i, tMatrixTransposed[i]));
        }
        result[i] = x;
    }
    return result;
}

vector<uint64_t> OTExtension::mbitXOR(vector<uint64_t> pInt, vector<uint64_t> pInt1, int m) {
    auto res = vector<uint64_t>((m+64-1)/64);
    for (int i = 0; i < (m+64-1)/64; ++i) {
        //Xor two 64 bit uint64_t integers
        res[i] = pInt[i] ^ pInt1[i];
    }
    return res;
}

int OTExtension::findithBit(vector<uint64_t> ui, int i) {
    //find number of blocks
    int block = (i / 64);
    int bit = i % 64;
    uint64_t ithblock = ui[block];
    uint64_t mask = 1 << bit;
    return (ithblock & mask) >> bit;
}

vector<uint64_t> OTExtension::Sender::entryWiseAnd(int si, const vector<uint64_t>& umatrixi, int m) {
    auto res = vector<uint64_t>((m+64-1)/64);
    uint64_t andBit;
    if (si == 0){
        andBit = 0;
    } else{
        andBit = UINT64_MAX;
    }
    for (int i = 0; i < (m+64-1)/64; ++i) {
        auto qi = umatrixi[i];
        //and two 64 bit uint64_t integers
        res[i] = qi & andBit;
    }
    return res;
}

void OTExtension::Sender::computeQMatrix(int symmetricKeysize, vector<vector<uint64_t>> umatrix,
                                         tuple<uint64_t, uint64_t> *kresults, int m) {
    tuple<uint64_t, uint64_t> &initalSenderString = initialOTChoiceBits;
    int k = sizeof(umatrix);
    qmatrix = vector<vector<uint64_t>>(symmetricKeysize, vector<uint64_t>());
    for (int i = 0; i < k; ++i) {
        //int si = int(initalSenderString[i]-'0');
        int si = InitialOT::findUIntBit(i, initalSenderString);
        auto siui = entryWiseAnd(si, umatrix[i], m);
        //qmatrix[i] = siui ^ randomGenerator(kresults[i], 0);
        qmatrix[i] = mbitXOR(siui, randomGenerator(kresults[i], m), m);
    }
}

string OTExtension::hFunction(int i, vector<uint64_t> qmatrixi) {
    //convert qmatrixi to string
    string qmatrixiString = "";
    for (int j = 0; j < qmatrixi.size(); ++j) {
        qmatrixiString += to_string(qmatrixi[j]);
    }
    qmatrixiString = to_string(i) + qmatrixiString;
    //hash qmatrixiString
    string hash = SHA256HashString(qmatrixiString);
    return hash;
}

vector<uint64_t> OTExtension::randomGenerator(tuple<uint64_t, uint64_t> ki, int m) {
    //TODO: make sure the ith block corresponds to the iths least significant block of bits
    return {}; //TODO: implement
}

string OTExtension::stringXor(string x, string y) //taken from https://stackoverflow.com/questions/18830505/bitxor-on-c-strings
{
    std::stringstream ss;

    // works properly only if they have same length!
    for(int i = 0; i < x.length(); i++)
    {
        ss <<  (x.at(i) ^ y.at(i));
    }

    return ss.str();
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
vector<uint64_t> OTExtension::extendKey(const tuple<uint64_t, uint64_t>& key, int m) {
    int size = (m+64-1)/64;
    vector<uint64_t> res = vector<uint64_t>(size);
    int counter = 0;
    for (int i = 0; i < size; i = i + 2) {
        auto keyi = AES128CounterMode(key);
        res[i] = get<0>(keyi);
        res[i+1] = get<1>(keyi);
        if(res[i] == res[i+1]){
            cout << "ERROR: AES128CounterMode returned same key twice" << endl;
        }
        counter++;
    }
    return res;
}


vector<tuple<string, string>> OTExtension::Sender::generateYpairs(int m, int k) {
    vector<tuple<string,string>> yPairs = vector<tuple<string,string>>(m);
    vector<vector<uint64_t>> transposedQMatrix = tranposeMatrix(qmatrix);
    for (int i = 0; i < m; ++i) {
        string y0 = stringXor(get<0>(senderStrings[i]), hFunction(i, transposedQMatrix[i]));
        vector<uint64_t> initialOTkbits = vector<uint64_t>({get<0>(initialOTChoiceBits), get<1>(initialOTChoiceBits)});
        auto qiXORs = mbitXOR(transposedQMatrix[i], initialOTkbits, k);
        string y1 = stringXor(get<1>(senderStrings[i]), hFunction(i, qiXORs));
        yPairs[i] = make_tuple(y0, y1);
    }
    return yPairs;
}

vector<vector<uint64_t>> OTExtension::tranposeMatrix(vector<vector<uint64_t>> matrix) {
    return matrix; //TODO: implement
}

string OTExtension::SHA256HashString(const string& aString){
    string digest;
    SHA256 hash;

    StringSource foo(aString, true,
                               new HashFilter(hash,
                                                        new Base64Encoder (
                                                                new StringSink(digest))));

    return digest;
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

std::string bin2str(std::string t_){
    std::stringstream bStream(t_);
    std::string ret;
    bitset<8> t;
    while(bStream >> t) {
        ret += static_cast<char>(t.to_ulong());
    }
    return ret;
}

tuple<uint64_t, uint64_t> str2bin(std::string t_){
    std::string ret;
    for (char c : t_) {
        ret += bitset<8>(c).to_string();
    }
    return {std::stoull(ret.substr(0, 64), nullptr, 2), std::stoull(ret.substr(64, 64), nullptr, 2)};
}

//AES-128 counter mode encryption
tuple<uint64_t, uint64_t> OTExtension::AES128CounterMode(tuple<uint64_t, uint64_t> plaintext) {
    AutoSeededRandomPool prng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock( key, key.size() );

    CryptoPP::byte ctr[ AES::BLOCKSIZE ];
    prng.GenerateBlock( ctr, sizeof(ctr) );


    //convert plaintext to bitset
    string a0 = bitset<64>(get<0>(plaintext)).to_string();
    string a1 = bitset<64>(get<1>(plaintext)).to_string();

    string a0bin = bin2str(a0);
    string a1bin = bin2str(a1);

    string plain;
    //convert plaintext to string
    plain += a0bin;
    plain += a1bin;
    string cipher, encoded, recovered;

    /*********************************\
    \*********************************/

    try
    {

        CTR_Mode< AES >::Encryption e;
        e.SetKeyWithIV( key, key.size(), ctr );

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher. CTR does not.
        StringSource ss1( plain, true,
                          new StreamTransformationFilter( e,
                                                          new StringSink( cipher )
                          ) // StreamTransformationFilter
        ); // StringSource
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << e.what() << endl;
        exit(1);
    }

    auto result = str2bin(cipher);


    //convert result to bitset
    string result0 = bitset<64>(get<0>(result)).to_string();
    string result1 = bitset<64>(get<1>(result)).to_string();


    return result;
}


