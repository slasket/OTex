//
// Created by a on 20/11/2022.
//

#include "InitialOT.h"
#include "elgamal.h"
#include "cryptopp/osrng.h"
#include <bitset>
#include <utility>
#include "OTExtension.h"

using namespace std;


tuple<Integer, Integer,Integer>* InitialOT::Alice::genPKArray(int keySize, Integer mod, Integer g) {
    const tuple<Integer, Integer> &keyValues = elgamal::KeyGen(keySize, mod, g);

    //save private key to alice
    privateKey.Initialize(mod, g, get<1>(keyValues));

    //ElGamal::PublicKey publicKey;
    //publicKey.AssignFrom(privateKey);

    Integer h = get<0>(keyValues);

    tuple<Integer, Integer,Integer> ogenVals = elgamal::OGen(mod, g, keySize);

    auto* pkArr = new tuple<Integer, Integer,Integer>[2];
    if (bitVal == 0){
        pkArr[0] = {mod, g, h};
        pkArr[1] = {get<0>(ogenVals),get<1>(ogenVals) ,get<2>(ogenVals)};

    } else{
        pkArr[0] = {get<0>(ogenVals),get<1>(ogenVals) ,get<2>(ogenVals)};
        pkArr[1] = {mod, g,h};
    }
    return pkArr;
}

tuple<uint64_t, uint64_t> InitialOT::Alice::receiveCipherArr(std::string *cpArr) {
    Integer mod = privateKey.GetGroupParameters().GetModulus();
    Integer g = privateKey.GetGroupParameters().GetGenerator();
    Integer x = privateKey.GetPrivateExponent();

    auto msg = elgamal::Decrypt(cpArr[bitVal], mod, g, x);

    uint64_t highBits = stoull(msg.substr(0, 64), nullptr, 2);
    uint64_t lowBits = stoull(msg.substr(64, 64), nullptr, 2);
    tuple<uint64_t, uint64_t> res = {highBits, lowBits};
    return res;

}

string* InitialOT::Bob::receivePKArray(tuple<Integer, Integer,Integer> *pkArray) {

    auto* cipherArr= new string[2];
    auto highBitsStr0 = bitset<64>(get<0>(str0)).to_string();
    auto lowBitsStr0 = bitset<64>(get<1>(str0)).to_string();
    auto highBitsStr1 = bitset<64>(get<0>(str1)).to_string();
    auto lowBitsStr1 = bitset<64>(get<1>(str1)).to_string();
    string stringToEncrypt0 = highBitsStr0 + lowBitsStr0;
    string stringToEncrypt1 = highBitsStr1 + lowBitsStr1;
    cipherArr[0] = elgamal::Encrypt(stringToEncrypt0, get<0>(pkArray[0]), get<1>(pkArray[0]), get<2>(pkArray[0]));
    cipherArr[1] = elgamal::Encrypt(stringToEncrypt1, get<0>(pkArray[1]), get<1>(pkArray[1]), get<2>(pkArray[1]));

    return cipherArr;
}

tuple<uint64_t, uint64_t> InitialOT::OT1out2(int keySize, const Integer& mod, const Integer& g, int choicebit, const tuple<uint64_t, uint64_t>& string0, const tuple<uint64_t, uint64_t>& string1) {
    Alice alice(choicebit);
    Bob bob(string0, string1);

    auto pkarr = alice.genPKArray(keySize, mod, g);
    string *cipherArr = bob.receivePKArray(pkarr);

    return alice.receiveCipherArr(cipherArr);
}


tuple<uint64_t, uint64_t> InitialOT::GenerateKbitString(int const k) {
    AutoSeededRandomPool prng;
    uint64_t intLowerBits;
    uint64_t intHigherBits;
    if(k < 64){
        cout << "You retard" << endl;
    }
    else {
        string bitString1;
        for(int i = 0; i < 64; i++){
            bitString1 += to_string(prng.GenerateBit());
        }
        if(bitString1.length() != 64) {
            cout << "bitString1 is not 64 bits" << endl;
        }
        intLowerBits = stoull(bitString1, nullptr, 2);
        string bitString2;
        for(int i = 64; i < k; i++) {
            bitString2 += to_string(prng.GenerateBit());
        }
        intHigherBits = stoull(bitString2, nullptr, 2);
    }
    return {intHigherBits, intLowerBits};

}


tuple<uint64_t, uint64_t>* InitialOT::BaseOT(int const elgamalkeysize, int symmetricKeysize, OTExtension::Sender sender, OTExtension::Receiver receiver) {


    //S choose a random string s
    tuple<uint64_t, uint64_t> initialOTChoiceBits = GenerateKbitString(symmetricKeysize);

    //Init group parameters
    auto groupParaKey = elgamal::InitializeGroupParameters(elgamalkeysize);
    Integer mod = groupParaKey.GetGroupParameters().GetModulus();
    Integer g = groupParaKey.GetGroupParameters().GetGenerator();

    //R chooses k pairs of k-bit seeds
    auto* receiverPairs = new tuple<tuple<uint64_t, uint64_t>,tuple<uint64_t, uint64_t>>[symmetricKeysize];
    for (int i = 0; i < symmetricKeysize; ++i) {
        receiverPairs[i] = {GenerateKbitString(symmetricKeysize),GenerateKbitString(symmetricKeysize)};
    }

    //Receiver saves kbitseeds
    //InitialOT::Receiver receiver{};
    //receiver.setKbitSeeds(receiverPairs);

    //kXOTk functionality
    auto* kresults = new tuple<uint64_t, uint64_t> [symmetricKeysize];
    for (int i = 0; i < symmetricKeysize; ++i) {
        int senderChoiceBit = findUIntBit(i, initialOTChoiceBits);

        tuple<uint64_t, uint64_t> receivedKey = OT1out2(elgamalkeysize, mod, g, senderChoiceBit, get<0>(receiverPairs[i]), get<1>(receiverPairs[i]));
        kresults[i] = receivedKey;

        //cout<< receivedString<<endl;
    }
    receiver.setKpairs(receiverPairs);
    sender.setInitialOTChoiceBits(initialOTChoiceBits);
    return kresults;

    //Receiver generates m selection bits called r
    //int r = std::stoi(GenerateKbitString(symmetricKeysize));    //MOVE TO SOMEWHERE ELSE. THIS IS ONLY FOR TESTING
    //int *umatrix = receiver.computeTandUMatricies(symmetricKeysize, receiverPairs, r);

    //Sender computes q matrix
    //InitialOT::Sender sender{};
    //sender.computeQMatrix(umatrix, kresults);

}

int InitialOT::findUIntBit(int idx, const tuple<uint64_t, uint64_t>& uint) {
    if(idx < 64){
        uint64_t leastSignificantBits = get<1>(uint);
        return bitset<64>(leastSignificantBits)[idx];
    }
    else {
        uint64_t mostSignificantBits = get<0>(uint);
        return bitset<64>(mostSignificantBits)[idx-64];
    }
}






