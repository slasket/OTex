#include <iostream>
#include <cryptopp/elgamal.h>
#include <bitset>
#include <sstream>
#include "cryptopp/sha.h"
#include "cryptopp/filters.h"
#include "cryptopp/base64.h"
#include "elgamal.h"
#include "cryptopp/nbtheory.h"
#include "InitialOT.h"
#include "OTExtension.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"
#include "cryptopp/modes.h"
#include "util.h"
#include <chrono>

using namespace std::chrono;

void sampleEncryption();

void timing1Of2OT();

void testGroupParaInit();



/*void sampleEncryption() {
    ElGamal::PrivateKey privateKey = elgamal::KeyGen(128);
    ElGamal::PublicKey publicKey;
    publicKey.AssignFrom(privateKey);
    tuple<Integer, Integer, Integer> ogenStuff = elgamal::OGen(privateKey.GetGroupParameters().GetModulus(), 128);
    string c = elgamal::Encrypt("banan",
                                publicKey.GetGroupParameters().GetModulus(),
                                publicKey.GetGroupParameters().GetGenerator(),
                                publicKey.GetPublicElement());
    cout << c << endl;
    string d = elgamal::Decrypt(c,
                                privateKey.GetGroupParameters().GetModulus(),
                                privateKey.GetGroupParameters().GetGenerator(),
                                privateKey.GetPrivateExponent());
    cout << d << endl;
}*/

void AESCBC();

void textExtendKey();

void testFindInt();

void testTransposeMatrix();

/*void InitialOTExample(int keysize, int choiceBit, string string0, string string1){
    InitialOT::Alice alice(choiceBit);
    InitialOT::Bob bob(string0, string1);

    auto pkarr = alice.genPKArray(keysize);
    string* cipherArr = bob.receivePKArray(pkarr);
    cout<< alice.receiveCipherArr(cipherArr)<< endl;
}

void timing1Of2OT() {
    auto begin = chrono::steady_clock::now();
    for (int i = 0; i < 128; ++i) {
        InitialOT::OT1out2(128, 0, "xd", "haha");//cout<< <<endl;
    }
    //cout<< InitialOT::OT1out2(128,1,"xd","haha")<<endl;
    auto end = chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<chrono::nanoseconds>(end - begin);
    printf("Time measured: %.3f seconds.\n", elapsed.count() * 1e-9);

    begin = chrono::steady_clock::now();
    for (int i = 0; i < 256; ++i) {
        InitialOT::OT1out2(256, 0, "xd", "haha");//cout<< <<endl;
    }
    end = chrono::steady_clock::now();
    elapsed = std::chrono::duration_cast<chrono::nanoseconds>(end - begin);
    printf("Time measured: %.3f seconds.\n", elapsed.count() * 1e-9);
}*/

void doMExtendedOTs(int m, int l, int symmetricKeySize, int elgamalKeysize){

    //M is ALWAYS a multiple of 64!!!!
    vector<tuple<string,string>> senderPairs(m);
    vector<uint64_t> rcvSelectionBits(m);
    senderPairs = util::genMPairsOfLbitStrings(m, l);
    rcvSelectionBits = util::genRcvSelectionBits(m);
    auto result = OTExtension::OTExtensionProtocol(senderPairs,rcvSelectionBits,symmetricKeySize,elgamalKeysize);

    //reverse result vector
    //reverse(result.begin(),result.end());
    //convert rcvSelectionBits to bitset
    //string choicebits;
    //int correctcounter = 0;
    //int incorrectcounter = 0;
    //int zeroes = 0;
    //int ones = 0;
    //for (int i = 0; i < m; ++i) {
    //    int choicebit = util::findithBit(rcvSelectionBits,i);
    //    choicebits += to_string(choicebit);
    //    if(choicebit == 0){
    //        if(result[i] == util::str2bitstr(get<0>(senderPairs[i])) ){
    //            //cout<<"res: "<<result[i]<<endl;
    //            //cout<<"par: "<<util::str2bitstr(get<0>(senderPairs[i]))<<endl;
    //            correctcounter++;
    //            zeroes++;
    //        } else {
    //            //cout<<"res: "<<result[i]<<endl;
    //            //cout<<"par: "<<util::str2bitstr(get<0>(senderPairs[i]))<<endl;
    //            incorrectcounter++;
    //        }
    //    }else{
    //        if(result[i] == util::str2bitstr(get<1>(senderPairs[i])) ){
    //            //cout<<"res: "<<result[i]<<endl;
    //            //cout<<"par: "<<util::str2bitstr(get<1>(senderPairs[i]))<<endl;
    //            correctcounter++;
    //            ones++;
    //        } else {
    //            //cout<<"res: "<<result[i]<<endl;
    //            //cout<<"par: "<<util::str2bitstr(get<1>(senderPairs[i]))<<endl;
    //            incorrectcounter++;
    //        }
    //    }
    //}
    //reverse findIntchoicebits
    //string findIntchoicebitsReversed;
    //for (int i = 0; i < findIntchoicebits.length(); ++i) {
    //    findIntchoicebitsReversed += findIntchoicebits[findIntchoicebits.length()-1-i];
    //}
    //cout << "findIn Rev: " << findIntchoicebitsReversed << endl;
    //count where choicebits and findIntchoicebits differ
    //cout << "correct: " << correctcounter << endl;
    //cout << "incorrect: " << incorrectcounter << endl;
    //cout<<"zeroes: "<<zeroes<<endl;
    //cout<<"ones: "<<ones<<endl;
}
void fromVtoKExtendedOTs(int v , int k, int l, int symmetricKeySize, int elgamalKeysize){
    for (int j = v; j <= k; j=j*2) {
        vector<tuple<string,string>> senderPairs(j);
        vector<uint64_t> rcvSelectionBits(j);
        senderPairs = util::genMPairsOfLbitStrings(j, l);
        rcvSelectionBits = util::genRcvSelectionBits(j);

        auto start = high_resolution_clock::now();

        auto result = OTExtension::OTExtensionProtocol(senderPairs,rcvSelectionBits,symmetricKeySize,elgamalKeysize);

        // Get ending timepoint
        auto stop = high_resolution_clock::now();

        // Get duration. Substart timepoints to
        // get duration. To cast it to proper unit
        // use duration cast method
        auto duration = duration_cast<seconds>(stop - start);
        cout << endl;
        cout <<"###OTamount: " << j<<" in "  << duration.count() << " seconds" << endl;
        cout << endl;

    }

}

int main() {

    fromVtoKExtendedOTs(512,1048576,80,128,2048);

    return 0;
}

void testTransposeMatrix() {
    vector<vector<uint64_t>> matrix;
    for (int i = 0; i < 128; ++i) {
        vector<uint64_t> t;
        tuple<uint64_t ,uint64_t > temp = InitialOT::GenerateKbitString(128);
        tuple<uint64_t ,uint64_t > temp2 = InitialOT::GenerateKbitString(128);
        //put tuples into t
        t.push_back(get<0>(temp));
        t.push_back(get<1>(temp));
        t.push_back(get<0>(temp2));
        t.push_back(get<1>(temp2));
        matrix.push_back(t);
    }
    cout << matrix.size() << endl;
    cout << matrix[0].size()*64 << endl;
    vector<vector<uint64_t>> transposedMatrix = util::transposeMatrix(matrix);
    cout << transposedMatrix.size() << endl;
    cout << transposedMatrix[0].size()*64 << endl;

    //get 0th column of matrix
    string ithColumn;
    for (int i = 0; i < matrix.size(); ++i) {
        //get the ith uint64_t of the column
        uint64_t temp = matrix[i][1];
        //convert to bitset
        bitset<64> tempBitset(temp);
        //get the most significant bit of the bitset
        string tempString = to_string(tempBitset[63]);
        //append to ithColumn
        ithColumn += tempString;
    }
    cout << ithColumn << endl;

    //cout transposedMatrix[0][0] as bitset
    string result = bitset<64>(transposedMatrix[64][0]).to_string()+ bitset<64>(transposedMatrix[64][1]).to_string();
    cout << result << endl;

    assert(ithColumn == result);
}

void testFindInt() {
    int m = 256;
    vector<uint64_t> rcvSelectionBits(m);
    rcvSelectionBits = util::genRcvSelectionBits(m);
    //convert rcvSelectionBits to bitset
    string rcvSelectionBitsString;
    for (int i = 0; i < m/64; ++i) {
        rcvSelectionBitsString += bitset<64>(rcvSelectionBits[i]).to_string();
    }
    bitset<256> rcvSelectionBitsBitset(rcvSelectionBitsString);

    cout << rcvSelectionBitsBitset << endl;
    string choicebits;
    string findintchoicebits;
 //   string finduglychoicebits;
    for (int i = 0; i < m; ++i) {
        int choicebit = rcvSelectionBitsBitset[i];
        int findintchoicebit = util::findithBit(rcvSelectionBits, i);
//        int finduglychoicebit = util::findithBitinvectorofuint64_t(rcvSelectionBits, m-1-i);
        choicebits += to_string(choicebit);
        findintchoicebits += to_string(findintchoicebit);
//        finduglychoicebits += to_string(finduglychoicebit);

    }
    cout << "choicebits: " << choicebits << endl;
    cout << "findintcho: " << findintchoicebits << endl;
  //  cout << "finduglych: " << finduglychoicebits << endl;
}

void textExtendKey() {
    tuple<uint64_t, uint64_t> a = InitialOT::GenerateKbitString(128);
    cout << bitset<64>(get<0>(a)) << endl;
    cout << bitset<64>(get<1>(a)) << endl;
    cout << "extended to" << endl;

    int size = 226;
    auto extentedKey = util::extendKey(a, size);
    //cout extendsKey
    for (int i = 0; i < (size+64-1)/64; ++i) {
        bitset<64> x(extentedKey[i]);
        cout << x << endl;
    }
}


void AESCBC() {
    AutoSeededRandomPool prng;
    HexEncoder encoder(new FileSink(cout));

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);

    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    string plain = "CBC Mode Test";
    string cipher, recovered;

    cout << "plain text: " << plain << endl;
    try
    {
        CBC_Mode< AES >::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        StringSource s(plain, true,
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher)
                       ) // StreamTransformationFilter
        ); // StringSource
    }
    catch(const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    cout << "key: ";
    encoder.Put(key, key.size());
    encoder.MessageEnd();
    cout << endl;

    cout << "iv: ";
    encoder.Put(iv, iv.size());
    encoder.MessageEnd();
    cout << endl;

    cout << "cipher text: ";
    encoder.Put((const CryptoPP::byte*)&cipher[0], cipher.size());
    encoder.MessageEnd();
    cout << endl;
}

void testGroupParaInit() {
    auto privateKey = elgamal::InitializeGroupParameters(
            128);

    Integer mod = privateKey.GetGroupParameters().GetModulus();
    Integer g = privateKey.GetGroupParameters().GetGenerator();

    for (int i = 0; i < 10000; ++i) {
        const tuple<Integer, Integer> &keyValues = elgamal::KeyGen(128, mod, g);
        string c = elgamal::Encrypt(("banan" + to_string(i)), mod, g, get<0>(keyValues));
        //cout << c << endl;
        string d = elgamal::Decrypt(c, mod, g, get<1>(keyValues));
        //cout << d << endl;
    }
}



