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
    OTExtension::OTExtensionProtocol(senderPairs,rcvSelectionBits,symmetricKeySize,elgamalKeysize);
}

int main() {
    //const char *string1 = "1111000101111010011111000101111010011111110001011110100111110001011110100111";
    //Integer a = Integer(string1);
    //cout << a << endl;
    //AESCBC();
    //YtextExtendKey();

    //vector<uint64_t> rcvString = {0,0};
    //OTExtension::OTExtensionProtocol(nullptr, rcvString, 128, 2048);

    //cout << util::reversestr2binVector("FF") << endl;
    //auto xd = util::stringXor(util::reversestr2binVector("FF"), util::reversestr2binVector("AB"));
    //cout << xd << endl;
    //xd = util::stringXor(xd, util::reversestr2binVector("AB"));
    //cout << xd << endl;

    doMExtendedOTs(256,256,128,2048);

    //cout << OTExtension::SHA256HashString("test") << endl;
    //OTExtension::Sender sender(nullptr);
    //OTExtension::Receiver receiver({0,0});
    //InitialOT::BaseOT(2048,128, sender, receiver);
    //timing1Of2OT();

    //sampleEncryption();

    //testGroupParaInit();

    return 0;
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



