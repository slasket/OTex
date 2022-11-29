# Oblivious Transfer extension project

questions for PETERRRR

Is it okay that the initial OT functionality is called as a single method that takes both parties secret input or does it have be split up where both parites are instantiated and then the protocol is called with the parties as input????!?!?!??!

we have a couple of efficiency concerns
    our implementation used most of its time just generating keys for elgamal
make own private key such that the group generation is only done once we need to generate our own private keys

ogen witnesses has to match the witnesses from the gen method

is it fine that we just make the naive protocol(shitty matrix transposistion)
and then compare it to the good one(cache friendly matrix trans position eklundhs)
    answer yes

we could also test
benchmarking
aes 256 as hashfunction

using strings is shooting ourselfs in the foot we need to change that
make matrix with uint64_t where each bit in the int is a part of our bit vector
e.g. 128-bit sec matrix
    [uint64_t, uint64_t;
     128 af de her slamberter
     uint64_t, uint64_t;]
          
møde yikes
december 8th 1330
