//
// ALICTF 2016
// Debug - 100pts
// the flag doesn't contain alictf,  [a-z0-9]+, first char is c
//

#include <stdio.h>
#define uint32_t unsigned int

void encrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;           // set up 
    uint32_t delta=0x9e3779b9;                     // a key schedule constant 
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   // cache key 
    for (i=0; i < 128; i++) {                      // basic cycle start 
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    }                                              // end cycle
    v[0]=v0; v[1]=v1;
}

void decrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0x1bbcdc80, i;  // set up 
    uint32_t delta=0x61C88647;                     // a key schedule constant
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   // cache key 
    for (i=0; i<128; i++) {                        // basic cycle start 
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum += delta;
    }                                              // end cycle 
    v[0]=v0; v[1]=v1;
}

int main(void)
{
  uint32_t key[] = { 0x112233, 0x44556677, 0x8899AABB, 0xCCDDEEFF };

  /*
  from struct import unpack
  enc = "6CCE26DC25C6B6D8197390ED3BA6C603".decode("hex")
  xored = ''.join([chr(ord(enc[i]) ^ 0x31) for i in range(len(enc))])

  for i in range(0, len(xored), 4):
    print hex(unpack("<L", xored[i:i+4])[0]) # encrypted data
  */

  uint32_t buff1[] = { 0xed17ff5d, 0xe987f714 };
  uint32_t buff2[] = { 0xdca14228, 0x32f7970a };

  decrypt(buff1, key);
  decrypt(buff2, key);

  printf("Flag: %08x%08x%08x%08x\n", buff1[0], buff1[1], buff2[0], buff2[1]);
  
  return 0;
}

