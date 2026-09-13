// SHA-256 and HMAC-SHA256.
//
// Vendored rather than linked because a Metamod plugin has to load into a 32-bit HLDS
// process on whatever distribution the game server happens to run, and adding an OpenSSL
// dependency to that is a much larger portability problem than 150 lines of hashing.
//
// This is used for one thing: signing the telemetry body so the backend can reject events
// that did not come from a server holding the shared secret.

#include <stdint.h>
#include <string.h>
#include <string>

namespace {

struct Sha256Ctx
{
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  data[64];
    uint32_t datalen;
};

const uint32_t K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

inline uint32_t Rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

void Transform(Sha256Ctx* c, const uint8_t* d)
{
    uint32_t m[64], a, b, cc, dd, e, f, g, h, t1, t2;
    for (int i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)d[j] << 24) | ((uint32_t)d[j+1] << 16) | ((uint32_t)d[j+2] << 8) | d[j+3];
    for (int i = 16; i < 64; ++i)
    {
        uint32_t s0 = Rotr(m[i-15], 7) ^ Rotr(m[i-15], 18) ^ (m[i-15] >> 3);
        uint32_t s1 = Rotr(m[i-2], 17) ^ Rotr(m[i-2], 19)  ^ (m[i-2] >> 10);
        m[i] = m[i-16] + s0 + m[i-7] + s1;
    }

    a=c->state[0]; b=c->state[1]; cc=c->state[2]; dd=c->state[3];
    e=c->state[4]; f=c->state[5]; g=c->state[6];  h=c->state[7];

    for (int i = 0; i < 64; ++i)
    {
        uint32_t S1 = Rotr(e,6) ^ Rotr(e,11) ^ Rotr(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + K[i] + m[i];
        uint32_t S0 = Rotr(a,2) ^ Rotr(a,13) ^ Rotr(a,22);
        uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);
        t2 = S0 + mj;
        h=g; g=f; f=e; e=dd+t1; dd=cc; cc=b; b=a; a=t1+t2;
    }

    c->state[0]+=a; c->state[1]+=b; c->state[2]+=cc; c->state[3]+=dd;
    c->state[4]+=e; c->state[5]+=f; c->state[6]+=g;  c->state[7]+=h;
}

void Init(Sha256Ctx* c)
{
    c->datalen = 0; c->bitlen = 0;
    c->state[0]=0x6a09e667u; c->state[1]=0xbb67ae85u; c->state[2]=0x3c6ef372u; c->state[3]=0xa54ff53au;
    c->state[4]=0x510e527fu; c->state[5]=0x9b05688cu; c->state[6]=0x1f83d9abu; c->state[7]=0x5be0cd19u;
}

void Update(Sha256Ctx* c, const uint8_t* data, size_t len)
{
    for (size_t i = 0; i < len; ++i)
    {
        c->data[c->datalen++] = data[i];
        if (c->datalen == 64) { Transform(c, c->data); c->bitlen += 512; c->datalen = 0; }
    }
}

void Final(Sha256Ctx* c, uint8_t* out)
{
    uint32_t i = c->datalen;
    if (c->datalen < 56)
    {
        c->data[i++] = 0x80;
        while (i < 56) c->data[i++] = 0x00;
    }
    else
    {
        c->data[i++] = 0x80;
        while (i < 64) c->data[i++] = 0x00;
        Transform(c, c->data);
        memset(c->data, 0, 56);
    }

    c->bitlen += (uint64_t)c->datalen * 8;
    for (int k = 0; k < 8; ++k) c->data[63 - k] = (uint8_t)(c->bitlen >> (8 * k));
    Transform(c, c->data);

    for (int k = 0; k < 4; ++k)
        for (int j = 0; j < 8; ++j)
            out[k + j * 4] = (uint8_t)((c->state[j] >> (24 - k * 8)) & 0xff);
}

void Raw(const uint8_t* data, size_t len, uint8_t* out32)
{
    Sha256Ctx c; Init(&c); Update(&c, data, len); Final(&c, out32);
}

} // namespace

std::string AcsHmacSha256Hex(const std::string& key, const std::string& data)
{
    uint8_t k[64];
    memset(k, 0, sizeof(k));
    if (key.size() > 64)
        Raw((const uint8_t*)key.data(), key.size(), k);
    else
        memcpy(k, key.data(), key.size());

    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }

    uint8_t inner[32];
    { Sha256Ctx c; Init(&c); Update(&c, ipad, 64);
      Update(&c, (const uint8_t*)data.data(), data.size()); Final(&c, inner); }

    uint8_t mac[32];
    { Sha256Ctx c; Init(&c); Update(&c, opad, 64); Update(&c, inner, 32); Final(&c, mac); }

    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (int i = 0; i < 32; ++i) { out += hex[mac[i] >> 4]; out += hex[mac[i] & 0x0f]; }
    return out;
}
