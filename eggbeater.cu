#include <stdio.h>

const unsigned
    BLOCK_DATA_SIZE = 16,
    BLOCK_SIZE      = 80,

    SESSION_KEY_BYTES = 44,
    SESSION_KEY_WORDS = SESSION_KEY_BYTES / sizeof(unsigned);

__device__ unsigned rotl(const unsigned value, const unsigned shift)
{
    return (value << shift) | (value >> (32 - shift));
}

__device__ unsigned reorder_bytes(const unsigned char* s, const unsigned i, const unsigned end)
{
    unsigned char a = 0, b = 0, c = 0, d = 0;
    // Efficiently handle the possibility that the string buffer does not have four
    // bytes left to reorder.  Any missing bytes default to zero.
    switch (end - i)
    {
        default:
        case 4:
            d = s[i+3];
        case 3:
            c = s[i+2];
        case 2:
            b = s[i+1];
        case 1:
            a = s[i];
        case 0:
            break;
    }
    return (a<<24) | (b<<16) | (c<<8) | d;
}

struct sha1_vector
{
    static const unsigned
        NOTHING_UP_MY_SLEEVE_A = 0x67452301,
        NOTHING_UP_MY_SLEEVE_B = 0xEFCDAB89,
        NOTHING_UP_MY_SLEEVE_C = 0x98BADCFE,
        NOTHING_UP_MY_SLEEVE_D = 0x10325476,
        NOTHING_UP_MY_SLEEVE_E = 0xC3D2E1F0,

        ROUND_1_MAGIC = 0x5A827999,
        ROUND_2_MAGIC = 0x6ED9EBA1,
        ROUND_3_MAGIC = 0x8F1BBCDC,
        ROUND_4_MAGIC = 0xCA62C1D6;

    __device__ sha1_vector() :
        a(NOTHING_UP_MY_SLEEVE_A),
        b(NOTHING_UP_MY_SLEEVE_B),
        c(NOTHING_UP_MY_SLEEVE_C),
        d(NOTHING_UP_MY_SLEEVE_D),
        e(NOTHING_UP_MY_SLEEVE_E)
    {}

    __device__ sha1_vector(const sha1_vector& rhs) :
        a(rhs.a),
        b(rhs.b),
        c(rhs.c),
        d(rhs.d),
        e(rhs.e)
    {}

    __device__ unsigned round_1_f() const { return (b&c)|((~b)&d); }
    __device__ unsigned round_2_f() const { return b^c^d; }
    __device__ unsigned round_3_f() const { return (b&c)|(b&d)|(c&d); }
    __device__ unsigned round_4_f() const { return b^c^d; }

    __device__ void compute(const unsigned* message, const unsigned start, const unsigned end)
    {
        for (unsigned i = start; i < min(20, end); ++i)
        {
            compress(round_1_f(), ROUND_1_MAGIC, message[i]);
        }

        for (unsigned i = max(20, start); i < min(40, end); ++i)
        {
            compress(round_2_f(), ROUND_2_MAGIC, message[i]);
        }

        for (unsigned i = max(40, start); i < min(60, end); ++i)
        {
            compress(round_3_f(), ROUND_3_MAGIC, message[i]);
        }

        for (unsigned i = max(60, start); i < min(80, end); ++i)
        {
            compress(round_4_f(), ROUND_4_MAGIC, message[i]);
        }
    }

    __device__ void compress(const unsigned F, const unsigned k, const unsigned w)
    {
        unsigned temp = rotl(a, 5) + F + e + k + w;
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = temp;
    }

    __device__ void finalize()
    {
        a += NOTHING_UP_MY_SLEEVE_A;
        b += NOTHING_UP_MY_SLEEVE_B;
        c += NOTHING_UP_MY_SLEEVE_C;
        d += NOTHING_UP_MY_SLEEVE_D;
        e += NOTHING_UP_MY_SLEEVE_E;
    }

    __device__ bool compare(const unsigned* meebo_digest) const
    {
        // Note that the meebo digest only has 14 bytes of significant
        // values (6 bytes less than a full SHA-1 hash).
        return
            a == meebo_digest[0] &&
            b == meebo_digest[1] &&
            c == meebo_digest[2] &&
            (d & 0xffff0000) == (meebo_digest[3] & 0xffff0000);
    }

    __device__ void print() const
    {
        printf("%08x%08x%08x%08x%08x\n", a, b, c, d, e);
    }

    unsigned a, b, c, d, e;
};

struct sha1_partial_state
{
    // The initial part of the SHA-1 hash calculation, for the session key,
    // will always have the same partial result.  This function calculates it
    // and stores it so that it can be cached and reused.
    __device__ sha1_partial_state(const unsigned char *session_key)
    {
        for (unsigned i = 0; i < SESSION_KEY_WORDS; ++i)
        {
            consumed[i] =
                reorder_bytes(session_key, i * sizeof(unsigned), SESSION_KEY_BYTES);
        }

        v.compute(consumed, 0, SESSION_KEY_WORDS);
    }

    sha1_vector v;

    unsigned consumed[SESSION_KEY_WORDS];
};

// NOTE: This only supports base36 numbers with 9 digits or less.
//       Also, 's' must have enough room for the 9 digits.
__device__ unsigned ultoa36(unsigned long value, unsigned char* s)
{
    const unsigned char* base36 = "abcdefghijklmnopqrstuvwxyz0123456789";
    unsigned long base = 101559956668416; // 36 ^ 9
    bool leading_zeros = true;
    unsigned char* next = s;

    if (!value)
    {
        *next++ = base36[0];
    }
    else
    {
        while (base)
        {
            unsigned long r = value / base;
            if (r)
            {
                leading_zeros = false;
                *next++ = base36[r];
                value %= base;
            }
            else if (!leading_zeros)
            {
                *next++ = base36[r];
            }
            base /= 36;
        }
    }

    return next - s;
}

__device__ bool try_secret(
    const sha1_partial_state* precalculated_state,
    const unsigned long secret_number,
    const unsigned* meebo_digest)
{
    unsigned char append[10];
    const unsigned secret_len = ultoa36(secret_number, append);
    const unsigned append_len = secret_len + 1;
    // Add the terminating '1' bit.
    append[secret_len] = 0x80;

    if (sizeof(append) < append_len)
    {
        printf("WARNING: static append buffer is too small.\n");
        return false;
    }

    unsigned block[BLOCK_SIZE];
    unsigned* next = block;

#pragma unroll
    for (unsigned i = 0; i < SESSION_KEY_WORDS; ++i)
    {
        *next++ = precalculated_state->consumed[i];
    }

    for (unsigned i = 0; i < append_len; i += sizeof(unsigned))
    {
        *next++ = reorder_bytes(append, i, append_len);
    }

    while (next != &block[BLOCK_DATA_SIZE - 1])
    {
        *next++ = 0;
    }

    // Append the length (in bits) to the end of the message.  In reality,
    // this is a 64 bit integer, but we'll never need the upper 32 bits.
    block[BLOCK_DATA_SIZE - 1] = 32 * SESSION_KEY_WORDS + 8 * secret_len;

    // Extend the initial block contents into a full block.
#pragma unroll
    for (unsigned i = BLOCK_DATA_SIZE; i < BLOCK_SIZE; ++i)
    {
        block[i] = block[i-3] ^ block[i-8] ^ block[i-14] ^ block[i-16];
        block[i] = rotl(block[i], 1);
    }

    sha1_vector v(precalculated_state->v);
    v.compute(block, SESSION_KEY_WORDS, 80); 
    v.finalize();
    if (v.compare(meebo_digest))
    {
        append[secret_len] = 0;
        printf("Key found: %s: ", append);
        v.print();
        return true;
    }

    return false;
}

__global__ void precalculate(
    const unsigned char* session_key,
    sha1_partial_state* precalculated_state)
{
    *precalculated_state = sha1_partial_state(session_key);
}

__global__ void crack(
    const sha1_partial_state* precalculated_state,
    const unsigned* meebo_digest,
    const unsigned long* secret_number_base,
    unsigned* key_found)
{
    const unsigned long secret_number =
        *secret_number_base + blockIdx.x * blockDim.x + threadIdx.x;

    if (try_secret(precalculated_state, secret_number, meebo_digest))
    {
        *key_found = 1;
    }
}
