/*
 * Copyright (c) 2015 Tim Ruffing <tim.ruffing@mmci.uni-saarland.de>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include "chameleonhash.h"

#include <vector>
#include <algorithm>

void ChameleonHash::initialize()
{
    // the following two initialization functions
    // ensure already by themselves that they do their work only once
    secp256k1_ecmult_gen_start();
    secp256k1_ecmult_start();
}


ChameleonHash::ChameleonHash(const pk_t& pk, const W& w) : hasSecretKey_(false)
{
    secp256k1_ge_t pkge;

    initialize();

    // secp256k1_eckey_pubkey_parse makes sure that the public key is valid, i.e.,
    // an affine group element
    if (!secp256k1_eckey_pubkey_parse(&pkge, pk.data(), pk.size())) {
        throw std::invalid_argument("not a valid public key");
    }

    secp256k1_gej_set_ge(&this->pk, &pkge);
    secp256k1_scalar_set_b32(&this->w, w.data(), nullptr);
}


ChameleonHash::ChameleonHash(const sk_t& sk, const W& w, int n) : hasSecretKey_(true)
{
    initialize();
    secp256k1_scalar_set_b32(&this->sk, sk.data(), nullptr);
    if (secp256k1_scalar_is_zero(&this->sk)) {
        throw std::invalid_argument("zero is not a valid secret key");
    }
    secp256k1_scalar_set_b32(&this->w, w.data(), nullptr);

    // compute public ke
    // set n*w
    secp256k1_scalar_t x;
    secp256k1_scalar_t a;
    secp256k1_scalar_clear(&a);
    secp256k1_scalar_clear(&x);
    secp256k1_scalar_add(&x, &x, &this->w);
    while (n) {
        if (n & 1) {
            secp256k1_scalar_add(&a, &a, &x);
        }
        secp256k1_scalar_add(&x, &x, &x);
        n >>= 1;
    }
    // set skr = sk+n*w
    secp256k1_scalar_t skr;
    secp256k1_scalar_clear(&skr);
    secp256k1_scalar_add(&skr, &skr, &this->sk);
    secp256k1_scalar_add(&skr, &skr, &a);
    // set pk = g^(sk+n*w)
    secp256k1_ecmult_gen(&this->pk, &skr);

    secp256k1_scalar_inverse(&this->skInv, &this->sk);
}

ChameleonHash::pk_t ChameleonHash::getPk(bool compressed)
{
    secp256k1_ge_t pkge;
    secp256k1_ge_set_gej_var(&pkge, &this->pk);

    pk_t res;
    res.resize(65);
    int size;
    secp256k1_eckey_pubkey_serialize(&pkge, res.data(), &size, compressed);
    res.resize(size);
    return res;
}

ChameleonHash::sk_t ChameleonHash::getSk()
{
    if (!hasSecretKey_) {
        throw std::logic_error("no secret key available");
    }
    sk_t res;
    secp256k1_scalar_get_b32(res.data(), &this->sk);
    return res;
}

void ChameleonHash::ch(hash_t& res, const digest_t& m, const rand_t& r, int n)
{
    // m cannot overflow, this is ensured by the public ch() method
    secp256k1_scalar_t ms;
    //将标量设置为无符号整数
    secp256k1_scalar_set_b32(&ms, m.data(), nullptr);

    int overflow;

    secp256k1_scalar_t rs;
    //将标量设置为无符号整数
    secp256k1_scalar_set_b32(&rs, r.data(), &overflow);
    if (overflow) {
        throw std::invalid_argument("overflow in randomness");
    }

    secp256k1_gej_t resgej;
    secp256k1_ge_t resge;

    int hash_len = 0;

    if (this->hasSecretKey_) {
        // now we (ab)use the rs variable to compute the result
        // set n*w
        secp256k1_scalar_t x;
        secp256k1_scalar_t a;
        secp256k1_scalar_clear(&a);
        secp256k1_scalar_clear(&x);
        secp256k1_scalar_add(&x, &x, &this->w);
        while (n) {
            if (n & 1) {
                secp256k1_scalar_add(&a, &a, &x);
            }
            secp256k1_scalar_add(&x, &x, &x);
            n >>= 1;
        }
        //set (n*w)*r
        secp256k1_scalar_mul(&a, &a, &rs);

        //将两个标量相乘（以组顺序为模）。 r*sk
        secp256k1_scalar_mul(&rs, &rs, &this->sk);
        //将两个标量相加（按组顺序进行模运算）。返回是否已溢出。 m+sk*r
        secp256k1_scalar_add(&rs, &rs, &ms);

        // set m+sk*r+(n*w)*r
        secp256k1_scalar_add(&rs, &rs, &a);

        //在签名过程中用于加速a*G计算 g^(m+(sk+(n*w))*r)
        secp256k1_ecmult_gen(&resgej, &rs);
    }
    else {
        secp256k1_ecmult(&resgej, &this->pk, &rs, &ms);
    }
    //获取产生器（在group包里提到过）
    secp256k1_ge_set_gej(&resge, &resgej);
    //签名
    if (!secp256k1_eckey_pubkey_serialize(&resge, res.data(), &hash_len, 1) || hash_len != HASH_LEN) {
        throw std::logic_error("cannot serialize chameleon hash");
    }
}

void ChameleonHash::ch(hash_t& res, const mesg_t& m, const rand_t& r, int n)
{
    digest_t d;
    digest(d, m);
    ch(res, d, r, n);
}

void ChameleonHash::extract(const mesg_t& m1, const rand_t& r1, int n1, const mesg_t& m2, const rand_t& r2, int n2) {
    digest_t d1, d2;
    digest(d1, m1);
    digest(d2, m2);
    extract(d1, r1, n1, d2, r2, n2);
}

void ChameleonHash::extract(const digest_t& d1, const rand_t& r1, int n1, const mesg_t& m2, const rand_t& r2, int n2) {
    digest_t d2;
    digest(d2, m2);
    extract(d1, r1, n1, d2, r2, n2);
}


void ChameleonHash::extract(const mesg_t& m1, const rand_t& r1, int n1, const digest_t& d2, const rand_t& r2, int n2) {
    digest_t d1;
    digest(d1, m1);
    extract(d1, r1, n1, d2, r2, n2);
}


void ChameleonHash::extract(const digest_t& d1, const rand_t& r1, int n1, const digest_t& d2, const rand_t& r2, int n2)
{
    // verify that the input is indeed a collision
//    hash_t ch1, ch2;
//    ch(ch1, d1, r1, n1, w);
//    ch(ch2, d2, r2, n2, w);
//    if ((r1 == r2 && d1 == d2) || ch1 != ch2) {
//        throw std::invalid_argument("not a collision");
//    }


    // set d1-d2
    secp256k1_scalar_t d1s, d2s, sumd1_d2;
    secp256k1_scalar_set_b32(&d1s, d1.data(), nullptr);
    secp256k1_scalar_set_b32(&d2s, d2.data(), nullptr);
    secp256k1_scalar_negate(&d2s, &d2s);
    secp256k1_scalar_add(&sumd1_d2, &d1s, &d2s);


    // set r2*n2
    secp256k1_scalar_t x2;
    secp256k1_scalar_t a2;
    secp256k1_scalar_clear(&a2);
    secp256k1_scalar_set_b32(&x2, r2.data(), nullptr);
    while (n2) {
        if (n2 & 1) {
            secp256k1_scalar_add(&a2, &a2, &x2);
        }
        secp256k1_scalar_add(&x2, &x2, &x2);
        n2 >>= 1;
    }
    // set r1*n1
    secp256k1_scalar_t x1;
    secp256k1_scalar_t a1;
    secp256k1_scalar_clear(&a1);
    secp256k1_scalar_set_b32(&x1, r1.data(), nullptr);
    while (n1) {
        if (n1 & 1) {
            secp256k1_scalar_add(&a1, &a1, &x1);
        }
        secp256k1_scalar_add(&x1, &x1, &x1);
        n1 >>= 1;
    }

    // set (r1*n1-r2*n2)
    secp256k1_scalar_negate(&a2, &a2);
    secp256k1_scalar_add(&a1, &a1, &a2);
    // set w*(r1*n1-r2*n2)
    secp256k1_scalar_t ws;
    secp256k1_scalar_clear(&ws);
    secp256k1_scalar_add(&ws, &ws, &this->w);
    secp256k1_scalar_mul(&a1, &a1, &ws);

    // set (d1-d2)+w*(r1*n1-r2*n2)
    secp256k1_scalar_t up;
    secp256k1_scalar_clear(&up);
    secp256k1_scalar_add(&up, &sumd1_d2, &a1);


    // set r2-r1
    secp256k1_scalar_t r1s, r2s, down;
    secp256k1_scalar_clear(&r1s);
    secp256k1_scalar_clear(&r2s);
    secp256k1_scalar_set_b32(&r1s, r1.data(), nullptr);
    secp256k1_scalar_set_b32(&r2s, r2.data(), nullptr);
    secp256k1_scalar_negate(&r1s, &r1s);
    secp256k1_scalar_add(&down, &r2s, &r1s);
    secp256k1_scalar_inverse(&down, &down);


    // set sk = ((d1-d2)-(r2*n2-r1*n1)*w) / (r2-r1)
    secp256k1_scalar_mul(&this->sk, &up, &down);
    secp256k1_scalar_inverse(&this->skInv, &this->sk);
    hasSecretKey_ = true;
}

void ChameleonHash::collision(const ChameleonHash::digest_t& d1, const ChameleonHash::rand_t& r1, int n1, const ChameleonHash::digest_t& d2, ChameleonHash::rand_t& r2, int n2)
{
    if (!hasSecretKey()) {
        throw std::logic_error("no secret key available");
    }

    // set d1-d2
    secp256k1_scalar_t d1s, d2s, sumd1_d2;
    secp256k1_scalar_set_b32(&d1s, d1.data(), nullptr);
    secp256k1_scalar_set_b32(&d2s, d2.data(), nullptr);
    secp256k1_scalar_negate(&d2s, &d2s);
    secp256k1_scalar_add(&sumd1_d2, &d1s, &d2s);

    // set n1*w
    secp256k1_scalar_t x1;
    secp256k1_scalar_t a1;
    secp256k1_scalar_clear(&a1);
    secp256k1_scalar_clear(&x1);
    secp256k1_scalar_add(&x1, &x1, &this->w);
    while (n1) {
        if (n1 & 1) {
            secp256k1_scalar_add(&a1, &a1, &x1);
        }
        secp256k1_scalar_add(&x1, &x1, &x1);
        n1 >>= 1;
    }

    // set (n1*w+sk)
    secp256k1_scalar_add(&a1, &a1, &this->sk);
    // set r1*(n1*w+sk)
    secp256k1_scalar_t r1s;
    secp256k1_scalar_set_b32(&r1s, r1.data(), nullptr);
    secp256k1_scalar_mul(&a1, &r1s, &a1);

    // set (d1-d2)+r1*(n1*w+sk)
    secp256k1_scalar_t up;
    secp256k1_scalar_clear(&up);
    secp256k1_scalar_add(&up, &sumd1_d2, &a1);

    // set n2*w
    secp256k1_scalar_t x2;
    secp256k1_scalar_t a2;
    secp256k1_scalar_clear(&a2);
    secp256k1_scalar_clear(&x2);
    secp256k1_scalar_add(&x2, &x2, &this->w);
    while (n2) {
        if (n2 & 1) {
            secp256k1_scalar_add(&a2, &a2, &x2);
        }
        secp256k1_scalar_add(&x2, &x2, &x2);
        n2 >>= 1;
    }

    // set (n2*w+sk)
    secp256k1_scalar_t down;
    secp256k1_scalar_clear(&down);
    secp256k1_scalar_add(&down, &a2, &this->sk);
    // set 1/(n2*w+sk)
    secp256k1_scalar_inverse(&down, &down);

    // r2 = ((d1-d2)+(n1*w+sk)*r1)/(n2*w+sk)
    secp256k1_scalar_t r2s;
    secp256k1_scalar_mul(&r2s, &up, &down);
    secp256k1_scalar_get_b32(r2.data(), &r2s);

}

void ChameleonHash::collision(const ChameleonHash::mesg_t& m1, const ChameleonHash::rand_t& r1, int n1, const ChameleonHash::mesg_t& m2, ChameleonHash::rand_t& r2, int n2)
{
    digest_t d1, d2;
    digest(d1, m1);
    digest(d2, m2);
    collision(d1, r1, n1, d2, r2, n2);
}

void ChameleonHash::collision(const ChameleonHash::mesg_t& m1, const ChameleonHash::rand_t& r1, int n1, const ChameleonHash::digest_t& d2, ChameleonHash::rand_t& r2, int n2)
{
    digest_t d1;
    digest(d1, m1);
    collision(d1, r1, n1, d2, r2, n2);
}

void ChameleonHash::collision(const ChameleonHash::digest_t& d1, const ChameleonHash::rand_t& r1, int n1, const ChameleonHash::mesg_t& m2, ChameleonHash::rand_t& r2, int n2)
{
    digest_t d2;
    digest(d2, m2);
    collision(d1, r1, n1, d2, r2, n2);
}


void ChameleonHash::digest(digest_t& digest, const mesg_t& m)
{
    secp256k1_sha256_t sha;
    secp256k1_scalar_t ms;

    const unsigned char* in = m.data();
    size_t size = m.size();

    int overflow;
    do {
        secp256k1_sha256_initialize(&sha);
        secp256k1_sha256_write(&sha, in, size);
        secp256k1_sha256_finalize(&sha, digest.data());
        secp256k1_scalar_set_b32(&ms, digest.data(), &overflow);
        in = digest.data();
        size = digest.size();
    } while (overflow);
}

void ChameleonHash::digest(digest_t& digest, const ChameleonHash::hash_t& in1, const ChameleonHash::hash_t& in2)
{
    secp256k1_sha256_t hash;
    secp256k1_sha256_initialize(&hash);
    secp256k1_sha256_write(&hash, in1.data(), in1.size());
    secp256k1_sha256_write(&hash, in2.data(), in2.size());
    secp256k1_sha256_finalize(&hash, digest.data());
}

void ChameleonHash::randomOracle(hash_t& out, const hash_t& in1, const rand_t& in2)
{
    secp256k1_hmac_sha256_t hmac;
    unsigned char key[] = "RandomOracleGRandomOracleGRandom";
    secp256k1_hmac_sha256_initialize(&hmac, key, 32);
    secp256k1_hmac_sha256_write(&hmac, in1.data(), in1.size());
    secp256k1_hmac_sha256_write(&hmac, in2.data(), in2.size());
    secp256k1_hmac_sha256_finalize(&hmac, out.data());
    out[32] = '\0';
}
