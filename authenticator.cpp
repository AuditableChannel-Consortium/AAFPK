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

#include "authenticator.h"
#include "chameleonhash.h"
#include "node.h"
#include "prf.h"

#include <exception>
#include <assert.h>

Authenticator::Authenticator(const Authenticator::dsk_t& dsk, const Authenticator::dw_t& dw, int n) : dsk(dsk), ch(dsk, dw, n), _n(n), hasSecretKey_(true) {
    Prf prf(dsk, true);
    ChameleonHash::digest_t x;
    ChameleonHash::rand_t r;

    ChameleonHash::hash_t left, right;
    Node node = Node::leftChildOfRoot();

    prf.getX(x, node);
    prf.getR(r, node);
    ch.ch(left, x, r, n);

    node.moveToSibling();

    prf.getX(x, node);
    prf.getR(r, node);
    ch.ch(right, x, r, n);

    ChameleonHash::digest(rootDigest, left, right);
}

Authenticator::Authenticator(const Authenticator::dpk_t& dpk, const Authenticator::dw_t& dw) : rootDigest(dpk.rootDigest), ch(dpk.chpk, dw), hasSecretKey_(false) { }


void Authenticator::authenticate(token_t& t, const Authenticator::ct_t& ct, const Authenticator::st_t& st, int n)
{
    if (!hasSecretKey_) {
        throw std::logic_error("cannot authenticate without secret key");
    }
    Prf prf(dsk, true);
    ChameleonHash::digest_t prfX, subTreeX, sibX;
    ChameleonHash::rand_t prfR, subTreeR, sibR;
    ChameleonHash::hash_t chash, sibchash;

    Node node(ct);
    ChameleonHash::digest(subTreeX, st);
    auto rOut = t.rs.begin();
    auto chOut = t.chs.begin();

    bool first = true;
    while (!node.isRoot()) {
        prf.getX(prfX, node);
        prf.getR(prfR, node);
        ch.ch(chash, prfX, prfR, this->_n);
        ch.collision(prfX, prfR, this->_n, subTreeX, subTreeR, n);

        if (first) {
            ChameleonHash::randomOracle(chash, chash, subTreeR);
            first = false;
        }

        node.moveToSibling();

        prf.getX(sibX, node);
        prf.getR(sibR, node);
        ch.ch(sibchash, sibX, sibR, this->_n);

        *(rOut++) = subTreeR;
        *(chOut++) = sibchash;


        if (node.isLeftChild()) {
            ChameleonHash::digest(subTreeX, sibchash, chash);
        }
        else {
            ChameleonHash::digest(subTreeX, chash, sibchash);
        }

        node.moveToParent();
    }
    assert(subTreeX == rootDigest);
}

void Authenticator::authenticates(altMessage& t, int cnt, const ct_t& ct, int n[], ChameleonHash::hash_t& res)
{
	for (int i = 0; i < cnt; i++) {
		authenticate(t.token[i], ct, t.ms[i], n[i]);
	}
	std::vector< ChameleonHash::rand_t> r;
	for (int i = 0; i < cnt; i++) {
		r.push_back(*t.token[i].rs.begin());
	}
	std::vector< ChameleonHash::digest_t> ms;
	for (int i = 0; i < cnt; i++) {
		ChameleonHash::digest_t X;
		ChameleonHash::digest(X, t.ms[i]);
		ms.push_back(X);
	}
	ch.mergeA(res, ms, r, n, cnt);
}

bool Authenticator::verifys(const altMessage& t, int cnt, const ct_t& ct, int n[],std::vector<ChameleonHash::pk_t> pk, dw_t w, ChameleonHash::hash_t& res)
{
	/*for (int i = 0; i < cnt; i++) {
		ChameleonHash ch_t(pk[i], w);
		this->ch = ch_t;
		if (!verifyWithLog(t.token[i], ct, t.ms[i], nullptr, n[i])) return false;
	}*/
	std::vector<ChameleonHash::rand_t> r;
	for (int i = 0; i < cnt; i++) {
		r.push_back(*t.token[i].rs.begin());
	}
	std::vector<ChameleonHash::digest_t> ms;
	for (int i = 0; i < cnt; i++) {
		ChameleonHash::digest_t X;
		ChameleonHash::digest(X, t.ms[i]);
		ms.push_back(X);
	}
	ChameleonHash::hash_t hash;
	ch.mergeV(hash, ms, r, pk, cnt);
	return (hash == res);
}

bool Authenticator::verify(const Authenticator::token_t& t, const Authenticator::ct_t& ct, const Authenticator::st_t& st, int n)
{
    return verifyWithLog(t, ct, st, nullptr, n);
}


bool Authenticator::verifyWithLog(const Authenticator::token_t& t, const Authenticator::ct_t& ct, const Authenticator::st_t& st, log_t* log, int n)
{
    ChameleonHash::digest_t subTreeX;
    ChameleonHash::hash_t chash;

    Node node(ct);
    ChameleonHash::digest(subTreeX, st);
    auto rIt = t.rs.begin();
    auto sibchashIt = t.chs.begin();

    bool first = true;
    while (!node.isRoot()) { // stop after the hash in the root
        ch.ch(chash, subTreeX, *rIt, n);

        if (log) {
            log->chs.push_back(chash);
            log->xs.push_back(subTreeX);
        }

        if (first) {
            ChameleonHash::randomOracle(chash, chash, *rIt);
            first = false;
        }

        // compute hash of the parent of node
        if (node.isLeftChild()) {
            ChameleonHash::digest(subTreeX, chash, *sibchashIt);
        }
        else {
            ChameleonHash::digest(subTreeX, *sibchashIt, chash);
        }

        rIt++;
        sibchashIt++;
        node.moveToParent();
    }
    assert(sibchashIt == t.chs.end());
    assert(rIt == t.rs.end());
    return (subTreeX == rootDigest);
}

void Authenticator::extract(const Authenticator::token_t& t1, const Authenticator::token_t& t2, const Authenticator::ct_t& ct, const Authenticator::st_t& st1, const Authenticator::st_t& st2, int n1, int n2)
{
    log_t log1, log2;
    if (!verifyWithLog(t1, ct, st1, &log1, n1)) {
        throw std::invalid_argument("t1 does not verify");
    }
    if (!verifyWithLog(t2, ct, st2, &log2, n2)) {
        throw std::invalid_argument("t2 does not verify");
    }

    for (int i = 0; i < DEPTH; i++) {
        // check for collision
        if ((log1.xs[i] != log2.xs[i] || t1.rs[i] != t2.rs[i]) && log1.chs[i] == log2.chs[i]) {
            ch.extract(log1.xs[i], t1.rs[i], n1, log2.xs[i], t2.rs[i], n2);
        }
        if (!ch.hasSecretKey()) {
            throw std::runtime_error("t1 and t2 are not extractable even though they both verify. This state should be computationally infeasible to reach.");
        }
        hasSecretKey_ = true;
    }
}


Authenticator::dpk_t Authenticator::getDpk()
{
    dpk_t dpk;
    dpk.chpk = ch.getPk(true);
    dpk.rootDigest = rootDigest;
    return dpk;
}

Authenticator::dsk_t Authenticator::getDsk()
{
    return ch.getSk();
}
