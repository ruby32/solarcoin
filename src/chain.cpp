// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain.h"
#include "consensus/params.h"

/**
 * CChain implementation
 */
void CChain::SetTip(CBlockIndex *pindex) {
    if (pindex == NULL) {
        vChain.clear();
        return;
    }
    vChain.resize(pindex->nHeight + 1);
    while (pindex && vChain[pindex->nHeight] != pindex) {
        vChain[pindex->nHeight] = pindex;
        pindex = pindex->pprev;
    }
}

CBlockLocator CChain::GetLocator(const CBlockIndex *pindex) const {
    int nStep = 1;
    std::vector<uint256> vHave;
    vHave.reserve(32);

    if (!pindex)
        pindex = Tip();
    while (pindex) {
        vHave.push_back(pindex->GetBlockHash());
        // Stop when we have added the genesis block.
        if (pindex->nHeight == 0)
            break;
        // Exponentially larger steps back, plus the genesis block.
        int nHeight = std::max(pindex->nHeight - nStep, 0);
        if (Contains(pindex)) {
            // Use O(1) CChain index if possible.
            pindex = (*this)[nHeight];
        } else {
            // Otherwise, use O(log n) skiplist.
            pindex = pindex->GetAncestor(nHeight);
        }
        if (vHave.size() > 10)
            nStep *= 2;
    }

    return CBlockLocator(vHave);
}

const CBlockIndex *CChain::FindFork(const CBlockIndex *pindex) const {
    if (pindex == NULL) {
        return NULL;
    }
    if (pindex->nHeight > Height())
        pindex = pindex->GetAncestor(Height());
    while (pindex && !Contains(pindex))
        pindex = pindex->pprev;
    return pindex;
}

CBlockIndex* CChain::FindEarliestAtLeast(int64_t nTime) const
{
    std::vector<CBlockIndex*>::const_iterator lower = std::lower_bound(vChain.begin(), vChain.end(), nTime,
        [](CBlockIndex* pBlock, const int64_t& time) -> bool { return pBlock->GetBlockTimeMax() < time; });
    return (lower == vChain.end() ? NULL : *lower);
}

/** Turn the lowest '1' bit in the binary representation of a number into a '0'. */
int static inline InvertLowestOne(int n) { return n & (n - 1); }

/** Compute what height to jump back to with the CBlockIndex::pskip pointer. */
int static inline GetSkipHeight(int height) {
    if (height < 2)
        return 0;

    // Determine which height to jump back to. Any number strictly lower than height is acceptable,
    // but the following expression seems to perform well in simulations (max 110 steps to go back
    // up to 2**18 blocks).
    return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height);
}

CBlockIndex* CBlockIndex::GetAncestor(int height)
{
    if (height > nHeight || height < 0)
        return NULL;

    CBlockIndex* pindexWalk = this;
    int heightWalk = nHeight;
    while (heightWalk > height) {
        int heightSkip = GetSkipHeight(heightWalk);
        int heightSkipPrev = GetSkipHeight(heightWalk - 1);
        if (pindexWalk->pskip != NULL &&
            (heightSkip == height ||
             (heightSkip > height && !(heightSkipPrev < heightSkip - 2 &&
                                       heightSkipPrev >= height)))) {
            // Only follow pskip if pprev->pskip isn't better than pskip->pprev.
            pindexWalk = pindexWalk->pskip;
            heightWalk = heightSkip;
        } else {
            assert(pindexWalk->pprev);
            pindexWalk = pindexWalk->pprev;
            heightWalk--;
        }
    }
    return pindexWalk;
}

const CBlockIndex* CBlockIndex::GetAncestor(int height) const
{
    return const_cast<CBlockIndex*>(this)->GetAncestor(height);
}

void CBlockIndex::BuildSkip()
{
    if (pprev)
        pskip = pprev->GetAncestor(GetSkipHeight(nHeight));
}

arith_uint256 GetBlockProof(const CBlockIndex& block)
{
    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(block.nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0)
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for a arith_uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (nTarget+1) + 1.
    return (~bnTarget / (bnTarget + 1)) + 1;
}

int64_t GetBlockProofEquivalentTime(const CBlockIndex& to, const CBlockIndex& from, const CBlockIndex& tip, const Consensus::Params& params)
{
    arith_uint256 r;
    int sign = 1;
    if (to.nChainWork > from.nChainWork) {
        r = to.nChainWork - from.nChainWork;
    } else {
        r = from.nChainWork - to.nChainWork;
        sign = -1;
    }
    r = r * arith_uint256(params.nPowTargetSpacing) / GetBlockProof(tip);
    if (r.bits() > 63) {
        return sign * std::numeric_limits<int64_t>::max();
    }
    return sign * r.GetLow64();
}

// SOLARCOIN
// get stake time factored weight for reward and hash PoST
int64_t GetStakeTimeFactoredWeight(int64_t timeWeight, int64_t bnCoinDayWeight, CBlockIndex* pindexPrev)
{
    int64_t factoredTimeWeight;
    double weightFraction = (bnCoinDayWeight+1) / (GetAverageStakeWeight(pindexPrev));
    if (weightFraction > 0.45)
    {
        factoredTimeWeight = nStakeMinAge+1;
    }
    else
    {
        double stakeTimeFactor = pow(cos((PI*weightFraction)),2.0);
        factoredTimeWeight = stakeTimeFactor*timeWeight;
    }
    return factoredTimeWeight;
}

// get average stake weight of last 60 blocks PoST
double GetAverageStakeWeight(CBlockIndex* pindexPrev)
{
    double weightSum = 0.0, weightAve = 0.0;
    if (nBestHeight < 1)
        return weightAve;

    // Use cached weight if it's still valid
    if (pindexPrev->nHeight == nAverageStakeWeightHeightCached)
    {
        return dAverageStakeWeightCached;
    }
    nAverageStakeWeightHeightCached = pindexPrev->nHeight;

    int i;
    CBlockIndex* currentBlockIndex = pindexPrev;
    for (i = 0; currentBlockIndex && i < 60; i++)
    {
        double tempWeight = GetPoSKernelPS(currentBlockIndex);
        weightSum += tempWeight;
        currentBlockIndex = currentBlockIndex->pprev;
    }
    weightAve = (weightSum/i)+21;

    // Cache the stake weight value
    dAverageStakeWeightCached = weightAve;

    return weightAve;
}

// get current inflation rate using average stake weight ~1.5-2.5% (measure of liquidity) PoST
double GetCurrentInflationRate(double nAverageWeight)
{
    double inflationRate = (17*(log(nAverageWeight/20)))/100;

    return inflationRate;
}

// get current interest rate by targeting for network stake dependent inflation rate PoST
double GetCurrentInterestRate(CBlockIndex* pindexPrev, twoPercentIntHeight, twoPercentInt)
{
    double interestRate = 0;

    // Fixed interest rate after PoW + 1000
    if (pindexPrev->nHeight > twoPercentIntHeight)
    {
        interestRate = twoPercentInt;
    }
    else
    {
        double nAverageWeight = GetAverageStakeWeight(pindexPrev);
        double inflationRate = GetCurrentInflationRate(nAverageWeight) / 100;
        // Bug fix: Should be "GetCurrentCoinSupply(pindexPrev) * COIN", but this code is no longer executed.
        interestRate = ((inflationRate * GetCurrentCoinSupply(pindexPrev)) / nAverageWeight) * 100;

        // Cap interest rate (must use the 2.0.2 interest rate value)
        if (interestRate > 10.0)
            interestRate = 10.0;
    }

    return interestRate;
}

// Get the current coin supply / COIN
int64_t GetCurrentCoinSupply(CBlockIndex* pindexPrev, twoPercentIntHeight, coinSupplyGrowthRate, initialCoinSupply, lastPowBlock)
{
    // removed addition of 1.35 SLR / block after 835000 + 1000
    if (pindexPrev->nHeight > twoPercentIntHeight)
        if (pindexPrev->nHeight >= FORK_HEIGHT_2)
            // Bug fix: pindexPrev->nMoneySupply is an int64_t that has overflowed and is now negative.
            // Use the real coin supply + expected growth rate since twoPercentIntHeight from granting.
            return ((pindexPrev->nMoneySupply - (98000000000 * COIN)) / COIN) + (int64_t)((double)(pindexPrev->nHeight - twoPercentIntHeight) * coinSupplyGrowthRate);
        else
            return initialCoinSupply;
    else
        return (initialCoinSupply + ((pindexPrev->nHeight - lastPowBlock) * coinSupplyGrowthRate));
}

// Get the block rate for one hour
int GetBlockRatePerHour()
{
    int nRate = 0;
    CBlockIndex* pindex = pindexBest;
    int64_t nTargetTime = GetAdjustedTime() - 3600;

    while (pindex && pindex->pprev && pindex->nTime > nTargetTime) {
        nRate += 1;
        pindex = pindex->pprev;
    }
    if (nRate < nTargetSpacing / 2)
        printf("GetBlockRatePerHour: Warning, block rate (%d) is less than half of nTargetSpacing=%d.\n", nRate, nTargetSpacing);
    return nRate;
}

// Stakers coin reward based on coin stake time factor and targeted inflation rate PoST
int64_t GetProofOfStakeTimeReward(int64_t nStakeTime, int64_t nFees, CBlockIndex* pindexPrev)
{
    int64_t nInterestRate = GetCurrentInterestRate(pindexPrev)*CENT;
    int64_t nSubsidy = nStakeTime * nInterestRate * 33 / (365 * 33 + 8);

    if (fDebug && GetBoolArg("-printcreation"))
        printf("GetProofOfStakeTimeReward(): create=%s nStakeTime=%"PRId64"\n", FormatMoney(nSubsidy).c_str(), nStakeTime);

    return nSubsidy + nFees;
}



