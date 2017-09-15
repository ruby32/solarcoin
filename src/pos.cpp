// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain.h"
#include "main.h"
#include "pos.h"
#include "primitives/block.h"

double GetPoSKernelPS(CBlockIndex* pindexPrev)
{
    int nPoSInterval = 72;
    double dStakeKernelsTriedAvg = 0;
    int nStakesHandled = 0, nStakesTime = 0;

    CBlockIndex* pindexPrevStake = NULL;

    while (pindexPrev && nStakesHandled < nPoSInterval)
    {
        if (pindexPrev->IsProofOfStake())
        {
            dStakeKernelsTriedAvg += GetDifficulty(pindexPrev) * 4294967296.0;
            if (pindexPrev->nHeight >= FORK_HEIGHT_2)
                nStakesTime += max((int)(pindexPrevStake ? (pindexPrevStake->nTime - pindexPrev->nTime) : 0), 0); // Bug fix: Prevent negative stake weight
            else
                nStakesTime += pindexPrevStake ? (pindexPrevStake->nTime - pindexPrev->nTime) : 0;
            pindexPrevStake = pindexPrev;
            nStakesHandled++;
        }
        pindexPrev = pindexPrev->pprev;
    }

   return nStakesTime ? dStakeKernelsTriedAvg / nStakesTime : 0;
}

