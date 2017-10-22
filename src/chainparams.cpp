// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"
#include "consensus/params.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 2;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;
    txNew.strTxComment = "text:SolarCoin genesis block";

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = 1;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{

    const char* pszTimestamp = "One Megawatt Hour";
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 525600;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); 
        consensus.posLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // SolarCoin: proof-of-stake limit
        consensus.nPowTargetTimespan_Version1 = 24 * 60 * 60; // 1 day 
        consensus.nPowTargetSpacing = 1 * 60; // SolarCoin: 1 minute

        consensus.nHeight_Version2 = 208440;
        consensus.nTargetTimespan_Version2 = consensus.DifficultyAdjustmentInterval_V2() * consensus.nPowTargetSpacing; // 15 minutes

        consensus.nPoSStakeMinAge = 8 * 60 * 60; // SolarCoin: 8 hours proof-of-stake min age
        consensus.nPoSModifierInterval = 10 * 50; // SolarCoin: 10 minute time interval modifier 

        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 6048; // 75% of 8064
        consensus.nMinerConfirmationWindow = 8064; // nPowTargetTimespan / nPowTargetSpacing * 4

        // deploy on block right after segwit soft-fork
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("e8666c8715fafbfb095132deb1dd2af63fe14d3d7163715341d48feffab458cc");
        consensus.BIP65Height = 1; 
        consensus.BIP66Height = 1;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1485561600; // January 28, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1517356801; // January 31st, 2018

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1485561600; // January 28, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1517356801; // January 31st, 2018

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000006805c7318ce2736c0");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0xd8bf60a8864768175ed8ab32e1be698a5e965aa0fdf6ba47376017738e9e3679"); // 1868955 

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x04;
        pchMessageStart[1] = 0xf1;
        pchMessageStart[2] = 0x04;
        pchMessageStart[3] = 0xfd;
        nDefaultPort = 18181;
        nPruneAfterHeight = 100000;

// static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
        //genesis = CreateGenesisBlock(1384473600, 1397766, 0x1e0ffff0, 1, 100 * COIN);
        genesis = CreateGenesisBlock(1384473600, 1397766, 0x1e0ffff0, 1, 100 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();
        printf("consensus.hashGenesisBlock: %s \n", genesis.GetHash().ToString());
        assert(consensus.hashGenesisBlock == uint256S("0xedcf32dbfd327fe7f546d3a175d91b05e955ec1224e087961acc9a2aa8f592ee"));
        assert(genesis.hashMerkleRoot == uint256S("0x33ecdb1985425f576c65e2c85d7983edc6207038a2910fefaf86cfb4e53185a3"));

        // Note that of those with the service bits flag, most only support a subset of possible options
        vSeeds.push_back(CDNSSeedData("dnsseed1", "dnsseed.solarcoin.org", true));
        vSeeds.push_back(CDNSSeedData("dnsseed2", "dnsseed2.solarcoin.org", true));
        vSeeds.push_back(CDNSSeedData("dnsseed3", "dnsseed3.solarcoin.org", true));
        vSeeds.push_back(CDNSSeedData("dnsseed-pnosker", "dnsseed.pnosker.com", true));
        vSeeds.push_back(CDNSSeedData("dnsseed-pcmerc", "dnsseed.kryptochaos.com", true));
        vSeeds.push_back(CDNSSeedData("dnsseed-pcmerc3", "seed.kryptochaos.com", true));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,18);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,50);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,146); // 128+PUBKEY_ADDRESS
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x08)(0xC5)(0xD1).convert_to_container<std::vector<unsigned char> >(); // TODO: check BIP32
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x22)(0xBE)(0xD7).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (  	  1, uint256S("0xe8666c8715fafbfb095132deb1dd2af63fe14d3d7163715341d48feffab458cc"))
            (  	 25, uint256S("0xe49cfc3e60515965380cbc3a1add5ab007e5bd2f226624cad9ff0f79eef680cc"))
            (  	 50, uint256S("0x0b082428186ab2dc55403b2b3c9bd14f087590b204e05c09a656914285520b4d"))
            (    98, uint256S("0xd27e483ae4d334cc65575bcc66d65f7a97913f31188662e2d3fe329675714128"))
            ( 25000, uint256S("0x76d94f81bf598f915b68a57db229ff015551fb175167546363e12d7e86226099"))
            ( 75000, uint256S("0xdc26dd1c5c53d0e09ce3eec73107423aa518b8a2c0ebe47e6d4987866d68b881"))
            (100000, uint256S("0x68d5027a570c605f6a0d24f8bad5c454769438eb4a237e93b4ee7a638eaa01b0"))
            (125000, uint256S("0x28cf8f91b29aae787b20c1c915d1cc29283b0ee4c517c5908d6c4b1017c05ee9"))
            (150000, uint256S("0xa9d3915cc6c9a18a6fe72429d496c985308c5335e60afe616fe6c8123c6e624f"))
            (175000, uint256S("0xbd7448096c4323e765bba6ce2cef0f4affc4e76f661002dda9154c7e583a0434"))
            (200000, uint256S("0x5f295d3a00a74641d9fda7bf538585456b30261d20bf559c4f4ca30a949062fe"))
            (225000, uint256S("0xa4ccb19c88086010441a3262cc61e99fee2981da43e6172024814431c480dc88"))
            (250000, uint256S("0xfacb5fd3f8e1053adeec85e780021c86a1e850d33b1e2d405c439789e838c5b0"))
            (290000, uint256S("0x815cde17499d0c13689df3c567b55a34e3b801cd3ef539ffd39bf4acbe17db47"))
            (543210, uint256S("0x46980e38cf574516a299c1f62a7bfdac13e8644b4af921578d246fcea4faf3bf"))
            (683052, uint256S("0x42603f6376d36e89e9924bb5f3d0d3abcb0e8576a7e0025eda0174d57b975929"))
            (737145, uint256S("0x437c7025ceb553768f6ec4209bbeb557ebe7beeb60c5988c891d0aab6e993f05"))
            (1000000, uint256S("0x96d44ecebaf37bc17044a52ecaf7ba9da16ecbb42936402de3e23c38561a6b20"))
            (1440000, uint256S("0xae70181c2b2a0af8eb16916f4037ceaf674f3b040e3609d59193a8c37f44e096"))
            (1450000, uint256S("0x65051554822826f1ced143093bba9443c00f4c53138a06df193741cdee3b3ac8"))
            (1456000, uint256S("0xd7c13104530a9794dc67a623111e6644b3110f7b18b6f8aa3a92aae8162d9996"))
        };

        chainTxData = ChainTxData{
            // TODO: get this data

            // Data as of block b44bc5ae41d1be67227ba9ad875d7268aa86c965b1d64b47c35be6e8d5c352f4 (height 1155626).
            1487715936, // * UNIX timestamp of last known number of transactions
            9243806,  // * total number of transactions between genesis and that timestamp
                    //   (the tx=... number in the SetBestChain debug.log lines)
            0.06     // * estimated number of transactions per second after that timestamp
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.BIP34Height = 76;
        consensus.BIP34Hash = uint256S("8075c771ed8b495ffd943980a95f702ab34fce3c8c54e379548bda33cc8c0573");
        consensus.BIP65Height = 76; // 8075c771ed8b495ffd943980a95f702ab34fce3c8c54e379548bda33cc8c0573
        consensus.BIP66Height = 76; // 8075c771ed8b495ffd943980a95f702ab34fce3c8c54e379548bda33cc8c0573
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan_Version1 = 24 * 60 * 60; // 3.5 days
        consensus.nPowTargetSpacing = 2.5 * 60;

        consensus.nHeight_Version2 = 208440;
        consensus.nInterval_Version2 = 15;

        consensus.nPowTargetTimespan_Version2 = 3.5 * 24 * 60 * 60; // 3.5 days
        consensus.nPowTargetTimespan_Version2 = consensus.nInterval_Version2 * consensus.nPowTargetSpacing; // 10 minutes

        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1483228800; // January 1, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1517356801; // January 31st, 2018

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1483228800; // January 1, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1517356801; // January 31st, 2018

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000000054cb9e7a0");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x43a16a626ef2ffdbe928f2bc26dcd5475c6a1a04f9542dfc6a0a88e5fcf9bd4c"); //8711

        pchMessageStart[0] = 0xfd;
        pchMessageStart[1] = 0xd2;
        pchMessageStart[2] = 0xc8;
        pchMessageStart[3] = 0xf1;
        nDefaultPort = 19335;
        nPruneAfterHeight = 1000;

        printf("asdfklajsfklafd\n");
        genesis = CreateGenesisBlock(1486949366, 293345, 0x1e0ffff0, 2, 100 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        printf("hashGenesisBlock: %08x \n", consensus.hashGenesisBlock);
        assert(consensus.hashGenesisBlock == uint256S("0x4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0"));
        assert(genesis.hashMerkleRoot == uint256S("0x97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.push_back(CDNSSeedData("solarcointools.com", "testnet-seed.solarcointools.com"));
        vSeeds.push_back(CDNSSeedData("loshan.co.uk", "seed-b.solarcoin.loshan.co.uk", true));
        vSeeds.push_back(CDNSSeedData("thrasher.io", "dnsseed-testnet.thrasher.io", true));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,58);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 2056, uint256S("0x17748a31ba97afdc9a4f86837a39d287e3e7c7290a08a1d816c5969c78a83289")),
        };

        chainTxData = ChainTxData{
            // Data as of block f2dc531da6be01f53774f970aaaca200c7a8317ee9fd398ee733b40f14e265d1 (height 8702)
            1487715270,
            8731,
            0.01
        };

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan_Version1 = 3.5 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 19444;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1296688602, 0, 0x207fffff, 2, 100 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x530827f38f93b43ed12af0b3ad25a288dc02ed74d6d7857862df51fc56c416f9"));
        assert(genesis.hashMerkleRoot == uint256S("0x97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true; 

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0x530827f38f93b43ed12af0b3ad25a288dc02ed74d6d7857862df51fc56c416f9"))
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,58);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
