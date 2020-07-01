#ifndef _ACCOUNTGADGETS_H_
#define _ACCOUNTGADGETS_H_

#include "../Utils/Constants.h"
#include "../Utils/Data.h"

#include "MerkleTree.h"

#include "ethsnarks.hpp"
#include "utils.hpp"
#include "gadgets/merkle_tree.hpp"
#include "gadgets/poseidon.hpp"

using namespace ethsnarks;

namespace Loopring
{

struct AccountState
{
    VariableT owner;
    VariableT publicKeyX;
    VariableT publicKeyY;
    VariableT nonce;
    VariableT walletHash;
    VariableT balancesRoot;
};

class AccountGadget : public GadgetT
{
public:
    VariableT owner;
    const jubjub::VariablePointT publicKey;
    VariableT nonce;
    VariableT walletHash;
    VariableT balancesRoot;

    AccountGadget(
        ProtoboardT& pb,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        owner(make_variable(pb, FMT(prefix, ".owner"))),
        publicKey(pb, FMT(prefix, ".publicKey")),
        nonce(make_variable(pb, FMT(prefix, ".nonce"))),
        walletHash(make_variable(pb, FMT(prefix, ".walletHash"))),
        balancesRoot(make_variable(pb, FMT(prefix, ".balancesRoot")))
    {

    }

    void generate_r1cs_witness(const Account& account)
    {
        pb.val(owner) = account.owner;
        pb.val(publicKey.x) = account.publicKey.x;
        pb.val(publicKey.y) = account.publicKey.y;
        pb.val(nonce) = account.nonce;
        pb.val(walletHash) = account.walletHash;
        pb.val(balancesRoot) = account.balancesRoot;
    }
};

class UpdateAccountGadget : public GadgetT
{
public:
    HashAccountLeaf leafBefore;
    HashAccountLeaf leafAfter;

    const VariableArrayT proof;
    MerklePathCheckT proofVerifierBefore;
    MerklePathT rootCalculatorAfter;

    UpdateAccountGadget(
        ProtoboardT& pb,
        const VariableT& merkleRoot,
        const VariableArrayT& address,
        const AccountState& before,
        const AccountState& after,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        leafBefore(pb, var_array({before.owner, before.publicKeyX, before.publicKeyY, before.nonce, before.walletHash, before.balancesRoot}), FMT(prefix, ".leafBefore")),
        leafAfter(pb, var_array({after.owner, after.publicKeyX, after.publicKeyY, after.nonce, after.walletHash, after.balancesRoot}), FMT(prefix, ".leafAfter")),

        proof(make_var_array(pb, TREE_DEPTH_ACCOUNTS * 3, FMT(prefix, ".proof"))),
        proofVerifierBefore(pb, TREE_DEPTH_ACCOUNTS, address, leafBefore.result(), merkleRoot, proof, FMT(prefix, ".pathBefore")),
        rootCalculatorAfter(pb, TREE_DEPTH_ACCOUNTS, address, leafAfter.result(), proof, FMT(prefix, ".pathAfter"))
    {

    }

    void generate_r1cs_witness(const Proof& _proof)
    {
        leafBefore.generate_r1cs_witness();
        leafAfter.generate_r1cs_witness();

        proof.fill_with_field_elements(pb, _proof.data);
        proofVerifierBefore.generate_r1cs_witness();
        rootCalculatorAfter.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        leafBefore.generate_r1cs_constraints();
        leafAfter.generate_r1cs_constraints();

        proofVerifierBefore.generate_r1cs_constraints();
        rootCalculatorAfter.generate_r1cs_constraints();
    }

    const VariableT& result() const
    {
        return rootCalculatorAfter.result();
    }
};

struct BalanceState
{
    VariableT balance;
    VariableT index;
    VariableT tradingHistory;
};

class BalanceGadget : public GadgetT
{
public:
    VariableT balance;
    VariableT index;
    VariableT tradingHistory;

    BalanceGadget(
        ProtoboardT& pb,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        balance(make_variable(pb, FMT(prefix, ".balance"))),
        index(make_variable(pb, FMT(prefix, ".index"))),
        tradingHistory(make_variable(pb, FMT(prefix, ".tradingHistory")))
    {

    }

    void generate_r1cs_witness(const BalanceLeaf& balanceLeaf)
    {
        pb.val(balance) = balanceLeaf.balance;
        pb.val(index) = balanceLeaf.index;
        pb.val(tradingHistory) = balanceLeaf.tradingHistoryRoot;
    }
};

class UpdateBalanceGadget : public GadgetT
{
public:
    HashBalanceLeaf leafBefore;
    HashBalanceLeaf leafAfter;

    const VariableArrayT proof;
    MerklePathCheckT proofVerifierBefore;
    MerklePathT rootCalculatorAfter;

    UpdateBalanceGadget(
        ProtoboardT& pb,
        const VariableT& merkleRoot,
        const VariableArrayT& tokenID,
        const BalanceState before,
        const BalanceState after,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        leafBefore(pb, var_array({before.balance, before.index, before.tradingHistory}), FMT(prefix, ".leafBefore")),
        leafAfter(pb, var_array({after.balance, after.index, after.tradingHistory}), FMT(prefix, ".leafAfter")),

        proof(make_var_array(pb, TREE_DEPTH_TOKENS * 3, FMT(prefix, ".proof"))),
        proofVerifierBefore(pb, TREE_DEPTH_TOKENS, tokenID, leafBefore.result(), merkleRoot, proof, FMT(prefix, ".pathBefore")),
        rootCalculatorAfter(pb, TREE_DEPTH_TOKENS, tokenID, leafAfter.result(), proof, FMT(prefix, ".pathAfter"))
    {

    }

    void generate_r1cs_witness(const Proof& _proof)
    {
        leafBefore.generate_r1cs_witness();
        leafAfter.generate_r1cs_witness();

        proof.fill_with_field_elements(pb, _proof.data);
        proofVerifierBefore.generate_r1cs_witness();
        rootCalculatorAfter.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        leafBefore.generate_r1cs_constraints();
        leafAfter.generate_r1cs_constraints();

        proofVerifierBefore.generate_r1cs_constraints();
        rootCalculatorAfter.generate_r1cs_constraints();
    }

    const VariableT& result() const
    {
        return rootCalculatorAfter.result();
    }
};

// Calculcates the state of a user's open position
class ApplyInterestGadget : public GadgetT
{
public:

    // TODO: make safe
    UnsafeSubGadget indexDiff;
    MulDivGadget balanceDiff;
    AddGadget newBalance;

    ApplyInterestGadget(
        ProtoboardT& pb,
        const Constants& constants,
        const VariableT& balance,
        const VariableT& oldIndex,
        const VariableT& newIndex,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        indexDiff(pb, newIndex, oldIndex, FMT(prefix, ".indexDiff")),
        balanceDiff(pb, constants, balance, indexDiff.result(), constants.indexBase, NUM_BITS_AMOUNT, NUM_BITS_AMOUNT, NUM_BITS_AMOUNT, FMT(prefix, ".balanceDiff")),
        newBalance(pb, balance, balanceDiff.result(), NUM_BITS_AMOUNT, FMT(prefix, ".newBalance"))
    {
    }

    ApplyInterestGadget(
        ProtoboardT& pb,
        const Constants& constants,
        const BalanceGadget& balance,
        const VariableT& index,
        const std::string& prefix
    ) :
        ApplyInterestGadget(pb, constants, balance.balance, balance.index, index, prefix)
    {
    }

    void generate_r1cs_witness()
    {
        indexDiff.generate_r1cs_witness();
        balanceDiff.generate_r1cs_witness();
        newBalance.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        indexDiff.generate_r1cs_constraints();
        balanceDiff.generate_r1cs_constraints();
        newBalance.generate_r1cs_constraints();
    }

    const VariableT result() const
    {
        return newBalance.result();
    }
};

// Calculcates the state of a user's open position
class DynamicBalanceGadget : public DynamicVariableGadget
{
public:

    const VariableT& newIndex;

    ApplyInterestGadget applyInterest;

    DynamicBalanceGadget(
        ProtoboardT& pb,
        const Constants& constants,
        const VariableT& balance,
        const VariableT& oldIndex,
        const VariableT& _index,
        const std::string& prefix
    ) :
        DynamicVariableGadget(pb, prefix),
        newIndex(_index),
        applyInterest(pb, constants, balance, oldIndex, newIndex, FMT(prefix, ".applyInterest"))
    {
        add(applyInterest.result());
        allowGeneratingWitness = false;
    }

    DynamicBalanceGadget(
        ProtoboardT& pb,
        const Constants& constants,
        const BalanceGadget& balance,
        const VariableT& _index,
        const std::string& prefix
    ) :
        DynamicBalanceGadget(pb, constants, balance.balance, balance.index, _index, prefix)
    {
    }

    DynamicBalanceGadget(
        ProtoboardT& pb,
        const Constants& constants,
        const BalanceGadget& balance,
        const BalanceGadget& _index,
        const std::string& prefix
    ) :
        DynamicBalanceGadget(pb, constants, balance, _index.index, prefix)
    {
    }

    void generate_r1cs_witness()
    {
        applyInterest.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        applyInterest.generate_r1cs_constraints();
    }

    const VariableT& balance() const
    {
        return back();
    }

    const VariableT& index() const
    {
        return newIndex;
    }
};

}

#endif
