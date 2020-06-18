#ifndef _PUBLICKEYUPDATECIRCUIT_H_
#define _PUBLICKEYUPDATECIRCUIT_H_

#include "Circuit.h"
#include "../Utils/Constants.h"
#include "../Utils/Data.h"

#include "ethsnarks.hpp"
#include "utils.hpp"

using namespace ethsnarks;

namespace Loopring
{
#if 0
class OwnerUpdateCircuit : public BaseTransactionCircuit
{
public:

    // Inputs
    ToBitsGadget oldOwner;
    DualVariableGadget newOwner;
    DualVariableGadget accountID;
    ToBitsGadget nonce;

    // Increase the nonce
    AddGadget nonce_after;

    UnsafeAddGadget numConditionalTransactionsAfter;

    OwnerUpdateCircuit(
        ProtoboardT& pb,
        const TransactionState& state,
        const std::string& prefix
    ) :
        BaseTransactionCircuit(pb, state, prefix),

        // Inputs
        oldOwner(pb, state.accountA.account.owner, NUM_BITS_ADDRESS, FMT(prefix, ".owner")),
        newOwner(pb, state.accountA.account.owner, NUM_BITS_ADDRESS, FMT(prefix, ".owner")),
        accountID(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".accountID")),
        nonce(pb, state.accountA.account.nonce, NUM_BITS_NONCE, FMT(prefix, ".nonce")),
        publicKeyX(make_variable(pb, FMT(prefix, ".publicKeyX"))),
        publicKeyY(make_variable(pb, FMT(prefix, ".publicKeyY"))),

        publicKeyBits(pb, publicKeyY, 256 - 1, FMT(prefix, ".publicKeyY")),
        packedBit(pb, publicKeyX, state.constants.halfP, 253, FMT(prefix, ".packedBit")),

        // Increase the nonce
        nonce_after(pb, state.accountA.account.nonce, state.constants.one, NUM_BITS_NONCE, FMT(prefix, ".nonce_after")),

        numConditionalTransactionsAfter(pb, state.numConditionalTransactions, state.constants.one, FMT(prefix, ".numConditionalTransactionsAfter"))
    {
        setArrayOutput(accountA_Address, accountID.bits);
        setOutput(accountA_PublicKeyX, publicKeyX);
        setOutput(accountA_PublicKeyY, publicKeyY);
        setOutput(accountA_Nonce, nonce_after.result());

        setOutput(signatureRequired_A, state.constants.zero);
        setOutput(signatureRequired_B, state.constants.zero);

        setOutput(misc_NumConditionalTransactions, numConditionalTransactionsAfter.result());
    }

    void generate_r1cs_witness(const PublicKeyUpdate& update)
    {
        // Inputs
        owner.generate_r1cs_witness();
        accountID.generate_r1cs_witness(pb, update.accountID);
        nonce.generate_r1cs_witness();
        pb.val(publicKeyX) = update.publicKeyX;
        pb.val(publicKeyY) = update.publicKeyY;

        publicKeyBits.generate_r1cs_witness();
        packedBit.generate_r1cs_witness();

        nonce_after.generate_r1cs_witness();

        numConditionalTransactionsAfter.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        // Inputs
        owner.generate_r1cs_constraints();
        accountID.generate_r1cs_constraints(true);
        nonce.generate_r1cs_constraints();

        publicKeyBits.generate_r1cs_constraints();
        packedBit.generate_r1cs_constraints();

        print(pb, "packedBit", packedBit.lt());

        nonce_after.generate_r1cs_constraints();

        numConditionalTransactionsAfter.generate_r1cs_constraints();
    }

    const VariableArrayT getPublicData() const
    {
        return flattenReverse({
            owner.result(),
            accountID.bits,
            nonce.result(),
            //VariableArrayT(1, packedBit.lt()), publicKeyBits.result()
            VariableArrayT(1, state.constants.zero), publicKeyBits.result()
        });
    }
};
#endif

}

#endif
