#ifndef _PUBLICKEYUPDATECIRCUIT_H_
#define _PUBLICKEYUPDATECIRCUIT_H_

#include "Circuit.h"
#include "../Utils/Constants.h"
#include "../Utils/Data.h"

#include "ethsnarks.hpp"
#include "utils.hpp"

#include "../Gadgets/SignatureGadgets.h"

using namespace ethsnarks;

namespace Loopring
{

class PublicKeyUpdateCircuit : public BaseTransactionCircuit
{
public:

    // Inputs
    DualVariableGadget owner;
    DualVariableGadget accountID;
    DualVariableGadget nonce;
    VariableT publicKeyX;
    VariableT publicKeyY;
    DualVariableGadget walletHash;

    DualVariableGadget feeTokenID;
    DualVariableGadget fee;

    // Compress the public key
    CompressPublicKey compressPublicKey;

    // Balances
    DynamicVariableGadget balanceS_A;
    DynamicVariableGadget balanceB_O;

    // Fee as float
    FloatGadget fFee;
    RequireAccuracyGadget requireAccuracyFee;

    // Fee payment from From to the operator
    TransferGadget feePayment;

    // Increase the nonce
    AddGadget nonce_after;

    UnsafeAddGadget numConditionalTransactionsAfter;

    PublicKeyUpdateCircuit(
        ProtoboardT& pb,
        const TransactionState& state,
        const std::string& prefix
    ) :
        BaseTransactionCircuit(pb, state, prefix),

        // Inputs
        owner(pb, state.accountA.account.owner, NUM_BITS_ADDRESS, FMT(prefix, ".owner")),
        accountID(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".accountID")),
        nonce(pb, state.accountA.account.nonce, NUM_BITS_NONCE, FMT(prefix, ".nonce")),
        publicKeyX(make_variable(pb, FMT(prefix, ".publicKeyX"))),
        publicKeyY(make_variable(pb, FMT(prefix, ".publicKeyY"))),
        walletHash(pb, NUM_BITS_HASH, FMT(prefix, ".walletHash")),
        feeTokenID(pb, NUM_BITS_TOKEN, FMT(prefix, ".feeTokenID")),
        fee(pb, NUM_BITS_AMOUNT, FMT(prefix, ".fee")),

        // Compress the public key
        compressPublicKey(pb, state.params, state.constants, publicKeyX, publicKeyY, FMT(this->annotation_prefix, ".compressPublicKey")),

        // Balances
        balanceS_A(pb, state.accountA.balanceS.balance, FMT(prefix, ".balanceS_A")),
        balanceB_O(pb, state.oper.balanceB.balance, FMT(prefix, ".balanceB_O")),

        // Fee as float
        fFee(pb, state.constants, Float16Encoding, FMT(prefix, ".fFee")),
        requireAccuracyFee(pb, fFee.value(), fee.packed, Float16Accuracy, NUM_BITS_AMOUNT, FMT(prefix, ".requireAccuracyFee")),

        // Fee payment from to the operator
        feePayment(pb, balanceS_A, balanceB_O, fFee.value(), FMT(prefix, ".feePayment")),

        // Increase the nonce
        nonce_after(pb, state.accountA.account.nonce, state.constants.one, NUM_BITS_NONCE, FMT(prefix, ".nonce_after")),

        numConditionalTransactionsAfter(pb, state.numConditionalTransactions, state.constants.one, FMT(prefix, ".numConditionalTransactionsAfter"))
    {
        setArrayOutput(accountA_Address, accountID.bits);
        setOutput(accountA_PublicKeyX, publicKeyX);
        setOutput(accountA_PublicKeyY, publicKeyY);
        setOutput(accountA_WalletHash, walletHash.packed);
        setOutput(accountA_Nonce, nonce_after.result());

        setArrayOutput(balanceA_S_Address, feeTokenID.bits);
        setOutput(balanceA_S_Balance, balanceS_A.back());

        setOutput(balanceO_B_Balance, balanceB_O.back());

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
        walletHash.generate_r1cs_witness(pb, update.walletHash);
        feeTokenID.generate_r1cs_witness(pb, update.feeTokenID);
        fee.generate_r1cs_witness(pb, update.fee);

        // Compress the public key
        compressPublicKey.generate_r1cs_witness();

        // Fee as float
        fFee.generate_r1cs_witness(toFloat(update.fee, Float16Encoding));
        requireAccuracyFee.generate_r1cs_witness();

        // Fee payment from to the operator
        feePayment.generate_r1cs_witness();

        // Increase the nonce
        nonce_after.generate_r1cs_witness();

        numConditionalTransactionsAfter.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        // Inputs
        owner.generate_r1cs_constraints();
        accountID.generate_r1cs_constraints(true);
        nonce.generate_r1cs_constraints();
        walletHash.generate_r1cs_constraints();
        feeTokenID.generate_r1cs_constraints(true);
        fee.generate_r1cs_constraints(true);

        // Compress the public key
        compressPublicKey.generate_r1cs_constraints();

        // Fee as float
        fFee.generate_r1cs_constraints();
        requireAccuracyFee.generate_r1cs_constraints();

        // Fee payment from to the operator
        feePayment.generate_r1cs_constraints();

        // Increase the nonce
        nonce_after.generate_r1cs_constraints();

        numConditionalTransactionsAfter.generate_r1cs_constraints();
    }

    const VariableArrayT getPublicData() const
    {
        return flattenReverse({
            owner.bits,
            accountID.bits,
            nonce.bits,
            compressPublicKey.result(),
            walletHash.bits,
            VariableArrayT(4, state.constants.zero), feeTokenID.bits,
            fFee.bits(),
        });
    }
};

}

#endif
