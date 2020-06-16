#ifndef _OFFCHAINWITHDRAWALCIRCUIT_H_
#define _OFFCHAINWITHDRAWALCIRCUIT_H_

#include "Circuit.h"
#include "../Utils/Constants.h"
#include "../Utils/Data.h"
#include "../Utils/Utils.h"
#include "../Gadgets/AccountGadgets.h"

#include "ethsnarks.hpp"
#include "utils.hpp"
#include "gadgets/subadd.hpp"

using namespace ethsnarks;

namespace Loopring
{

class WithdrawCircuit : public BaseTransactionCircuit
{
public:

    // Inputs
    DualVariableGadget owner;
    DualVariableGadget accountID;
    DualVariableGadget nonce;
    DualVariableGadget tokenID;
    DualVariableGadget amount;
    DualVariableGadget feeTokenID;
    DualVariableGadget fee;
    DualVariableGadget type;

    // Signature
    Poseidon_gadget_T<8, 1, 6, 53, 7, 1> hash;

    // Balances
    DynamicVariableGadget balanceB_A;
    DynamicVariableGadget balanceA_O;

    // Type
    IsNonZero isConditional;
    UnsafeAddGadget numConditionalTransactionsAfter;
    NotGadget needsSignature;
    EqualGadget invalidWithdrawal;

    // Fee as float
    FloatGadget fFee;
    RequireAccuracyGadget requireAccuracyFee;

    // Calculate how much can be withdrawn
    MinGadget amountToWithdraw;
    TernaryGadget amountWithdrawn;
    ToBitsGadget amountWithdrawnBits;

    // Fee payment from From to the operator
    TransferGadget feePayment;

    // Calculate the new balance
    UnsafeSubGadget balance_after;

    // Increase the nonce of the user by 1
    AddGadget nonce_after;

    WithdrawCircuit(
        ProtoboardT& pb,
        const TransactionState& state,
        const std::string& prefix
    ) :
        BaseTransactionCircuit(pb, state, prefix),

        // Inputs
        owner(pb, state.accountA.account.owner, NUM_BITS_OWNER, FMT(prefix, ".owner")),
        accountID(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".accountID")),
        nonce(pb, state.accountA.account.nonce, NUM_BITS_NONCE, FMT(prefix, ".nonce")),
        tokenID(pb, NUM_BITS_TOKEN, FMT(prefix, ".tokenID")),
        amount(pb, NUM_BITS_AMOUNT, FMT(prefix, ".amount")),
        feeTokenID(pb, NUM_BITS_TOKEN, FMT(prefix, ".feeTokenID")),
        fee(pb, NUM_BITS_AMOUNT, FMT(prefix, ".fee")),
        type(pb, NUM_BITS_TYPE, FMT(prefix, ".type")),

        // Signature
        hash(pb, var_array({
            state.exchangeID,
            accountID.packed,
            tokenID.packed,
            amount.packed,
            feeTokenID.packed,
            fee.packed,
            state.accountA.account.nonce
        }), FMT(this->annotation_prefix, ".hash")),

        balanceB_A(pb, state.accountA.balanceB.balance, FMT(prefix, ".balanceB_A")),
        balanceA_O(pb, state.oper.balanceA.balance, FMT(prefix, ".balanceA_O")),

        // Type
        isConditional(pb, type.packed, ".isConditional"),
        numConditionalTransactionsAfter(pb, state.numConditionalTransactions, state.constants.one, ".numConditionalTransactionsAfter"),
        needsSignature(pb, isConditional.result(), ".needsSignature"),
        invalidWithdrawal(pb, type.packed, state.constants.two, ".invalidWithdrawal"),

        // Calculate how much can be withdrawn
        amountToWithdraw(pb, amount.packed, state.accountA.balanceS.balance, NUM_BITS_AMOUNT, FMT(prefix, ".min(amountRequested, balance)")),
        amountWithdrawn(pb, invalidWithdrawal.result(), state.constants.zero, amountToWithdraw.result(), FMT(prefix, ".min(amountRequested, balance)")),
        amountWithdrawnBits(pb, amountWithdrawn.result(), NUM_BITS_AMOUNT, FMT(prefix, ".amountWithdrawnBits")),

        // Fee as float
        fFee(pb, state.constants, Float16Encoding, FMT(prefix, ".fFee")),
        requireAccuracyFee(pb, fFee.value(), fee.packed, Float16Accuracy, NUM_BITS_AMOUNT, FMT(prefix, ".requireAccuracyFee")),

        // Fee payment from From to the operator
        feePayment(pb, balanceB_A, balanceA_O, fFee.value(), FMT(prefix, ".feePayment")),

        // Calculate the new balance
        balance_after(pb, state.accountA.balanceS.balance, amountWithdrawn.result(), FMT(prefix, ".balance_after")),

        // Increase the nonce of From by 1 (unless it's a conditional transfer)
        nonce_after(pb, state.accountA.account.nonce, state.constants.one, NUM_BITS_NONCE, FMT(prefix, ".nonce_From_after"))
    {
        setArrayOutput(accountA_Address, accountID.bits);
        setOutput(accountA_Nonce, nonce_after.result());

        setArrayOutput(balanceA_S_Address, tokenID.bits);
        setOutput(balanceA_S_Balance, balance_after.result());
        setArrayOutput(balanceA_B_Address, feeTokenID.bits);
        setOutput(balanceA_B_Balance, balanceB_A.back());

        setOutput(balanceO_A_Balance, balanceA_O.back());

        setOutput(hash_A, hash.result());

        setOutput(signatureRequired_A, needsSignature.result());
        setOutput(signatureRequired_B, state.constants.zero);

        setOutput(misc_NumConditionalTransactions, numConditionalTransactionsAfter.result());
    }

    void generate_r1cs_witness(const OffchainWithdrawal& withdrawal)
    {
        // Inputs
        owner.generate_r1cs_witness();
        accountID.generate_r1cs_witness(pb, withdrawal.accountID);
        nonce.generate_r1cs_witness();
        tokenID.generate_r1cs_witness(pb, withdrawal.tokenID);
        amount.generate_r1cs_witness(pb, withdrawal.amount);
        feeTokenID.generate_r1cs_witness(pb, withdrawal.feeTokenID);
        fee.generate_r1cs_witness(pb, withdrawal.fee);
        type.generate_r1cs_witness(pb, withdrawal.type);
        // Signature
        hash.generate_r1cs_witness();

        // Type
        isConditional.generate_r1cs_witness();
        numConditionalTransactionsAfter.generate_r1cs_witness();
        //pb.val(numConditionalTransactionsAfter.sum) = transfer.numConditionalTransactionsAfter;
        needsSignature.generate_r1cs_witness();
        invalidWithdrawal.generate_r1cs_witness();

        // Calculate how much can be withdrawn
        amountToWithdraw.generate_r1cs_witness();
        amountWithdrawn.generate_r1cs_witness();
        amountWithdrawnBits.generate_r1cs_witness();

        // Fee as float
        fFee.generate_r1cs_witness(toFloat(withdrawal.fee, Float16Encoding));
        requireAccuracyFee.generate_r1cs_witness();

        // Fee payment from From to the operator
        feePayment.generate_r1cs_witness();

        // Calculate the new balance
        balance_after.generate_r1cs_witness();

        // Increase the nonce of From by 1
        nonce_after.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        // Inputs
        owner.generate_r1cs_constraints(true);
        accountID.generate_r1cs_constraints(true);
        nonce.generate_r1cs_constraints();
        tokenID.generate_r1cs_constraints(true);
        amount.generate_r1cs_constraints(true);
        feeTokenID.generate_r1cs_constraints(true);
        fee.generate_r1cs_constraints(true);
        type.generate_r1cs_constraints(true);

        // Signature
        hash.generate_r1cs_constraints();

        // Type
        isConditional.generate_r1cs_constraints();
        numConditionalTransactionsAfter.generate_r1cs_constraints();
        needsSignature.generate_r1cs_constraints();
        invalidWithdrawal.generate_r1cs_constraints();

        // Calculate how much can be withdrawn
        amountToWithdraw.generate_r1cs_constraints();
        amountWithdrawn.generate_r1cs_constraints();
        amountWithdrawnBits.generate_r1cs_constraints();

        // Fee as float
        fFee.generate_r1cs_constraints();
        requireAccuracyFee.generate_r1cs_constraints();

        // Fee payment from From to the operator
        feePayment.generate_r1cs_constraints();

        // Calculate the new balance
        balance_after.generate_r1cs_constraints();

        // Increase the nonce of From by 1
        nonce_after.generate_r1cs_constraints();
    }

    const VariableArrayT getPublicData() const
    {
        return flattenReverse({
            type.bits,
            owner.bits,
            accountID.bits,
            nonce.bits,
            tokenID.bits,
            feeTokenID.bits,
            amountWithdrawnBits.result(),
            fFee.bits(),
            amount.bits
        });
    }
};


}

#endif
