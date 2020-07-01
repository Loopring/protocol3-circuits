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
    DualVariableGadget to;
    DualVariableGadget type;

    // Signature
    Poseidon_gadget_T<8, 1, 6, 53, 7, 1> hash;

    // Type
    IsNonZero isConditional;
    UnsafeAddGadget numConditionalTransactionsAfter;
    NotGadget needsSignature;

    // Check how much should be withdrawn
    EqualGadget amountIsZero;
    EqualGadget amountIsFullBalance;
    EqualGadget validFullWithdrawalType;
    EqualGadget invalidFullWithdrawalType;
    IfThenRequireGadget checkValidFullWithdrawal;
    IfThenRequireGadget checkInvalidFullWithdrawal;

    // Balances
    DynamicBalanceGadget balanceB_A;
    DynamicBalanceGadget balanceA_O;
    // Fee as float
    FloatGadget fFee;
    RequireAccuracyGadget requireAccuracyFee;
    // Fee payment from From to the operator
    TransferGadget feePayment;

    // Calculate the new balance
    DynamicBalanceGadget balanceS_A;
    UnsafeSubGadget balance_after;

    // Increase the nonce of the user by 1
    OrGadget isForcedWithdrawal;
    NotGadget isNotForcedWithdrawal;
    AddGadget nonce_after;

    WithdrawCircuit(
        ProtoboardT& pb,
        const TransactionState& state,
        const std::string& prefix
    ) :
        BaseTransactionCircuit(pb, state, prefix),

        // Inputs
        owner(pb, state.accountA.account.owner, NUM_BITS_ADDRESS, FMT(prefix, ".owner")),
        accountID(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".accountID")),
        nonce(pb, state.accountA.account.nonce, NUM_BITS_NONCE, FMT(prefix, ".nonce")),
        tokenID(pb, NUM_BITS_TOKEN, FMT(prefix, ".tokenID")),
        amount(pb, NUM_BITS_AMOUNT, FMT(prefix, ".amount")),
        feeTokenID(pb, NUM_BITS_TOKEN, FMT(prefix, ".feeTokenID")),
        fee(pb, NUM_BITS_AMOUNT, FMT(prefix, ".fee")),
        to(pb, NUM_BITS_ADDRESS, FMT(prefix, ".to")),
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

        // Type
        isConditional(pb, type.packed, FMT(prefix, ".isConditional")),
        numConditionalTransactionsAfter(pb, state.numConditionalTransactions, state.constants.one, FMT(prefix, ".numConditionalTransactionsAfter")),
        needsSignature(pb, isConditional.result(), FMT(prefix, ".needsSignature")),

        // Check how much should be withdrawn
        amountIsZero(pb, amount.packed, state.constants.zero, FMT(prefix, ".amountIsZero")),
        amountIsFullBalance(pb, amount.packed, state.accountA.balanceS.balance, FMT(prefix, ".amountIsFullBalance")),
        validFullWithdrawalType(pb, type.packed, state.constants.two, FMT(prefix, ".validFullWithdrawalType")),
        invalidFullWithdrawalType(pb, type.packed, state.constants.three, FMT(prefix, ".invalidFullWithdrawalType")),
        checkValidFullWithdrawal(pb, validFullWithdrawalType.result(), amountIsFullBalance.result(), FMT(prefix, ".checkValidFullWithdrawal")),
        checkInvalidFullWithdrawal(pb, invalidFullWithdrawalType.result(), amountIsZero.result(), FMT(prefix, ".checkInvalidFullWithdrawal")),

        // Balances
        balanceB_A(pb, state.constants, state.accountA.balanceB, state.index.balanceA, FMT(prefix, ".balanceB_A")),
        balanceA_O(pb, state.constants, state.oper.balanceA, state.index.balanceA, FMT(prefix, ".balanceA_O")),
        // Fee as float
        fFee(pb, state.constants, Float16Encoding, FMT(prefix, ".fFee")),
        requireAccuracyFee(pb, fFee.value(), fee.packed, Float16Accuracy, NUM_BITS_AMOUNT, FMT(prefix, ".requireAccuracyFee")),
        // Fee payment from to the operator
        feePayment(pb, balanceB_A, balanceA_O, fFee.value(), FMT(prefix, ".feePayment")),

        // Calculate the new balance
        balanceS_A(pb, state.constants, state.accountA.balanceS, state.index.balanceB, FMT(prefix, ".balanceS_A")),
        balance_after(pb, balanceS_A.balance(), amount.packed, FMT(prefix, ".balance_after")),

        // Increase the nonce by 1 (unless it's a forced withdrawal)
        isForcedWithdrawal(pb, {validFullWithdrawalType.result(), invalidFullWithdrawalType.result()}, FMT(prefix, ".isForcedWithdrawal")),
        isNotForcedWithdrawal(pb, isForcedWithdrawal.result(), FMT(prefix, ".isNotForcedWithdrawal")),
        nonce_after(pb, state.accountA.account.nonce, isNotForcedWithdrawal.result(), NUM_BITS_NONCE, FMT(prefix, ".nonce_after"))
    {
        setArrayOutput(accountA_Address, accountID.bits);
        setOutput(accountA_Nonce, nonce_after.result());

        setArrayOutput(balanceA_S_Address, tokenID.bits);
        setOutput(balanceA_S_Balance, balance_after.result());
        setOutput(balanceA_S_Index, balanceS_A.index());
        setArrayOutput(balanceB_S_Address, feeTokenID.bits);
        setOutput(balanceA_B_Balance, balanceB_A.balance());
        setOutput(balanceA_B_Index, balanceB_A.index());

        setOutput(balanceO_A_Balance, balanceA_O.balance());
        setOutput(balanceO_A_Index, balanceA_O.index());

        setOutput(hash_A, hash.result());

        setOutput(signatureRequired_A, needsSignature.result());
        setOutput(signatureRequired_B, state.constants.zero);

        setOutput(misc_NumConditionalTransactions, numConditionalTransactionsAfter.result());
    }

    void generate_r1cs_witness(const Withdrawal& withdrawal)
    {
        // Inputs
        owner.generate_r1cs_witness();
        accountID.generate_r1cs_witness(pb, withdrawal.accountID);
        nonce.generate_r1cs_witness();
        tokenID.generate_r1cs_witness(pb, withdrawal.tokenID);
        amount.generate_r1cs_witness(pb, withdrawal.amount);
        feeTokenID.generate_r1cs_witness(pb, withdrawal.feeTokenID);
        fee.generate_r1cs_witness(pb, withdrawal.fee);
        to.generate_r1cs_witness(pb, withdrawal.to);
        type.generate_r1cs_witness(pb, withdrawal.type);

        // Signature
        hash.generate_r1cs_witness();

        // Type
        isConditional.generate_r1cs_witness();
        numConditionalTransactionsAfter.generate_r1cs_witness();
        //pb.val(numConditionalTransactionsAfter.sum) = transfer.numConditionalTransactionsAfter;
        needsSignature.generate_r1cs_witness();

        // Check how much should be withdrawn
        amountIsZero.generate_r1cs_witness();
        amountIsFullBalance.generate_r1cs_witness();
        validFullWithdrawalType.generate_r1cs_witness();
        invalidFullWithdrawalType.generate_r1cs_witness();
        checkValidFullWithdrawal.generate_r1cs_witness();
        checkInvalidFullWithdrawal.generate_r1cs_witness();

        // Balances
        balanceB_A.generate_r1cs_witness();
        balanceA_O.generate_r1cs_witness();
        // Fee as float
        fFee.generate_r1cs_witness(toFloat(withdrawal.fee, Float16Encoding));
        requireAccuracyFee.generate_r1cs_witness();
        // Fee payment from to the operator
        feePayment.generate_r1cs_witness();

        // Calculate the new balance
        balanceS_A.generate_r1cs_witness();
        balance_after.generate_r1cs_witness();

        // Increase the nonce by 1 (unless it's a forced withdrawal)
        isForcedWithdrawal.generate_r1cs_witness();
        isNotForcedWithdrawal.generate_r1cs_witness();
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
        to.generate_r1cs_constraints(true);
        type.generate_r1cs_constraints(true);

        // Signature
        hash.generate_r1cs_constraints();

        // Type
        isConditional.generate_r1cs_constraints();
        numConditionalTransactionsAfter.generate_r1cs_constraints();
        needsSignature.generate_r1cs_constraints();

        // Check how much should be withdrawn
        amountIsZero.generate_r1cs_constraints();
        amountIsFullBalance.generate_r1cs_constraints();
        validFullWithdrawalType.generate_r1cs_constraints();
        invalidFullWithdrawalType.generate_r1cs_constraints();
        checkValidFullWithdrawal.generate_r1cs_constraints();
        checkInvalidFullWithdrawal.generate_r1cs_constraints();

        // Balances
        balanceB_A.generate_r1cs_constraints();
        balanceA_O.generate_r1cs_constraints();
        // Fee as float
        fFee.generate_r1cs_constraints();
        requireAccuracyFee.generate_r1cs_constraints();
        // Fee payment from to the operator
        feePayment.generate_r1cs_constraints();

        // Calculate the new balance
        balanceS_A.generate_r1cs_constraints();
        balance_after.generate_r1cs_constraints();

        // Increase the nonce by 1 (unless it's a forced withdrawal)
        isForcedWithdrawal.generate_r1cs_constraints();
        isNotForcedWithdrawal.generate_r1cs_constraints();
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
            amount.bits,
            fFee.bits(),
            to.bits
        });
    }
};


}

#endif
