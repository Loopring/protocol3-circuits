#ifndef _INTERNAL_TRANSFER_CIRCUIT_H_
#define _INTERNAL_TRANSFER_CIRCUIT_H_

#include "Circuit.h"
#include "../Utils/Constants.h"
#include "../Utils/Data.h"
#include "../Utils/Utils.h"


#include "ethsnarks.hpp"
#include "utils.hpp"

using namespace ethsnarks;
namespace Loopring
{

class TransferCircuit : public BaseTransactionCircuit
{
public:

    // Inputs
    DualVariableGadget accountID_From;
    DualVariableGadget accountID_To;
    DualVariableGadget tokenID;
    DualVariableGadget amount;
    DualVariableGadget feeTokenID;
    DualVariableGadget fee;
    DualVariableGadget type;
    DualVariableGadget owner_From;
    DualVariableGadget owner_To;
    DualVariableGadget nonce;

    // Signature
    Poseidon_gadget_T<9, 1, 6, 53, 8, 1> hash;

    // Balances
    DynamicVariableGadget balanceS_A;
    DynamicVariableGadget balanceB_A;
    DynamicVariableGadget balanceB_B;
    DynamicVariableGadget balanceA_O;

    // Addresses
    OwnerValidGadget ownerValid;
    //ArraySelectGadget owner_delta;

    // Type
    IsNonZero isConditional;
    UnsafeAddGadget numConditionalTransactionsAfter;
    NotGadget needsSignature;

    // Fee as float
    FloatGadget fFee;
    RequireAccuracyGadget requireAccuracyFee;
    // Amount as float
    FloatGadget fAmount;
    RequireAccuracyGadget requireAccuracyAmount;

    // Fee payment from From to the operator
    TransferGadget feePayment;
    // Transfer from From to To
    TransferGadget transferPayment;

    // Increase the nonce of From by 1
    AddGadget nonce_From_after;

    TransferCircuit(
        ProtoboardT& pb,
        const TransactionState& state,
        const std::string& prefix
    ) :
        BaseTransactionCircuit(pb, state, prefix),

        // Inputs
        accountID_From(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".accountID_From")),
        accountID_To(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".accountID_To")),
        tokenID(pb, NUM_BITS_TOKEN, FMT(prefix, ".tokenID")),
        amount(pb, NUM_BITS_AMOUNT, FMT(prefix, ".amount")),
        feeTokenID(pb, NUM_BITS_TOKEN, FMT(prefix, ".feeTokenID")),
        fee(pb, NUM_BITS_AMOUNT, FMT(prefix, ".fee")),
        type(pb, NUM_BITS_TYPE, FMT(prefix, ".type")),
        owner_From(pb, state.accountA.account.owner, NUM_BITS_OWNER, FMT(prefix, ".owner_From")),
        owner_To(pb, NUM_BITS_OWNER, FMT(prefix, ".owner_To")),
        nonce(pb, state.accountA.account.nonce, NUM_BITS_NONCE, FMT(prefix, ".nonce")),

        hash(pb, var_array({
            state.exchangeID,
            accountID_From.packed,
            accountID_To.packed,
            tokenID.packed,
            amount.packed,
            feeTokenID.packed,
            fee.packed,
            nonce.packed
        }), FMT(this->annotation_prefix, ".hash")),

        // Balances
        balanceS_A(pb, state.accountA.balanceS.balance, FMT(prefix, ".balanceS_A")),
        balanceB_A(pb, state.accountA.balanceB.balance, FMT(prefix, ".balanceB_A")),
        balanceB_B(pb, state.accountB.balanceB.balance, FMT(prefix, ".balanceB_B")),
        balanceA_O(pb, state.oper.balanceA.balance, FMT(prefix, ".balanceA_O")),

        // Owner
        ownerValid(pb, state.constants, state.accountB.account.owner, owner_To.packed, FMT(prefix, ".owner_To_equal_accountID_To_owner")),
        //owner_delta(pb, owner_To_equal_accountID_To_owner.result(), VariableArrayT(NUM_BITS_OWNER, state.constants.zero), owner_To.bits, FMT(prefix, ".owner_delta")),

        // Type
        isConditional(pb, type.packed, ".isConditional"),
        numConditionalTransactionsAfter(pb, state.numConditionalTransactions, isConditional.result(), ".numConditionalTransactionsAfter"),
        needsSignature(pb, isConditional.result(), ".needsSignature"),

        // Fee as float
        fFee(pb, state.constants, Float16Encoding, FMT(prefix, ".fFee")),
        requireAccuracyFee(pb, fFee.value(), fee.packed, Float16Accuracy, NUM_BITS_AMOUNT, FMT(prefix, ".requireAccuracyFee")),
        // Amount as float
        fAmount(pb, state.constants, Float24Encoding, FMT(prefix, ".fAmount")),
        requireAccuracyAmount(pb, fAmount.value(), amount.packed, Float24Accuracy, NUM_BITS_AMOUNT, FMT(prefix, ".requireAccuracyAmount")),

        // Fee payment from From to the operator
        feePayment(pb, balanceB_A, balanceA_O, fFee.value(), FMT(prefix, ".feePayment")),
        // Transfer from From to To
        transferPayment(pb, balanceS_A, balanceB_B, fAmount.value(), FMT(prefix, ".transferPayment")),

        // Increase the nonce of From by 1 (unless it's a conditional transfer)
        nonce_From_after(pb, state.accountA.account.nonce, state.constants.one, NUM_BITS_NONCE, FMT(prefix, ".nonce_From_after"))
    {
        setArrayOutput(accountA_Address, accountID_From.bits);
        setOutput(accountA_Nonce, nonce_From_after.result());

        setArrayOutput(balanceA_S_Address, tokenID.bits);
        setOutput(balanceA_S_Balance, balanceS_A.back());
        setArrayOutput(balanceA_B_Address, feeTokenID.bits);
        setOutput(balanceA_B_Balance, balanceB_A.back());

        setArrayOutput(accountB_Address, accountID_To.bits);
        setOutput(accountB_Owner, owner_To.packed);

        setArrayOutput(balanceB_B_Address, tokenID.bits);
        setOutput(balanceB_B_Balance, balanceB_B.back());

        setOutput(balanceO_A_Balance, balanceA_O.back());

        setOutput(hash_A, hash.result());

        setOutput(signatureRequired_A, needsSignature.result());
        setOutput(signatureRequired_B, state.constants.zero);

        setOutput(misc_NumConditionalTransactions, numConditionalTransactionsAfter.result());
    }

    void generate_r1cs_witness(const Transfer& transfer)
    {
        // Inputs
        accountID_From.generate_r1cs_witness(pb, transfer.accountFromID);
        accountID_To.generate_r1cs_witness(pb, transfer.accountToID);
        tokenID.generate_r1cs_witness(pb, transfer.tokenID);
        amount.generate_r1cs_witness(pb, transfer.amount);
        feeTokenID.generate_r1cs_witness(pb, transfer.feeTokenID);
        fee.generate_r1cs_witness(pb, transfer.fee);
        type.generate_r1cs_witness(pb, transfer.type);
        owner_From.generate_r1cs_witness();
        owner_To.generate_r1cs_witness(pb, transfer.ownerTo);
        nonce.generate_r1cs_witness();

        // Signature
        hash.generate_r1cs_witness();

        // Owner
        ownerValid.generate_r1cs_witness();
        //owner_delta.generate_r1cs_witness();

        // Type
        isConditional.generate_r1cs_witness();
        numConditionalTransactionsAfter.generate_r1cs_witness();
        //pb.val(numConditionalTransactionsAfter.sum) = transfer.numConditionalTransactionsAfter;
        needsSignature.generate_r1cs_witness();

        // Fee as float
        fFee.generate_r1cs_witness(toFloat(transfer.fee, Float16Encoding));
        requireAccuracyFee.generate_r1cs_witness();
        // Amount as float
        fAmount.generate_r1cs_witness(toFloat(transfer.amount, Float24Encoding));
        requireAccuracyAmount.generate_r1cs_witness();

        // Fee payment from From to the operator
        feePayment.generate_r1cs_witness();
        // Transfer from From to To
        transferPayment.generate_r1cs_witness();

        // Increase the nonce of From by 1
        nonce_From_after.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        // Inputs
        accountID_From.generate_r1cs_constraints(true);
        accountID_To.generate_r1cs_constraints(true);
        tokenID.generate_r1cs_constraints(true);
        amount.generate_r1cs_constraints(true);
        feeTokenID.generate_r1cs_constraints(true);
        fee.generate_r1cs_constraints(true);
        type.generate_r1cs_constraints(true);
        owner_From.generate_r1cs_constraints(true);
        owner_To.generate_r1cs_constraints(true);
        nonce.generate_r1cs_constraints(true);

        // Signature
        hash.generate_r1cs_constraints();

        // Owner
        ownerValid.generate_r1cs_constraints();
        //owner_delta.generate_r1cs_constraints();

        // Type
        isConditional.generate_r1cs_constraints();
        numConditionalTransactionsAfter.generate_r1cs_constraints();
        needsSignature.generate_r1cs_constraints();

        // Fee as float
        fFee.generate_r1cs_constraints();
        requireAccuracyFee.generate_r1cs_constraints();

        // Amount as float
        fAmount.generate_r1cs_constraints();
        requireAccuracyAmount.generate_r1cs_constraints();

        // Fee payment from From to the operator
        feePayment.generate_r1cs_constraints();
        // Transfer from From to To
        transferPayment.generate_r1cs_constraints();

        // Increase the nonce of From by 1
        nonce_From_after.generate_r1cs_constraints();
    }

    const VariableArrayT getPublicData() const
    {
        return flattenReverse({
            type.bits,
            accountID_From.bits,
            accountID_To.bits,
            tokenID.bits,
            feeTokenID.bits,
            fAmount.bits(),
            fFee.bits(),
            nonce.bits,
            //owner_delta.result()
            owner_From.bits,
            owner_To.bits
        });
    }
};

} // namespace Loopring

#endif
