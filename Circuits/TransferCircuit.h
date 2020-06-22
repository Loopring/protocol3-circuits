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

/*
    Default: ownerTo != 0 and accountID_To != 0
    New account: ownerTo != 0 and accountID_To == 0
    Open: ownerTo == 0 and accountID_To == 0
    Invalid: ownerTo == 0 and accountID_To != 0

    // Allow the payer to use dual authoring
    if (payer_owner_To != 0) {
        require(payer_owner_To == owner_To);
        require(payer_accountID_To == payee_accountID_To);
    }
    // Allow sending to an address instead of a specific accountID.
    if (payee_accountID_To != 0) {
        require(payee_accountID_To == accountID_To);
    }
    require (owner_To != 0);
    require (accountID_To > 1);
*/
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
    DualVariableGadget validUntil;
    DualVariableGadget type;
    DualVariableGadget owner_From;
    DualVariableGadget owner_To;
    DualVariableGadget nonce;
    VariableT dualAuthorX;
    VariableT dualAuthorY;
    DualVariableGadget payer_accountID_To;
    DualVariableGadget payer_owner_To;
    DualVariableGadget payee_accountID_To;

    // Check if the inputs are valid
    EqualGadget isTransferTx;
    IsNonZero isNonZero_payer_owner_To;
    IfThenRequireEqualGadget ifrequire_payer_owner_To_eq_owner_To;
    IfThenRequireEqualGadget ifrequire_payer_accountID_To_eq_payee_accountID_To;
    IsNonZero isNonZero_payee_accountID_To;
    IfThenRequireEqualGadget ifrequire_payee_accountID_To_eq_accountID_To;
    RequireLtGadget one_lt_accountID_To;
    IfThenRequireNotEqualGadget ifrequire_NotZero_owner_To;
    RequireLtGadget requireValidUntil;

    // Fill in standard dual author key if none is given
    IsNonZero isNonZero_dualAuthorX;
    IsNonZero isNonZero_dualAuthorY;
    OrGadget isNonZero_dualAuthor;
    TernaryGadget resolvedDualAuthorX;
    TernaryGadget resolvedDualAuthorY;

    // Signature
    Poseidon_gadget_T<13, 1, 6, 53, 12, 1> hashPayer;
    Poseidon_gadget_T<13, 1, 6, 53, 12, 1> hashDual;

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
        validUntil(pb, NUM_BITS_TIMESTAMP, FMT(prefix, ".validUntil")),
        type(pb, NUM_BITS_TYPE, FMT(prefix, ".type")),
        owner_From(pb, state.accountA.account.owner, NUM_BITS_ADDRESS, FMT(prefix, ".owner_From")),
        owner_To(pb, NUM_BITS_ADDRESS, FMT(prefix, ".owner_To")),
        nonce(pb, state.accountA.account.nonce, NUM_BITS_NONCE, FMT(prefix, ".nonce")),
        dualAuthorX(make_variable(pb, FMT(prefix, ".dualAuthorX"))),
        dualAuthorY(make_variable(pb, FMT(prefix, ".dualAuthorY"))),
        payer_accountID_To(pb, NUM_BITS_ADDRESS, FMT(prefix, ".payer_accountID_To")),
        payer_owner_To(pb, NUM_BITS_ADDRESS, FMT(prefix, ".payer_owner_To")),
        payee_accountID_To(pb, NUM_BITS_ADDRESS, FMT(prefix, ".payee_accountID_To")),

        // Check if the inputs are valid
        isTransferTx(pb, state.type, state.constants.txTypeTransfer, FMT(prefix, ".isTransferTx")),
        isNonZero_payer_owner_To(pb, payer_owner_To.packed, FMT(prefix, ".isNonZero_payer_owner_To")),
        ifrequire_payer_owner_To_eq_owner_To(pb, isNonZero_payer_owner_To.result(), payer_owner_To.packed, owner_To.packed, FMT(prefix, ".ifrequire_payer_owner_To_eq_owner_To")),
        ifrequire_payer_accountID_To_eq_payee_accountID_To(pb, isNonZero_payer_owner_To.result(), payer_accountID_To.packed, accountID_To.packed, FMT(prefix, ".ifrequire_payer_accountID_To_eq_payee_accountID_To")),
        isNonZero_payee_accountID_To(pb, payee_accountID_To.packed, FMT(prefix, ".isNonZero_payee_accountID_To")),
        ifrequire_payee_accountID_To_eq_accountID_To(pb, isNonZero_payee_accountID_To.result(), payee_accountID_To.packed, accountID_To.packed, FMT(prefix, ".ifrequire_payee_accountID_To_eq_accountID_To")),
        one_lt_accountID_To(pb, state.constants.one, accountID_To.packed, NUM_BITS_ACCOUNT, FMT(prefix, ".one_lt_accountID_To")),
        ifrequire_NotZero_owner_To(pb, isTransferTx.result(), owner_To.packed, state.constants.zero, FMT(prefix, ".ifrequire_NotZero_owner_To")),
        requireValidUntil(pb, state.timestamp, validUntil.packed, NUM_BITS_TIMESTAMP, FMT(prefix, ".requireValidUntil")),

        // Fill in standard dual author key if none is given
        isNonZero_dualAuthorX(pb, dualAuthorX, FMT(prefix, ".isNonZero_dualAuthorX")),
        isNonZero_dualAuthorY(pb, dualAuthorY, FMT(prefix, ".isNonZero_dualAuthorY")),
        isNonZero_dualAuthor(pb, {isNonZero_dualAuthorX.result(), isNonZero_dualAuthorY.result()}, FMT(prefix, ".isNonZero_dualAuthor")),
        resolvedDualAuthorX(pb, isNonZero_dualAuthor.result(), dualAuthorX, state.accountA.account.publicKey.x, FMT(prefix, ".resolvedDualAuthorX")),
        resolvedDualAuthorY(pb, isNonZero_dualAuthor.result(), dualAuthorY, state.accountA.account.publicKey.y, FMT(prefix, ".resolvedDualAuthorY")),

        // Hashes
        hashPayer(pb, var_array({
            state.exchangeID,
            accountID_From.packed,
            payer_accountID_To.packed,
            tokenID.packed,
            amount.packed,
            feeTokenID.packed,
            fee.packed,
            validUntil.packed,
            payer_owner_To.packed,
            dualAuthorX,
            dualAuthorY,
            nonce.packed
        }), FMT(this->annotation_prefix, ".hashPayer")),
        hashDual(pb, var_array({
            state.exchangeID,
            accountID_From.packed,
            payee_accountID_To.packed,
            tokenID.packed,
            amount.packed,
            feeTokenID.packed,
            fee.packed,
            validUntil.packed,
            owner_To.packed,
            dualAuthorX,
            dualAuthorY,
            nonce.packed
        }), FMT(this->annotation_prefix, ".hashDual")),

        // Balances
        balanceS_A(pb, state.accountA.balanceS.balance, FMT(prefix, ".balanceS_A")),
        balanceB_A(pb, state.accountA.balanceB.balance, FMT(prefix, ".balanceB_A")),
        balanceB_B(pb, state.accountB.balanceB.balance, FMT(prefix, ".balanceB_B")),
        balanceA_O(pb, state.oper.balanceA.balance, FMT(prefix, ".balanceA_O")),

        // Owner
        ownerValid(pb, state.constants, state.accountB.account.owner, owner_To.packed, FMT(prefix, ".ownerValid")),
        //owner_delta(pb, owner_To_equal_accountID_To_owner.result(), VariableArrayT(NUM_BITS_ADDRESS, state.constants.zero), owner_To.bits, FMT(prefix, ".owner_delta")),

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

        setOutput(hash_A, hashPayer.result());

        setOutput(hash_B, hashDual.result());
        setOutput(publicKeyX_B, resolvedDualAuthorX.result());
        setOutput(publicKeyY_B, resolvedDualAuthorY.result());

        setOutput(signatureRequired_A, needsSignature.result());
        setOutput(signatureRequired_B, needsSignature.result());

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
        validUntil.generate_r1cs_witness(pb, transfer.validUntil);
        type.generate_r1cs_witness(pb, transfer.type);
        owner_From.generate_r1cs_witness();
        owner_To.generate_r1cs_witness(pb, transfer.ownerTo);
        nonce.generate_r1cs_witness();
        pb.val(dualAuthorX) = transfer.dualAuthorX;
        pb.val(dualAuthorY) = transfer.dualAuthorY;
        payer_accountID_To.generate_r1cs_witness(pb, transfer.payerAccountToID);
        payer_owner_To.generate_r1cs_witness(pb, transfer.payerOwnerTo);
        payee_accountID_To.generate_r1cs_witness(pb, transfer.payeeAccountToID);

        // Check if the inputs are valid
        isTransferTx.generate_r1cs_witness();
        isNonZero_payer_owner_To.generate_r1cs_witness();
        ifrequire_payer_owner_To_eq_owner_To.generate_r1cs_witness();
        ifrequire_payer_accountID_To_eq_payee_accountID_To.generate_r1cs_witness();
        isNonZero_payee_accountID_To.generate_r1cs_witness();
        ifrequire_payee_accountID_To_eq_accountID_To.generate_r1cs_witness();
        one_lt_accountID_To.generate_r1cs_witness();
        ifrequire_NotZero_owner_To.generate_r1cs_witness();
        requireValidUntil.generate_r1cs_witness();

        // Fill in standard dual author key if none is given
        isNonZero_dualAuthorX.generate_r1cs_witness();
        isNonZero_dualAuthorY.generate_r1cs_witness();
        isNonZero_dualAuthor.generate_r1cs_witness();
        resolvedDualAuthorX.generate_r1cs_witness();
        resolvedDualAuthorY.generate_r1cs_witness();

        // Signatures
        hashPayer.generate_r1cs_witness();
        hashDual.generate_r1cs_witness();

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

        // Check if the inputs are valid
        isTransferTx.generate_r1cs_constraints();
        isNonZero_payer_owner_To.generate_r1cs_constraints();
        ifrequire_payer_owner_To_eq_owner_To.generate_r1cs_constraints();
        ifrequire_payer_accountID_To_eq_payee_accountID_To.generate_r1cs_constraints();
        isNonZero_payee_accountID_To.generate_r1cs_constraints();
        ifrequire_payee_accountID_To_eq_accountID_To.generate_r1cs_constraints();
        one_lt_accountID_To.generate_r1cs_constraints();
        ifrequire_NotZero_owner_To.generate_r1cs_constraints();
        requireValidUntil.generate_r1cs_constraints();

        // Fill in standard dual author key if none is given
        isNonZero_dualAuthorX.generate_r1cs_constraints();
        isNonZero_dualAuthorY.generate_r1cs_constraints();
        isNonZero_dualAuthor.generate_r1cs_constraints();
        resolvedDualAuthorX.generate_r1cs_constraints();
        resolvedDualAuthorY.generate_r1cs_constraints();

        // Signature
        hashPayer.generate_r1cs_constraints();
        hashDual.generate_r1cs_constraints();

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
