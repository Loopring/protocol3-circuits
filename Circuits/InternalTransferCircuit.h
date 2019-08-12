#ifndef _INTERNAL_TRANSFER_CIRCUIT_H_
#define _INTERNAL_TRANSFER_CIRCUIT_H_

#include "../Utils/Constants.h"
#include "../Utils/Data.h"
#include "../Utils/Utils.h"
#include "../Gadgets/AccountGadgets.h"
#include "../Gadgets/TradingHistoryGadgets.h"

#include "ethsnarks.hpp"
#include "utils.hpp"
#include "jubjub/point.hpp"

using namespace ethsnarks;

namespace Loopring
{

class InternalTransferGadget : public GadgetT
{
public:

    const Constants& constants;

    const jubjub::VariablePointT publicKeyA;
    const jubjub::VariablePointT publicKeyB;

    libsnark::dual_variable_gadget<FieldT> accountID_A; // from
    libsnark::dual_variable_gadget<FieldT> accountID_B; // to
    libsnark::dual_variable_gadget<FieldT> transTokenID;
    libsnark::dual_variable_gadget<FieldT> feeTokenID;
    libsnark::dual_variable_gadget<FieldT> transAmount;
    libsnark::dual_variable_gadget<FieldT> fee;
    libsnark::dual_variable_gadget<FieldT> label;

    FloatGadget fFee;
    FloatGadget fTransAmount;
    EnsureAccuracyGadget ensureAccuracyFee;
    EnsureAccuracyGadget ensureAccuracyTransAmount;

    VariableT balancesRoot_A_before;
    VariableT balanceF_A_before;
    VariableT balanceT_A_before;
    VariableT tradingHistoryRootT_A;

    VariableT balancesRoot_B_before;
    VariableT balanceT_B_before;
    VariableT tradingHistoryRootT_B;
    
    VariableT balanceF_O_before;
    VariableT tradingHistoryRootF_O;

    libsnark::dual_variable_gadget<FieldT> nonce_A_before;
    UnsafeAddGadget nonce_A_after;

    libsnark::dual_variable_gadget<FieldT> nonce_B_before;

    subadd_gadget feePayment;
    subadd_gadget transferPayment;

    UpdateBalanceGadget updateBalanceF_A;
    UpdateBalanceGadget updateBalanceT_A;
    UpdateAccountGadget updateAccount_A;

    UpdateBalanceGadget updateBalanceT_B;
    UpdateAccountGadget updateAccount_B;

    UpdateBalanceGadget updateBalanceF_O;

    Poseidon_gadget_T<11, 1, 6, 53, 10, 1> hash;
    SignatureVerifier signatureVerifier;

    InternalTransferGadget(
        ProtoboardT& pb,
        const jubjub::Params& params,
        const Constants& _constants,
        const VariableT& _accountsMerkleRoot,
        const VariableT& _operatorBalancesRoot,
        const VariableT& blockExchangeID,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        constants(_constants),

        publicKeyA(pb, FMT(prefix, ".publicKeyA")),
        publicKeyB(pb, FMT(prefix, ".publicKeyB")),

        accountID_A(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".accountID_A")),
        accountID_B(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".accountID_B")),

        feeTokenID(pb, NUM_BITS_TOKEN, FMT(prefix, ".feeTokenID")),
        transTokenID(pb, NUM_BITS_TOKEN, FMT(prefix, ".transTokenID")),
        fee(pb, NUM_BITS_AMOUNT, FMT(prefix, ".fee")),
        transAmount(pb, NUM_BITS_AMOUNT, FMT(prefix, ".amount")),
        label(pb, NUM_BITS_LABEL, FMT(prefix, ".label")),

        fFee(pb, constants, Float16Encoding, FMT(prefix, ".fFee")),
        fTransAmount(pb, constants, Float28Encoding, FMT(prefix, ".ftransAmount")),
        ensureAccuracyFee(pb, fFee.value(), fee.packed, Float16Accuracy, NUM_BITS_AMOUNT, FMT(prefix, ".ensureAccuracyFee")),
        ensureAccuracyTransAmount(pb, fTransAmount.value(), transAmount.packed, Float28Accuracy, NUM_BITS_AMOUNT, FMT(prefix, ".ensureAccuracyTransAmount")),

        balanceF_A_before(make_variable(pb, FMT(prefix, ".balanceF_A_before"))),
        balanceT_A_before(make_variable(pb, FMT(prefix, ".balanceT_A_before"))),
        balancesRoot_A_before(make_variable(pb, FMT(prefix, ".balancesRoot_A_before"))),

        balanceT_B_before(make_variable(pb, FMT(prefix, ".balanceT_B"))),
        balancesRoot_B_before(make_variable(pb, FMT(prefix, ".balancesRoot_B_before"))),

        balanceF_O_before(make_variable(pb, FMT(prefix, ".balanceF_O_before"))),

        nonce_A_before(pb, NUM_BITS_NONCE, FMT(prefix, ".nonce_A_before")),
        // Increase A nonce by 1
        nonce_A_after(pb, nonce_A_before.packed, constants.one, FMT(prefix, ".nonce_A_after")),

        nonce_B_before(pb, NUM_BITS_NONCE, FMT(prefix, ".nonce_B_before")),

        // Fee payment to the operator
        feePayment(pb, NUM_BITS_AMOUNT, balanceT_A_before, balanceF_O_before, fFee.value(), FMT(prefix, ".feePayment")),

        // Transfer payment from A to B
        transferPayment(pb, NUM_BITS_AMOUNT, feePayment.X, balanceT_B_before, fTransAmount.value(), FMT(prefix, ".transAmount")),

        // Balance
        updateBalanceF_A(pb, balancesRoot_A_before, feeTokenID.bits,
                         {balanceF_A_before, tradingHistoryRootT_A},
                         {feePayment.X, tradingHistoryRootT_A},
                         FMT(prefix, ".updateBalanceF_A")),

        updateBalanceT_A(pb, updateBalanceF_A.getNewRoot(), transTokenID.bits,
                         {balanceT_A_before, tradingHistoryRootT_A},
                         {transferPayment.X, tradingHistoryRootT_A},
                         FMT(prefix, ".updateBalanceT_A")),
        
        updateBalanceT_B(pb, balancesRoot_B_before, transTokenID.bits,
                         {balanceT_B_before, tradingHistoryRootT_B},
                         {transferPayment.Y, tradingHistoryRootT_B},
                         FMT(prefix, ".updateBalanceT_B")),

        // Account
        updateAccount_A(pb, _accountsMerkleRoot, accountID_A.bits,
                        {publicKeyA.x, publicKeyA.y, nonce_A_before.packed, balancesRoot_A_before},
                        {publicKeyA.x, publicKeyA.y, nonce_A_after.result(), updateBalanceT_A.getNewRoot()},
                        FMT(prefix, ".updateAccount_A")),

        updateAccount_B(pb, _accountsMerkleRoot, accountID_B.bits,
                        {publicKeyB.x, publicKeyB.y, nonce_B_before.packed, balancesRoot_B_before},
                        {publicKeyB.x, publicKeyB.y, nonce_B_before.packed, updateBalanceT_B.getNewRoot()},
                        FMT(prefix, ".updateAccount_B")),

        // Operator balance
        updateBalanceF_O(pb, _operatorBalancesRoot, transTokenID.bits,
                         {balanceF_O_before, tradingHistoryRootF_O},
                         {feePayment.Y, tradingHistoryRootF_O},
                         FMT(prefix, ".updateBalanceF_O")),

        // Signature
        hash(pb, var_array({
            blockExchangeID,
            accountID_A.packed,
            accountID_B.packed,
            transTokenID.packed,
            transAmount.packed,
            feeTokenID.packed,
            fee.packed,
            label.packed,
            nonce_A_before.packed,
            nonce_B_before.packed
        }), FMT(this->annotation_prefix, ".hash")),
        signatureVerifier(pb, params, publicKeyA, hash.result(), FMT(prefix, ".signatureVerifier"))
    {

    }

    const VariableT getNewAccountsRoot() const
    {
        return updateAccount_A.result();
    }

    const VariableT getNewOperatorBalancesRoot() const
    {
        return updateBalanceF_O.getNewRoot();
    }

    const std::vector<VariableArrayT> getPublicData() const
    {
        return {accountID_A.bits,
                accountID_B.bits,
                transTokenID.bits,
                fTransAmount.bits(),
                feeTokenID.bits,
                fFee.bits()};
    }

    void generate_r1cs_witness(const InternalTransfer& interTransfer)
    {
        pb.val(publicKeyA.x) = interTransfer.accountUpdate_A.before.publicKey.x;
        pb.val(publicKeyA.y) = interTransfer.accountUpdate_A.before.publicKey.y;

        pb.val(publicKeyB.x) = interTransfer.accountUpdate_B.before.publicKey.x;
        pb.val(publicKeyB.y) = interTransfer.accountUpdate_B.before.publicKey.y;

        accountID_A.bits.fill_with_bits_of_field_element(pb, interTransfer.accountUpdate_A.accountID);
        accountID_A.generate_r1cs_witness_from_bits();

        accountID_B.bits.fill_with_bits_of_field_element(pb, interTransfer.accountUpdate_A.accountID);
        accountID_B.generate_r1cs_witness_from_bits();        

        transTokenID.bits.fill_with_bits_of_field_element(pb, interTransfer.balanceUpdateT_A.tokenID);
        transTokenID.generate_r1cs_witness_from_bits();

        fee.bits.fill_with_bits_of_field_element(pb, interTransfer.fee);
        fee.generate_r1cs_witness_from_bits();

        transAmount.bits.fill_with_bits_of_field_element(pb, interTransfer.amount);
        transAmount.generate_r1cs_witness_from_bits();

        label.bits.fill_with_bits_of_field_element(pb, interTransfer.label);
        label.generate_r1cs_witness_from_bits();

        fFee.generate_r1cs_witness(toFloat(interTransfer.fee, Float16Encoding));
        ensureAccuracyFee.generate_r1cs_witness();

        fTransAmount.generate_r1cs_witness(toFloat(interTransfer.amount, Float28Encoding));
        ensureAccuracyTransAmount.generate_r1cs_witness();

        pb.val(balanceF_A_before) = interTransfer.balanceUpdateF_A.before.balance;
        pb.val(balanceT_A_before) = interTransfer.balanceUpdateT_A.before.balance;
        pb.val(tradingHistoryRootT_A) = interTransfer.balanceUpdateT_A.before.tradingHistoryRoot;

        pb.val(balanceT_B_before) = interTransfer.balanceUpdateT_B.before.balance;
        pb.val(tradingHistoryRootT_B) = interTransfer.balanceUpdateT_B.before.tradingHistoryRoot;

        pb.val(balanceF_O_before) = interTransfer.balanceUpdateF_O.before.balance;
        pb.val(tradingHistoryRootF_O) = interTransfer.balanceUpdateF_O.before.tradingHistoryRoot;

        nonce_A_before.bits.fill_with_bits_of_field_element(pb, interTransfer.accountUpdate_A.before.nonce);
        nonce_A_before.generate_r1cs_witness_from_bits();
        nonce_A_after.generate_r1cs_witness();
        pb.val(balancesRoot_A_before) = interTransfer.accountUpdate_A.before.balancesRoot;

        nonce_B_before.bits.fill_with_bits_of_field_element(pb, interTransfer.accountUpdate_B.before.nonce);
        nonce_B_before.generate_r1cs_witness_from_bits();
        pb.val(balancesRoot_B_before) = interTransfer.accountUpdate_B.before.balancesRoot;

        // Fee payment calculations
        feePayment.generate_r1cs_witness();
        transferPayment.generate_r1cs_witness();

        updateBalanceF_A.generate_r1cs_witness(interTransfer.balanceUpdateF_A.proof);
        updateBalanceT_A.generate_r1cs_witness(interTransfer.balanceUpdateT_A.proof);
        updateAccount_A.generate_r1cs_witness(interTransfer.accountUpdate_A.proof);

        updateBalanceT_B.generate_r1cs_witness(interTransfer.balanceUpdateT_B.proof);
        updateAccount_B.generate_r1cs_witness(interTransfer.accountUpdate_B.proof);

        updateBalanceF_O.generate_r1cs_witness(interTransfer.balanceUpdateF_O.proof);

        // Check signature
        hash.generate_r1cs_witness();
        signatureVerifier.generate_r1cs_witness(interTransfer.signature);
    }

    void generate_r1cs_constraints()
    {
        accountID_A.generate_r1cs_constraints(true);
        accountID_B.generate_r1cs_constraints(true);
        transTokenID.generate_r1cs_constraints(true);
        fee.generate_r1cs_constraints(true);
        transAmount.generate_r1cs_constraints(true);
        label.generate_r1cs_constraints(true);

        fFee.generate_r1cs_constraints();
        ensureAccuracyFee.generate_r1cs_constraints();
        
        fTransAmount.generate_r1cs_constraints();
        ensureAccuracyTransAmount.generate_r1cs_constraints();

        nonce_A_before.generate_r1cs_constraints(true);
        nonce_A_after.generate_r1cs_constraints();

        nonce_B_before.generate_r1cs_constraints(true);

        // Fee payment calculations
        feePayment.generate_r1cs_constraints();
        transferPayment.generate_r1cs_constraints();

        // Account
        updateBalanceT_A.generate_r1cs_constraints();
        updateBalanceF_A.generate_r1cs_constraints();
        updateAccount_A.generate_r1cs_constraints();

        updateBalanceT_B.generate_r1cs_constraints();
        updateAccount_B.generate_r1cs_constraints();

        // Operator
        updateBalanceF_O.generate_r1cs_constraints();

        // Check signature
        hash.generate_r1cs_constraints();
        signatureVerifier.generate_r1cs_constraints();
    }
};

class InternalTransferCircuit : public GadgetT
{
public:
    jubjub::Params params;

    bool onchainDataAvailability;
    unsigned int numTrans;
    std::vector<InternalTransferGadget> interTransferres;

    PublicDataGadget publicData;

    Constants constants;

    libsnark::dual_variable_gadget<FieldT> exchangeID;
    libsnark::dual_variable_gadget<FieldT> merkleRootBefore;
    libsnark::dual_variable_gadget<FieldT> merkleRootAfter;

    libsnark::dual_variable_gadget<FieldT> operatorAccountID;
    const jubjub::VariablePointT publicKey;
    VariableT nonce;
    VariableT balancesRoot_O_before;

    ForceNotZeroGadget publicKeyX_notZero;

    std::unique_ptr<UpdateAccountGadget> updateAccount_O;

    std::vector<VariableT> labels;
    std::unique_ptr<LabelHasher> labelHasher;

    InternalTransferCircuit(ProtoboardT& pb, const std::string& prefix) :
        GadgetT(pb, prefix),

        publicData(pb, FMT(prefix, ".publicData")),

        constants(pb, FMT(prefix, ".constants")),

        exchangeID(pb, 32, FMT(prefix, ".exchangeID")),
        merkleRootBefore(pb, 256, FMT(prefix, ".merkleRootBefore")),
        merkleRootAfter(pb, 256, FMT(prefix, ".merkleRootAfter")),

        operatorAccountID(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".operatorAccountID")),
        publicKey(pb, FMT(prefix, ".publicKey")),
        nonce(make_variable(pb, 0, FMT(prefix, ".nonce"))),
        balancesRoot_O_before(make_variable(pb, 0, FMT(prefix, ".balancesRoot_O_before"))),
        publicKeyX_notZero(pb, publicKey.x, FMT(prefix, ".publicKeyX_notZero"))
    {

    }

    void generate_r1cs_constraints(bool onchainDataAvailability, int numTrans)
    {
        this->onchainDataAvailability = onchainDataAvailability;
        this->numTrans = numTrans;

        constants.generate_r1cs_constraints();

        publicKeyX_notZero.generate_r1cs_constraints();

        for (size_t j = 0; j < numTrans; j++)
        {
            VariableT transAccountsRoot = (j == 0) ? merkleRootBefore.packed : interTransferres.back().getNewAccountsRoot();
            VariableT transOperatorBalancesRoot = (j == 0) ? balancesRoot_O_before : interTransferres.back().getNewOperatorBalancesRoot();
            interTransferres.emplace_back(
                pb,
                params,
                constants,
                transAccountsRoot,
                transOperatorBalancesRoot,
                exchangeID.packed,
                std::string("transfer_") + std::to_string(j)
            );
            interTransferres.back().generate_r1cs_constraints();
            labels.push_back(interTransferres.back().label.packed);
        }

        // Update operator account
        operatorAccountID.generate_r1cs_constraints(true);
        updateAccount_O.reset(new UpdateAccountGadget(pb, interTransferres.back().getNewAccountsRoot(), operatorAccountID.bits,
                {publicKey.x, publicKey.y, nonce, balancesRoot_O_before},
                {publicKey.x, publicKey.y, nonce, interTransferres.back().getNewOperatorBalancesRoot()},
                FMT(annotation_prefix, ".updateAccount_O")));
        updateAccount_O->generate_r1cs_constraints();

        // Calculate the label hash
        labelHasher.reset(new LabelHasher(pb, constants, labels, FMT(annotation_prefix, ".labelHash")));
        labelHasher->generate_r1cs_constraints();

        // Public data
        publicData.add(exchangeID.bits);
        publicData.add(merkleRootBefore.bits);
        publicData.add(merkleRootAfter.bits);
        publicData.add(labelHasher->result()->bits);
        if (onchainDataAvailability)
        {
            publicData.add(constants.accountPadding);
            publicData.add(operatorAccountID.bits);
            for (const InternalTransferGadget& trans : interTransferres)
            {
                publicData.add(trans.getPublicData());
            }
        }

        // Check the input hash
        publicData.generate_r1cs_constraints();

        // Check the new merkle root
        forceEqual(pb, updateAccount_O->result(), merkleRootAfter.packed, "newMerkleRoot");
    }

    void printInfo()
    {
        std::cout << pb.num_constraints() << " constraints (" << (pb.num_constraints() / numTrans) << "/transfer)" << std::endl;
    }

    bool generateWitness(const Loopring::InternalTransferBlock& block)
    {
        constants.generate_r1cs_witness();

        exchangeID.bits.fill_with_bits_of_field_element(pb, block.exchangeID);
        exchangeID.generate_r1cs_witness_from_bits();

        merkleRootBefore.bits.fill_with_bits_of_field_element(pb, block.merkleRootBefore);
        merkleRootBefore.generate_r1cs_witness_from_bits();
        merkleRootAfter.bits.fill_with_bits_of_field_element(pb, block.merkleRootAfter);
        merkleRootAfter.generate_r1cs_witness_from_bits();

        pb.val(balancesRoot_O_before) = block.accountUpdate_O.before.balancesRoot;

        for(unsigned int i = 0; i < block.interTransferres.size(); i++)
        {
            interTransferres[i].generate_r1cs_witness(block.interTransferres[i]);
        }

        operatorAccountID.bits.fill_with_bits_of_field_element(pb, block.operatorAccountID);
        operatorAccountID.generate_r1cs_witness_from_bits();
        pb.val(publicKey.x) = block.accountUpdate_O.before.publicKey.x;
        pb.val(publicKey.y) = block.accountUpdate_O.before.publicKey.y;
        pb.val(nonce) = block.accountUpdate_O.before.nonce;

        publicKeyX_notZero.generate_r1cs_witness();

        updateAccount_O->generate_r1cs_witness(block.accountUpdate_O.proof);

        // Calculate the label hash
        labelHasher->generate_r1cs_witness();

        publicData.generate_r1cs_witness();

        return true;
    }
};

}

#endif
