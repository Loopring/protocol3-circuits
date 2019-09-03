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
    DualVariableGadget accountID_A; // from A
    DualVariableGadget accountID_B; // to B
    DualVariableGadget feeTokenID;
    DualVariableGadget fee;
    DualVariableGadget transTokenID;
    DualVariableGadget transAmount;

    VariableT label;

    // User state
    BalanceGadget balanceF_A_Before;  // A pays fee
    BalanceGadget balanceT_A_Before;  // A transfers balance
    BalanceGadget balanceT_B_Before;  // B receives balance
    AccountGadget account_A_Before;
    AccountGadget account_B_Before;

    // Operator state
    BalanceGadget balanceF_O_Before;

    // fee payment related gadgets
    FloatGadget fFee;
    RequireAccuracyGadget ensureAccuracyFee;
    subadd_gadget feePayment;

    // transfer payment related gadgets
    FloatGadget fTransAmount;
    RequireAccuracyGadget ensureAccuracyTransAmount;
    subadd_gadget transferPayment;

    // Increase the nonce of the user by 1
    AddGadget nonce_A_after;

    UpdateBalanceGadget updateBalanceF_A;
    UpdateBalanceGadget updateBalanceT_A;
    UpdateAccountGadget updateAccount_A;

    UpdateBalanceGadget updateBalanceT_B;
    UpdateAccountGadget updateAccount_B;

    UpdateBalanceGadget updateBalanceF_O;

    Poseidon_gadget_T<10, 1, 6, 53, 9, 1> hash;
    SignatureVerifier signatureVerifier;

    // constants
    const VariableArrayT& dataPadding_0000;

    InternalTransferGadget(
        ProtoboardT &pb,
        const jubjub::Params &params,
        const Constants &constants,
        const VariableT &_accountsMerkleRoot,
        const VariableT &_operatorBalancesRoot,
        const VariableT &blockExchangeID,
        const std::string &prefix)
        : GadgetT(pb, prefix),

          accountID_A(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".accountID_A")),
          accountID_B(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".accountID_B")),
          feeTokenID(pb, NUM_BITS_TOKEN, FMT(prefix, ".feeTokenID")),
          fee(pb, NUM_BITS_AMOUNT, FMT(prefix, ".fee")),
          transTokenID(pb, NUM_BITS_TOKEN, FMT(prefix, ".transTokenID")),
          transAmount(pb, NUM_BITS_AMOUNT, FMT(prefix, ".transAmount")),

          label(make_variable(pb, FMT(prefix, ".label"))),

          balanceF_A_Before(pb, FMT(prefix, "balanceF_A_Before")), // A pays fee
          balanceT_A_Before(pb, FMT(prefix, "balanceT_A_Before")),
          balanceT_B_Before(pb, FMT(prefix, "balanceT_B_Before")),
          account_A_Before(pb, FMT(prefix, "account_A_Before")),
          account_B_Before(pb, FMT(prefix, "account_B_Before")),

          balanceF_O_Before(pb, FMT(prefix, "balanceBefore_O")),

          // Fee payment to the operator
          fFee(pb, constants, Float16Encoding, FMT(prefix, ".fFee")),
          ensureAccuracyFee(pb, fFee.value(), fee.packed, Float16Accuracy, NUM_BITS_AMOUNT, FMT(prefix, ".ensureAccuracyFee")),
          feePayment(pb, NUM_BITS_AMOUNT, balanceF_A_Before.balance, balanceF_O_Before.balance, fFee.value(), FMT(prefix, ".feePayment")),

          // Calculate how much can be transferred and transfer payment from A to B
          fTransAmount(pb, constants, Float28Encoding, FMT(prefix, ".fTansAmount")),
          ensureAccuracyTransAmount(pb, fTransAmount.value(), fTransAmount.value(), Float28Accuracy, NUM_BITS_AMOUNT, FMT(prefix, ".ensureAccuracyTransAmount")),
          transferPayment(pb, NUM_BITS_AMOUNT, balanceT_A_Before.balance, balanceT_B_Before.balance, fTransAmount.value(), FMT(prefix, ".transferPayment")),

          // Increase A nonce by 1
          nonce_A_after(pb, account_A_Before.nonce, constants.one, NUM_BITS_NONCE, FMT(prefix, ".nonce_A_after")),

          // Balance
          updateBalanceF_A(pb, account_A_Before.balancesRoot, feeTokenID.bits,
                           {balanceF_A_Before.balance, balanceF_A_Before.tradingHistory},
                           {feePayment.X, balanceF_A_Before.tradingHistory},
                           FMT(prefix, ".updateBalanceF_A")),

          updateBalanceT_A(pb, updateBalanceF_A.result(), transTokenID.bits,
                           {balanceT_A_Before.balance, balanceT_A_Before.tradingHistory},
                           {transferPayment.X, balanceT_A_Before.tradingHistory},
                           FMT(prefix, ".updateBalanceT_A")),

          updateBalanceT_B(pb, account_B_Before.balancesRoot, transTokenID.bits,
                           {balanceT_B_Before.balance, balanceT_B_Before.tradingHistory},
                           {transferPayment.Y, balanceT_B_Before.tradingHistory},
                           FMT(prefix, ".updateBalanceT_B")),

          // Account
          updateAccount_A(pb, _accountsMerkleRoot, accountID_A.bits,
                          {account_A_Before.publicKey.x, account_A_Before.publicKey.y, account_A_Before.nonce, account_A_Before.balancesRoot},
                          {account_A_Before.publicKey.x, account_A_Before.publicKey.y, nonce_A_after.result(), updateBalanceT_A.result()},
                          FMT(prefix, ".updateAccount_A")),

          updateAccount_B(pb, updateAccount_A.result(), accountID_B.bits,
                          {account_B_Before.publicKey.x, account_B_Before.publicKey.y, account_B_Before.nonce, account_B_Before.balancesRoot},
                          {account_B_Before.publicKey.x, account_B_Before.publicKey.y, account_B_Before.nonce, updateBalanceT_B.result()},
                          FMT(prefix, ".updateAccount_B")),

          // Operator balance
          updateBalanceF_O(pb, _operatorBalancesRoot, transTokenID.bits,
                           {balanceF_O_Before.balance, balanceF_O_Before.tradingHistory},
                           {feePayment.Y, balanceF_O_Before.tradingHistory},
                           FMT(prefix, ".updateBalanceF_O")),

          // Signature
          hash(pb, var_array({blockExchangeID, accountID_A.packed, accountID_B.packed, transTokenID.packed, transAmount.packed, feeTokenID.packed, fee.packed, label, account_A_Before.nonce}), FMT(this->annotation_prefix, ".hash")),
          signatureVerifier(pb, params, account_A_Before.publicKey, hash.result(), FMT(prefix, ".signatureVerifier")),

          dataPadding_0000(constants.padding_0000)
    {
    }

    const VariableT getNewAccountsRoot() const
    {
        return updateAccount_B.result();
    }

    const VariableT getNewOperatorBalancesRoot() const
    {
        return updateBalanceF_O.result();
    }

    const std::vector<VariableArrayT> getPublicData() const
    {
        return {
            dataPadding_0000,
            accountID_A.bits,
            dataPadding_0000,
            accountID_B.bits,
            transTokenID.bits,
            dataPadding_0000,
            fTransAmount.bits(),
            feeTokenID.bits,
            fFee.bits()};
    }

    void generate_r1cs_witness(const InternalTransfer &interTransfer)
    {
        accountID_A.generate_r1cs_witness(pb, interTransfer.accountUpdate_A.accountID);
        accountID_B.generate_r1cs_witness(pb, interTransfer.accountUpdate_B.accountID);
        feeTokenID.generate_r1cs_witness(pb, interTransfer.balanceUpdateF_A.tokenID);
        fee.generate_r1cs_witness(pb, interTransfer.fee);
        transTokenID.generate_r1cs_witness(pb, interTransfer.balanceUpdateT_A.tokenID);
        transAmount.generate_r1cs_witness(pb, interTransfer.amount);

        pb.val(label) = interTransfer.label;

        balanceF_A_Before.generate_r1cs_witness(interTransfer.balanceUpdateF_A.before); // A pays fee
        balanceT_A_Before.generate_r1cs_witness(interTransfer.balanceUpdateT_A.before);
        balanceT_B_Before.generate_r1cs_witness(interTransfer.balanceUpdateT_B.before);
        account_A_Before.generate_r1cs_witness(interTransfer.accountUpdate_A.before);
        account_B_Before.generate_r1cs_witness(interTransfer.accountUpdate_B.before);

        balanceF_O_Before.generate_r1cs_witness(interTransfer.balanceUpdateF_O.before);

        // Fee payment calculations
        fFee.generate_r1cs_witness(toFloat(interTransfer.fee, Float16Encoding));
        ensureAccuracyFee.generate_r1cs_witness();
        feePayment.generate_r1cs_witness();

        // transfer amount calculation
        fTransAmount.generate_r1cs_witness(toFloat(interTransfer.amount, Float28Encoding));
        ensureAccuracyTransAmount.generate_r1cs_witness();
        transferPayment.generate_r1cs_witness();

        // nonce++
        nonce_A_after.generate_r1cs_witness();

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
        transAmount.generate_r1cs_constraints(true);
        feeTokenID.generate_r1cs_constraints(true);
        fee.generate_r1cs_constraints(true);

        fFee.generate_r1cs_constraints();
        ensureAccuracyFee.generate_r1cs_constraints();

        fTransAmount.generate_r1cs_constraints();
        ensureAccuracyTransAmount.generate_r1cs_constraints();

        nonce_A_after.generate_r1cs_constraints();

        // Fee payment calculations
        feePayment.generate_r1cs_constraints();
        transferPayment.generate_r1cs_constraints();

        // Account
        updateBalanceF_A.generate_r1cs_constraints();
        updateBalanceT_A.generate_r1cs_constraints();
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
    PublicDataGadget publicData;

    Constants constants;

    jubjub::Params params;

    // State
    AccountGadget accountBefore_O;

    // Inputs
    DualVariableGadget exchangeID;
    DualVariableGadget merkleRootBefore;
    DualVariableGadget merkleRootAfter;
    DualVariableGadget operatorAccountID;

    RequireNotZeroGadget publicKeyX_notZero;

    bool onchainDataAvailability;
    unsigned int numTrans;
    std::vector<InternalTransferGadget> interTransferres;

    std::unique_ptr<UpdateAccountGadget> updateAccount_O;

    std::vector<VariableT> labels;
    std::unique_ptr<LabelHasher> labelHasher;

    InternalTransferCircuit(ProtoboardT &pb, const std::string &prefix)
        : GadgetT(pb, prefix),

          publicData(pb, FMT(prefix, ".publicData")),

          constants(pb, FMT(prefix, ".constants")),

          // State
          accountBefore_O(pb, FMT(prefix, ".accountBefore_O")),

          // Inputs
          exchangeID(pb, NUM_BITS_EXCHANGE_ID, FMT(prefix, ".exchangeID")),
          merkleRootBefore(pb, 256, FMT(prefix, ".merkleRootBefore")),
          merkleRootAfter(pb, 256, FMT(prefix, ".merkleRootAfter")),
          operatorAccountID(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".operatorAccountID")),

          publicKeyX_notZero(pb, accountBefore_O.publicKey.x, FMT(prefix, ".publicKeyX_notZero"))
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
            VariableT transOperatorBalancesRoot = (j == 0) ? accountBefore_O.balancesRoot : interTransferres.back().getNewOperatorBalancesRoot();

            interTransferres.emplace_back(
                pb,
                params,
                constants,
                transAccountsRoot,
                transOperatorBalancesRoot,
                exchangeID.packed,
                std::string("transfer_") + std::to_string(j));
            interTransferres.back().generate_r1cs_constraints();
            labels.push_back(interTransferres.back().label);
        }

        // Update operator account
        operatorAccountID.generate_r1cs_constraints(true);
        updateAccount_O.reset(new UpdateAccountGadget(pb, interTransferres.back().getNewAccountsRoot(), operatorAccountID.bits,
                                                      {accountBefore_O.publicKey.x, accountBefore_O.publicKey.y, accountBefore_O.nonce, accountBefore_O.balancesRoot},
                                                      {accountBefore_O.publicKey.x, accountBefore_O.publicKey.y, accountBefore_O.nonce, interTransferres.back().getNewOperatorBalancesRoot()},
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
            publicData.add(constants.padding_0000);
            publicData.add(operatorAccountID.bits);
            for (const InternalTransferGadget &trans : interTransferres)
            {
                publicData.add(trans.getPublicData());
            }
        }

        // Check the input hash
        publicData.generate_r1cs_constraints();

        // Check the new merkle root
        requireEqual(pb, updateAccount_O->result(), merkleRootAfter.packed, "newMerkleRoot");
    }

    void printInfo()
    {
        std::cout << pb.num_constraints() << " constraints (" << (pb.num_constraints() / numTrans) << "/transfer)" << std::endl;
    }

    bool generateWitness(const Loopring::InternalTransferBlock &block)
    {
        constants.generate_r1cs_witness();

        // State
        accountBefore_O.generate_r1cs_witness(block.accountUpdate_O.before);

        exchangeID.bits.fill_with_bits_of_field_element(pb, block.exchangeID);
        exchangeID.generate_r1cs_witness_from_bits();

        merkleRootBefore.bits.fill_with_bits_of_field_element(pb, block.merkleRootBefore);
        merkleRootBefore.generate_r1cs_witness_from_bits();
        merkleRootAfter.bits.fill_with_bits_of_field_element(pb, block.merkleRootAfter);
        merkleRootAfter.generate_r1cs_witness_from_bits();

        operatorAccountID.bits.fill_with_bits_of_field_element(pb, block.operatorAccountID);
        operatorAccountID.generate_r1cs_witness_from_bits();

        publicKeyX_notZero.generate_r1cs_witness();

        for (unsigned int i = 0; i < block.interTransferres.size(); i++)
        {
            interTransferres[i].generate_r1cs_witness(block.interTransferres[i]);
        }

        updateAccount_O->generate_r1cs_witness(block.accountUpdate_O.proof);

        // Calculate the label hash
        labelHasher->generate_r1cs_witness();

        publicData.generate_r1cs_witness();

        return true;
    }
};

} // namespace Loopring

#endif
