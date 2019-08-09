#ifndef _ORDERCANCELLATIONCIRCUIT_H_
#define _ORDERCANCELLATIONCIRCUIT_H_

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

class OrderCancellationGadget : public GadgetT
{
public:

    // User state
    const jubjub::VariablePointT publicKey;
    VariableT filled;
    VariableT cancelled_before;
    VariableT orderID_before;
    VariableT balanceT_A;
    VariableT tradingHistoryRootT_A_before;
    VariableT balanceF_A_before;
    VariableT tradingHistoryRootF_A;
    VariableT balanceF_O_before;
    VariableT tradingHistoryRootF_O;
    VariableT nonce_before;
    VariableT balancesRoot_before;

    // Inputs
    libsnark::dual_variable_gadget<FieldT> accountID;
    libsnark::dual_variable_gadget<FieldT> orderTokenID;
    libsnark::dual_variable_gadget<FieldT> orderID;
    libsnark::dual_variable_gadget<FieldT> feeTokenID;
    libsnark::dual_variable_gadget<FieldT> fee;
    libsnark::dual_variable_gadget<FieldT> label;

    // OrderID check
    RequireLeqGadget oldOrderID_leq_newOrderID;

    // Fee as float
    FloatGadget fFee;
    RequireAccuracyGadget requireAccuracyFee;

    // Fee payment from the user to the operator
    subadd_gadget feePayment;

    // Increase the nonce of the user by 1
    AddGadget nonce_after;

    // Update User
    UpdateTradeHistoryGadget updateTradeHistory_A;
    UpdateBalanceGadget updateBalanceT_A;
    UpdateBalanceGadget updateBalanceF_A;
    UpdateAccountGadget updateAccount_A;

    // Update Operator
    UpdateBalanceGadget updateBalanceF_O;

    // Signature
    Poseidon_gadget_T<9, 1, 6, 53, 8, 1> hash;
    SignatureVerifier signatureVerifier;

    OrderCancellationGadget(
        ProtoboardT& pb,
        const jubjub::Params& params,
        const Constants& constants,
        const VariableT& _accountsMerkleRoot,
        const VariableT& _operatorBalancesRoot,
        const VariableT& blockExchangeID,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        // User state
        publicKey(pb, FMT(prefix, ".publicKey")),
        filled(make_variable(pb, 0, FMT(prefix, ".filled"))),
        cancelled_before(make_variable(pb, 0, FMT(prefix, ".cancelled_before"))),
        orderID_before(make_variable(pb, 0, FMT(prefix, ".orderID_before"))),
        balanceT_A(make_variable(pb, FMT(prefix, ".balanceT_A"))),
        tradingHistoryRootT_A_before(make_variable(pb, FMT(prefix, ".tradingHistoryRootT_A_before"))),
        balanceF_A_before(make_variable(pb, FMT(prefix, ".balanceF_A_before"))),
        tradingHistoryRootF_A(make_variable(pb, FMT(prefix, ".tradingHistoryRootF_A"))),
        balanceF_O_before(make_variable(pb, FMT(prefix, ".balanceF_O_before"))),
        tradingHistoryRootF_O(make_variable(pb, FMT(prefix, ".tradingHistoryRootF_O"))),
        nonce_before(make_variable(pb, FMT(prefix, ".nonce_before"))),
        balancesRoot_before(make_variable(pb, FMT(prefix, ".balancesRoot_before"))),

        // Inputs
        accountID(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".accountID")),
        orderTokenID(pb, NUM_BITS_TOKEN, FMT(prefix, ".orderTokenID")),
        orderID(pb, NUM_BITS_ORDERID, FMT(prefix, ".orderID")),
        feeTokenID(pb, NUM_BITS_TOKEN, FMT(prefix, ".feeTokenID")),
        fee(pb, NUM_BITS_AMOUNT, FMT(prefix, ".fee")),
        label(pb, NUM_BITS_LABEL, FMT(prefix, ".label")),

        // OrderID check
        oldOrderID_leq_newOrderID(pb, orderID_before, orderID.packed, NUM_BITS_ORDERID, FMT(prefix, ".checkOrderID")),

        // Fee as float
        fFee(pb, constants, Float16Encoding, FMT(prefix, ".fFee")),
        requireAccuracyFee(pb, fFee.value(), fee.packed, Float16Accuracy, NUM_BITS_AMOUNT, FMT(prefix, ".requireAccuracyFee")),

        // Fee payment from the user to the operator
        feePayment(pb, NUM_BITS_AMOUNT, balanceF_A_before, balanceF_O_before, fFee.value(), FMT(prefix, ".feePayment")),

        // Increase the nonce of the user by 1
        nonce_after(pb, nonce_before, constants.one, NUM_BITS_NONCE, FMT(prefix, ".nonce_after")),

        // Update User
        updateTradeHistory_A(pb, tradingHistoryRootT_A_before, subArray(orderID.bits, 0, NUM_BITS_TRADING_HISTORY),
                             {filled, cancelled_before, orderID_before},
                             {filled, constants.one, orderID.packed},
                             FMT(prefix, ".updateTradeHistory_A")),
        updateBalanceT_A(pb, balancesRoot_before, orderTokenID.bits,
                         {balanceT_A, tradingHistoryRootT_A_before},
                         {balanceT_A, updateTradeHistory_A.result()},
                         FMT(prefix, ".updateBalanceT_A")),
        updateBalanceF_A(pb, updateBalanceT_A.result(), feeTokenID.bits,
                         {balanceF_A_before, tradingHistoryRootF_A},
                         {feePayment.X, tradingHistoryRootF_A},
                         FMT(prefix, ".updateBalanceF_A")),
        updateAccount_A(pb, _accountsMerkleRoot, accountID.bits,
                        {publicKey.x, publicKey.y, nonce_before, balancesRoot_before},
                        {publicKey.x, publicKey.y, nonce_after.result(), updateBalanceF_A.result()},
                        FMT(prefix, ".updateAccount_A")),

        // Update Operator
        updateBalanceF_O(pb, _operatorBalancesRoot, feeTokenID.bits,
                         {balanceF_O_before, tradingHistoryRootF_O},
                         {feePayment.Y, tradingHistoryRootF_O},
                         FMT(prefix, ".updateBalanceF_O")),

        // Signature
        hash(pb, var_array({
            blockExchangeID,
            accountID.packed,
            orderTokenID.packed,
            orderID.packed,
            feeTokenID.packed,
            fee.packed,
            label.packed,
            nonce_before
        }), FMT(this->annotation_prefix, ".hash")),
        signatureVerifier(pb, params, publicKey, hash.result(), FMT(prefix, ".signatureVerifier"))
    {

    }

    void generate_r1cs_witness(const Cancellation& cancellation)
    {
        // User state
        pb.val(publicKey.x) = cancellation.accountUpdate_A.before.publicKey.x;
        pb.val(publicKey.y) = cancellation.accountUpdate_A.before.publicKey.y;
        pb.val(filled) = cancellation.tradeHistoryUpdate_A.before.filled;
        pb.val(cancelled_before) = cancellation.tradeHistoryUpdate_A.before.cancelled;
        pb.val(orderID_before) = cancellation.tradeHistoryUpdate_A.before.orderID;
        pb.val(balanceT_A) = cancellation.balanceUpdateT_A.before.balance;
        pb.val(tradingHistoryRootT_A_before) = cancellation.balanceUpdateT_A.before.tradingHistoryRoot;
        pb.val(balanceF_A_before) = cancellation.balanceUpdateF_A.before.balance;
        pb.val(tradingHistoryRootF_A) = cancellation.balanceUpdateF_A.before.tradingHistoryRoot;
        pb.val(balanceF_O_before) = cancellation.balanceUpdateF_O.before.balance;
        pb.val(tradingHistoryRootF_O) = cancellation.balanceUpdateF_O.before.tradingHistoryRoot;
        pb.val(nonce_before) = cancellation.accountUpdate_A.before.nonce;
        pb.val(balancesRoot_before) = cancellation.accountUpdate_A.before.balancesRoot;

        // Inputs
        accountID.bits.fill_with_bits_of_field_element(pb, cancellation.accountUpdate_A.accountID);
        accountID.generate_r1cs_witness_from_bits();
        orderTokenID.bits.fill_with_bits_of_field_element(pb, cancellation.balanceUpdateT_A.tokenID);
        orderTokenID.generate_r1cs_witness_from_bits();
        orderID.bits.fill_with_bits_of_field_element(pb, cancellation.tradeHistoryUpdate_A.orderID);
        orderID.generate_r1cs_witness_from_bits();
        feeTokenID.bits.fill_with_bits_of_field_element(pb, cancellation.balanceUpdateF_A.tokenID);
        feeTokenID.generate_r1cs_witness_from_bits();
        fee.bits.fill_with_bits_of_field_element(pb, cancellation.fee);
        fee.generate_r1cs_witness_from_bits();
        label.bits.fill_with_bits_of_field_element(pb, cancellation.label);
        label.generate_r1cs_witness_from_bits();

        // OrderID check
        oldOrderID_leq_newOrderID.generate_r1cs_witness();

        // Fee as float
        fFee.generate_r1cs_witness(toFloat(cancellation.fee, Float16Encoding));
        requireAccuracyFee.generate_r1cs_witness();

        // Fee payment from the user to the operator
        feePayment.generate_r1cs_witness();

        // Increase the nonce of the user by 1
        nonce_after.generate_r1cs_witness();

        // Update User
        updateTradeHistory_A.generate_r1cs_witness(cancellation.tradeHistoryUpdate_A.proof);
        updateBalanceT_A.generate_r1cs_witness(cancellation.balanceUpdateT_A.proof);
        updateBalanceF_A.generate_r1cs_witness(cancellation.balanceUpdateF_A.proof);
        updateAccount_A.generate_r1cs_witness(cancellation.accountUpdate_A.proof);

        // Update Operator
        updateBalanceF_O.generate_r1cs_witness(cancellation.balanceUpdateF_O.proof);

        // Check signature
        hash.generate_r1cs_witness();
        signatureVerifier.generate_r1cs_witness(cancellation.signature);
    }

    void generate_r1cs_constraints()
    {
        // Inputs
        accountID.generate_r1cs_constraints(true);
        orderTokenID.generate_r1cs_constraints(true);
        orderID.generate_r1cs_constraints(true);
        feeTokenID.generate_r1cs_constraints(true);
        fee.generate_r1cs_constraints(true);
        label.generate_r1cs_constraints(true);

        // OrderID check
        oldOrderID_leq_newOrderID.generate_r1cs_constraints();

        // Fee as float
        fFee.generate_r1cs_constraints();
        requireAccuracyFee.generate_r1cs_constraints();

        // Fee payment from the user to the operator
        feePayment.generate_r1cs_constraints();

        // Increase the nonce of the user by 1
        nonce_after.generate_r1cs_constraints();

        // Update User
        updateTradeHistory_A.generate_r1cs_constraints();
        updateBalanceT_A.generate_r1cs_constraints();
        updateBalanceF_A.generate_r1cs_constraints();
        updateAccount_A.generate_r1cs_constraints();

        // Update Operator
        updateBalanceF_O.generate_r1cs_constraints();

        // Check signature
        hash.generate_r1cs_constraints();
        signatureVerifier.generate_r1cs_constraints();
    }

    const std::vector<VariableArrayT> getPublicData() const
    {
        return {accountID.bits,
                orderID.bits,
                orderTokenID.bits,
                feeTokenID.bits,
                fFee.bits()};
    }

    const VariableT getNewAccountsRoot() const
    {
        return updateAccount_A.result();
    }

    const VariableT getNewOperatorBalancesRoot() const
    {
        return updateBalanceF_O.result();
    }
};

class OrderCancellationCircuit : public GadgetT
{
public:

    PublicDataGadget publicData;
    Constants constants;
    jubjub::Params params;

    // State
    const jubjub::VariablePointT publicKey;
    VariableT nonce;
    VariableT balancesRoot_before;

    // Inputs
    libsnark::dual_variable_gadget<FieldT> exchangeID;
    libsnark::dual_variable_gadget<FieldT> merkleRootBefore;
    libsnark::dual_variable_gadget<FieldT> merkleRootAfter;
    libsnark::dual_variable_gadget<FieldT> operatorAccountID;

    // Operator account check
    RequireNotZeroGadget publicKeyX_notZero;

    // Cancels
    bool onchainDataAvailability;
    unsigned int numCancels;
    std::vector<OrderCancellationGadget> cancels;

    // Update Operator
    std::unique_ptr<UpdateAccountGadget> updateAccount_O;

    // Labels
    std::vector<VariableT> labels;
    std::unique_ptr<LabelHasher> labelHasher;

    OrderCancellationCircuit(ProtoboardT& pb, const std::string& prefix) :
        GadgetT(pb, prefix),

        publicData(pb, FMT(prefix, ".publicData")),
        constants(pb, FMT(prefix, ".constants")),

        // State
        publicKey(pb, FMT(prefix, ".publicKey")),
        nonce(make_variable(pb, 0, FMT(prefix, ".nonce"))),
        balancesRoot_before(make_variable(pb, 0, FMT(prefix, ".balancesRoot_before"))),

        // Inputs
        exchangeID(pb, NUM_BITS_EXCHANGE_ID, FMT(prefix, ".exchangeID")),
        merkleRootBefore(pb, 256, FMT(prefix, ".merkleRootBefore")),
        merkleRootAfter(pb, 256, FMT(prefix, ".merkleRootAfter")),
        operatorAccountID(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".operatorAccountID")),

        // Operator account check
        publicKeyX_notZero(pb, publicKey.x, FMT(prefix, ".publicKeyX_notZero"))
    {

    }

    void generate_r1cs_constraints(bool onchainDataAvailability, int numCancels)
    {
        this->onchainDataAvailability = onchainDataAvailability;
        this->numCancels = numCancels;

        constants.generate_r1cs_constraints();

        // Inputs
        exchangeID.generate_r1cs_constraints(true);
        merkleRootBefore.generate_r1cs_constraints(true);
        merkleRootAfter.generate_r1cs_constraints(true);
        operatorAccountID.generate_r1cs_constraints(true);

        // Operator account check
        publicKeyX_notZero.generate_r1cs_constraints();

        // Cancels
        for (size_t j = 0; j < numCancels; j++)
        {
            VariableT cancelAccountsRoot = (j == 0) ? merkleRootBefore.packed : cancels.back().getNewAccountsRoot();
            VariableT cancelOperatorBalancesRoot = (j == 0) ? balancesRoot_before : cancels.back().getNewOperatorBalancesRoot();
            cancels.emplace_back(
                pb,
                params,
                constants,
                cancelAccountsRoot,
                cancelOperatorBalancesRoot,
                exchangeID.packed,
                std::string("cancels_") + std::to_string(j)
            );
            cancels.back().generate_r1cs_constraints();
            labels.push_back(cancels.back().label.packed);
        }

        // Update Operator
        updateAccount_O.reset(new UpdateAccountGadget(pb, cancels.back().getNewAccountsRoot(), operatorAccountID.bits,
                {publicKey.x, publicKey.y, nonce, balancesRoot_before},
                {publicKey.x, publicKey.y, nonce, cancels.back().getNewOperatorBalancesRoot()},
                FMT(annotation_prefix, ".updateAccount_O")));
        updateAccount_O->generate_r1cs_constraints();

        // Labels
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
            for (const OrderCancellationGadget& cancel : cancels)
            {
                publicData.add(cancel.getPublicData());
            }
        }
        publicData.generate_r1cs_constraints();

        // Check the new merkle root
        forceEqual(pb, updateAccount_O->result(), merkleRootAfter.packed, "newMerkleRoot");
    }

    bool generateWitness(const Loopring::OrderCancellationBlock& block)
    {
        constants.generate_r1cs_witness();

        // State
        pb.val(publicKey.x) = block.accountUpdate_O.before.publicKey.x;
        pb.val(publicKey.y) = block.accountUpdate_O.before.publicKey.y;
        pb.val(nonce) = block.accountUpdate_O.before.nonce;
        pb.val(balancesRoot_before) = block.accountUpdate_O.before.balancesRoot;

        // Inputs
        exchangeID.bits.fill_with_bits_of_field_element(pb, block.exchangeID);
        exchangeID.generate_r1cs_witness_from_bits();
        merkleRootBefore.bits.fill_with_bits_of_field_element(pb, block.merkleRootBefore);
        merkleRootBefore.generate_r1cs_witness_from_bits();
        merkleRootAfter.bits.fill_with_bits_of_field_element(pb, block.merkleRootAfter);
        merkleRootAfter.generate_r1cs_witness_from_bits();
        operatorAccountID.bits.fill_with_bits_of_field_element(pb, block.operatorAccountID);
        operatorAccountID.generate_r1cs_witness_from_bits();

        // Operator account check
        publicKeyX_notZero.generate_r1cs_witness();

        // Cancels
        for(unsigned int i = 0; i < block.cancels.size(); i++)
        {
            cancels[i].generate_r1cs_witness(block.cancels[i]);
        }

        // Update Operator
        updateAccount_O->generate_r1cs_witness(block.accountUpdate_O.proof);

        // Calculate the label hash
        labelHasher->generate_r1cs_witness();

        // Public data
        publicData.generate_r1cs_witness();

        return true;
    }

    void printInfo()
    {
        std::cout << pb.num_constraints() << " constraints (" << (pb.num_constraints() / numCancels) << "/cancel)" << std::endl;
    }
};

}

#endif
