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
    TradeHistoryGadget tradeHistoryBefore;
    BalanceGadget balanceTBefore;
    BalanceGadget balanceFBefore;
    AccountGadget accountBefore;
    // Operator state
    BalanceGadget balanceBefore_O;

    // Inputs
    DualVariableGadget accountID;
    DualVariableGadget orderTokenID;
    DualVariableGadget orderID;
    DualVariableGadget feeTokenID;
    DualVariableGadget fee;
    VariableT label;

    // OrderID check
    LeqGadget oldOrderID_leq_newOrderID;
    RequireEqualGadget require_oldOrderID_leq_newOrderID;

    // New filled amount
    TernaryGadget filled_after;

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
        const VariableT& accountsMerkleRoot,
        const VariableT& operatorBalancesRoot,
        const VariableT& blockExchangeID,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        // User state
        tradeHistoryBefore(pb, FMT(prefix, ".tradeHistoryBefore")),
        balanceTBefore(pb, FMT(prefix, ".balanceFBefore")),
        balanceFBefore(pb, FMT(prefix, ".balanceBefore")),
        accountBefore(pb, FMT(prefix, ".accountBefore")),
        // Operator state
        balanceBefore_O(pb, FMT(prefix, ".accountBefore_O")),

        // Inputs
        accountID(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".accountID")),
        orderTokenID(pb, NUM_BITS_TOKEN, FMT(prefix, ".orderTokenID")),
        orderID(pb, NUM_BITS_ORDERID, FMT(prefix, ".orderID")),
        feeTokenID(pb, NUM_BITS_TOKEN, FMT(prefix, ".feeTokenID")),
        fee(pb, NUM_BITS_AMOUNT, FMT(prefix, ".fee")),
        label(make_variable(pb, FMT(prefix, ".label"))),

        // OrderID check
        oldOrderID_leq_newOrderID(pb, tradeHistoryBefore.orderID, orderID.packed, NUM_BITS_ORDERID, FMT(prefix, ".oldOrderID_leq_newOrderID")),
        require_oldOrderID_leq_newOrderID(pb, oldOrderID_leq_newOrderID.leq(), constants.one, FMT(prefix, ".require_oldOrderID_leq_newOrderID")),

        // Fee as float
        fFee(pb, constants, Float16Encoding, FMT(prefix, ".fFee")),
        requireAccuracyFee(pb, fFee.value(), fee.packed, Float16Accuracy, NUM_BITS_AMOUNT, FMT(prefix, ".requireAccuracyFee")),

        // New filled amount
        filled_after(pb, oldOrderID_leq_newOrderID.lt(), constants.zero, tradeHistoryBefore.filled, FMT(prefix, ".filled_after")),

        // Fee payment from the user to the operator
        feePayment(pb, NUM_BITS_AMOUNT, balanceFBefore.balance, balanceBefore_O.balance, fFee.value(), FMT(prefix, ".feePayment")),

        // Increase the nonce of the user by 1
        nonce_after(pb, accountBefore.nonce, constants.one, NUM_BITS_NONCE, FMT(prefix, ".nonce_after")),

        // Update User
        updateTradeHistory_A(pb, balanceTBefore.tradingHistory, subArray(orderID.bits, 0, NUM_BITS_TRADING_HISTORY),
                             {tradeHistoryBefore.filled, tradeHistoryBefore.cancelled, tradeHistoryBefore.orderID},
                             {filled_after.result(), constants.one, orderID.packed},
                             FMT(prefix, ".updateTradeHistory_A")),
        updateBalanceT_A(pb, accountBefore.balancesRoot, orderTokenID.bits,
                         {balanceTBefore.balance, balanceTBefore.tradingHistory},
                         {balanceTBefore.balance, updateTradeHistory_A.result()},
                         FMT(prefix, ".updateBalanceT_A")),
        updateBalanceF_A(pb, updateBalanceT_A.result(), feeTokenID.bits,
                         {balanceFBefore.balance, balanceFBefore.tradingHistory},
                         {feePayment.X, balanceFBefore.tradingHistory},
                         FMT(prefix, ".updateBalanceF_A")),
        updateAccount_A(pb, accountsMerkleRoot, accountID.bits,
                        {accountBefore.publicKey.x, accountBefore.publicKey.y, accountBefore.nonce, accountBefore.balancesRoot},
                        {accountBefore.publicKey.x, accountBefore.publicKey.y, nonce_after.result(), updateBalanceF_A.result()},
                        FMT(prefix, ".updateAccount_A")),

        // Update Operator
        updateBalanceF_O(pb, operatorBalancesRoot, feeTokenID.bits,
                         {balanceBefore_O.balance, balanceBefore_O.tradingHistory},
                         {feePayment.Y, balanceBefore_O.tradingHistory},
                         FMT(prefix, ".updateBalanceF_O")),

        // Signature
        hash(pb, var_array({
            blockExchangeID,
            accountID.packed,
            orderTokenID.packed,
            orderID.packed,
            feeTokenID.packed,
            fee.packed,
            label,
            accountBefore.nonce
        }), FMT(this->annotation_prefix, ".hash")),
        signatureVerifier(pb, params, accountBefore.publicKey, hash.result(), FMT(prefix, ".signatureVerifier"))
    {

    }

    void generate_r1cs_witness(const Cancellation& cancellation)
    {
        // User state
        tradeHistoryBefore.generate_r1cs_witness(cancellation.tradeHistoryUpdate_A.before);
        balanceTBefore.generate_r1cs_witness(cancellation.balanceUpdateT_A.before);
        balanceFBefore.generate_r1cs_witness(cancellation.balanceUpdateF_A.before);
        accountBefore.generate_r1cs_witness(cancellation.accountUpdate_A.before);
        // Operator state
        balanceBefore_O.generate_r1cs_witness(cancellation.balanceUpdateF_O.before);

        // Inputs
        accountID.generate_r1cs_witness(pb, cancellation.accountUpdate_A.accountID);
        orderTokenID.generate_r1cs_witness(pb, cancellation.balanceUpdateT_A.tokenID);
        orderID.generate_r1cs_witness(pb, cancellation.tradeHistoryUpdate_A.orderID);
        feeTokenID.generate_r1cs_witness(pb, cancellation.balanceUpdateF_A.tokenID);
        fee.generate_r1cs_witness(pb, cancellation.fee);
        pb.val(label) = cancellation.label;

        // OrderID check
        oldOrderID_leq_newOrderID.generate_r1cs_witness();
        require_oldOrderID_leq_newOrderID.generate_r1cs_witness();

        // New filled amount
        filled_after.generate_r1cs_witness();

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
        // label has no limit

        // OrderID check
        oldOrderID_leq_newOrderID.generate_r1cs_constraints();
        require_oldOrderID_leq_newOrderID.generate_r1cs_constraints();

        // New filled amount
        filled_after.generate_r1cs_constraints();

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
    AccountGadget accountBefore_O;

    // Inputs
    DualVariableGadget exchangeID;
    DualVariableGadget merkleRootBefore;
    DualVariableGadget merkleRootAfter;
    DualVariableGadget operatorAccountID;

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
        accountBefore_O(pb, FMT(prefix, ".accountBefore_O")),

        // Inputs
        exchangeID(pb, NUM_BITS_EXCHANGE_ID, FMT(prefix, ".exchangeID")),
        merkleRootBefore(pb, 256, FMT(prefix, ".merkleRootBefore")),
        merkleRootAfter(pb, 256, FMT(prefix, ".merkleRootAfter")),
        operatorAccountID(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".operatorAccountID")),

        // Operator account check
        publicKeyX_notZero(pb, accountBefore_O.publicKey.x, FMT(prefix, ".publicKeyX_notZero"))
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
            VariableT cancelOperatorBalancesRoot = (j == 0) ? accountBefore_O.balancesRoot : cancels.back().getNewOperatorBalancesRoot();
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
            labels.push_back(cancels.back().label);
        }

        // Update Operator
        updateAccount_O.reset(new UpdateAccountGadget(pb, cancels.back().getNewAccountsRoot(), operatorAccountID.bits,
                {accountBefore_O.publicKey.x, accountBefore_O.publicKey.y, accountBefore_O.nonce, accountBefore_O.balancesRoot},
                {accountBefore_O.publicKey.x, accountBefore_O.publicKey.y, accountBefore_O.nonce, cancels.back().getNewOperatorBalancesRoot()},
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
        accountBefore_O.generate_r1cs_witness(block.accountUpdate_O.before);

        // Inputs
        exchangeID.generate_r1cs_witness(pb, block.exchangeID);
        merkleRootBefore.generate_r1cs_witness(pb, block.merkleRootBefore);
        merkleRootAfter.generate_r1cs_witness(pb, block.merkleRootAfter);
        operatorAccountID.generate_r1cs_witness(pb, block.operatorAccountID);

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
