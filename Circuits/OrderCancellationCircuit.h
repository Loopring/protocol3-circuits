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

    const Constants& constants;

    const jubjub::VariablePointT publicKey;
    const jubjub::VariablePointT walletPublicKey;

    libsnark::dual_variable_gadget<FieldT> accountID;
    libsnark::dual_variable_gadget<FieldT> orderTokenID;
    libsnark::dual_variable_gadget<FieldT> orderID;
    libsnark::dual_variable_gadget<FieldT> walletAccountID;
    libsnark::dual_variable_gadget<FieldT> feeTokenID;
    libsnark::dual_variable_gadget<FieldT> fee;
    FloatGadget fFee;
    EnsureAccuracyGadget ensureAccuracyFee;
    PercentageGadget walletSplitPercentage;

    VariableT filled;
    VariableT cancelled_before;
    VariableT cancelled_after;
    VariableT orderID_before;

    VariableT balanceT_A;
    VariableT tradingHistoryRootT_A_before;

    VariableT balanceF_A_before;
    VariableT tradingHistoryRootF_A;

    VariableT balancesRoot_W_before;
    VariableT balanceF_W_before;
    VariableT nonce_W;
    VariableT tradingHistoryRootF_W;

    VariableT balanceF_O_before;
    VariableT tradingHistoryRootF_O;

    libsnark::dual_variable_gadget<FieldT> nonce_before;
    UnsafeAddGadget nonce_after;
    VariableT balancesRoot_before;

    MulDivGadget feeToWallet;
    UnsafeSubGadget feeToOperator;

    subadd_gadget feePaymentWallet;
    subadd_gadget feePaymentOperator;

    UpdateTradeHistoryGadget updateTradeHistory_A;
    UpdateBalanceGadget updateBalanceT_A;
    UpdateBalanceGadget updateBalanceF_A;
    UpdateAccountGadget updateAccount_A;

    UpdateBalanceGadget updateBalanceF_W;
    UpdateAccountGadget updateAccount_W;

    UpdateBalanceGadget updateBalanceF_O;

    ForceLeqGadget checkOrderID;

    Poseidon_gadget_T<11, 1, 6, 53, 9, 1> hash;
    SignatureVerifier signatureVerifier;

    OrderCancellationGadget(
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

        publicKey(pb, FMT(prefix, ".publicKey")),
        walletPublicKey(pb, FMT(prefix, ".walletPublicKey")),

        accountID(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".accountID")),
        orderTokenID(pb, NUM_BITS_TOKEN, FMT(prefix, ".orderTokenID")),
        orderID(pb, NUM_BITS_ORDERID, FMT(prefix, ".orderID")),
        walletAccountID(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".walletAccountID")),
        feeTokenID(pb, NUM_BITS_TOKEN, FMT(prefix, ".feeTokenID")),
        fee(pb, NUM_BITS_AMOUNT, FMT(prefix, ".fee")),
        fFee(pb, constants, Float16Encoding, FMT(prefix, ".fFee")),
        walletSplitPercentage(pb, constants, FMT(prefix, ".walletSplitPercentage")),

        ensureAccuracyFee(pb, fFee.value(), fee.packed, Float16Accuracy, FMT(prefix, ".ensureAccuracyFee")),

        filled(make_variable(pb, 0, FMT(prefix, ".filled"))),
        cancelled_before(make_variable(pb, 0, FMT(prefix, ".cancelled_before"))),
        orderID_before(make_variable(pb, 0, FMT(prefix, ".orderID_before"))),

        balanceT_A(make_variable(pb, FMT(prefix, ".balanceT_A"))),
        tradingHistoryRootT_A_before(make_variable(pb, FMT(prefix, ".tradingHistoryRootT_A_before"))),

        balanceF_A_before(make_variable(pb, FMT(prefix, ".balanceF_A_before"))),
        tradingHistoryRootF_A(make_variable(pb, FMT(prefix, ".tradingHistoryRootF_A"))),

        balancesRoot_W_before(make_variable(pb, FMT(prefix, ".balancesRoot_W_before"))),
        balanceF_W_before(make_variable(pb, FMT(prefix, ".balanceF_W_before"))),
        nonce_W(make_variable(pb, FMT(prefix, ".nonce_W"))),
        tradingHistoryRootF_W(make_variable(pb, FMT(prefix, ".tradingHistoryRootF_W"))),

        balanceF_O_before(make_variable(pb, FMT(prefix, ".balanceF_O_before"))),
        tradingHistoryRootF_O(make_variable(pb, FMT(prefix, ".tradingHistoryRootF_O"))),

        nonce_before(pb, NUM_BITS_NONCE, FMT(prefix, ".nonce_before")),
        // Increase nonce by 1
        nonce_after(pb, nonce_before.packed, constants.one, FMT(prefix, ".nonce_after")),
        balancesRoot_before(make_variable(pb, FMT(prefix, ".balancesRoot_before"))),

        // Fee payment calculations
        feeToWallet(pb, constants, fFee.value(), walletSplitPercentage.value.packed, constants._100, FMT(prefix, ".feeToWallet")),
        feeToOperator(pb, fFee.value(), feeToWallet.result(), FMT(prefix, ".feeToOperator")),
        // Calculate the balances after fee payment of the wallet and operator
        feePaymentWallet(pb, NUM_BITS_AMOUNT, balanceF_A_before, balanceF_W_before, feeToWallet.result(), FMT(prefix, ".feePaymentWallet")),
        feePaymentOperator(pb, NUM_BITS_AMOUNT, feePaymentWallet.X, balanceF_O_before, feeToOperator.result(), FMT(prefix, ".feePaymentOperator")),

        // Trade history
        updateTradeHistory_A(pb, tradingHistoryRootT_A_before, subArray(orderID.bits, 0, NUM_BITS_TRADING_HISTORY),
                             {filled, cancelled_before, orderID_before},
                             {filled, constants.one, orderID.packed},
                             FMT(prefix, ".updateTradeHistory_A")),
        // Balance
        updateBalanceT_A(pb, balancesRoot_before, orderTokenID.bits,
                         {balanceT_A, tradingHistoryRootT_A_before},
                         {balanceT_A, updateTradeHistory_A.getNewRoot()},
                         FMT(prefix, ".updateBalanceT_A")),
        // Balance Fee
        updateBalanceF_A(pb, updateBalanceT_A.getNewRoot(), feeTokenID.bits,
                         {balanceF_A_before, tradingHistoryRootF_A},
                         {feePaymentOperator.X, tradingHistoryRootF_A},
                         FMT(prefix, ".updateBalanceF_A")),
        // Account
        updateAccount_A(pb, _accountsMerkleRoot, accountID.bits,
                        {publicKey.x, publicKey.y, nonce_before.packed, balancesRoot_before},
                        {publicKey.x, publicKey.y, nonce_after.result(), updateBalanceF_A.getNewRoot()},
                        FMT(prefix, ".updateAccount_A")),


        // Wallet balance
        updateBalanceF_W(pb, balancesRoot_W_before, feeTokenID.bits,
                         {balanceF_W_before, tradingHistoryRootF_W},
                         {feePaymentWallet.Y, tradingHistoryRootF_W},
                         FMT(prefix, ".updateBalanceF_W")),
        // Wallet account
        updateAccount_W(pb, updateAccount_A.result(), walletAccountID.bits,
                        {walletPublicKey.x, walletPublicKey.y, nonce_W, balancesRoot_W_before},
                        {walletPublicKey.x, walletPublicKey.y, nonce_W, updateBalanceF_W.getNewRoot()},
                        FMT(prefix, ".updateAccount_W")),

        // Operator balance
        updateBalanceF_O(pb, _operatorBalancesRoot, feeTokenID.bits,
                         {balanceF_O_before, tradingHistoryRootF_O},
                         {feePaymentOperator.Y, tradingHistoryRootF_O},
                         FMT(prefix, ".updateBalanceF_O")),

        // OrderID check
        checkOrderID(pb, orderID_before, orderID.packed, NUM_BITS_ORDERID, FMT(prefix, ".checkOrderID")),

         // Signature
        hash(pb, var_array({
            blockExchangeID,
            accountID.packed,
            orderTokenID.packed,
            orderID.packed,
            walletAccountID.packed,
            feeTokenID.packed,
            fee.packed,
            walletSplitPercentage.value.packed,
            nonce_before.packed
        }), FMT(this->annotation_prefix, ".hash")),
        signatureVerifier(pb, params, publicKey, hash.result(), FMT(prefix, ".signatureVerifier"))
    {

    }

    const VariableT getNewAccountsRoot() const
    {
        return updateAccount_W.result();
    }

    const VariableT getNewOperatorBalancesRoot() const
    {
        return updateBalanceF_O.getNewRoot();
    }

    const std::vector<VariableArrayT> getPublicData() const
    {
        return {accountID.bits,
                walletAccountID.bits,
                orderTokenID.bits,
                constants.accountPadding, orderID.bits,
                feeTokenID.bits,
                fFee.bits(),
                constants.padding_0, walletSplitPercentage.value.bits};
    }

    void generate_r1cs_witness(const Cancellation& cancellation)
    {
        pb.val(publicKey.x) = cancellation.accountUpdate_A.before.publicKey.x;
        pb.val(publicKey.y) = cancellation.accountUpdate_A.before.publicKey.y;
        pb.val(walletPublicKey.x) = cancellation.accountUpdate_W.before.publicKey.x;
        pb.val(walletPublicKey.y) = cancellation.accountUpdate_W.before.publicKey.y;

        accountID.bits.fill_with_bits_of_field_element(pb, cancellation.accountUpdate_A.accountID);
        accountID.generate_r1cs_witness_from_bits();
        orderTokenID.bits.fill_with_bits_of_field_element(pb, cancellation.balanceUpdateT_A.tokenID);
        orderTokenID.generate_r1cs_witness_from_bits();
        orderID.bits.fill_with_bits_of_field_element(pb, cancellation.tradeHistoryUpdate_A.orderID);
        orderID.generate_r1cs_witness_from_bits();
        walletAccountID.bits.fill_with_bits_of_field_element(pb, cancellation.accountUpdate_W.accountID);
        walletAccountID.generate_r1cs_witness_from_bits();
        feeTokenID.bits.fill_with_bits_of_field_element(pb, cancellation.balanceUpdateF_A.tokenID);
        feeTokenID.generate_r1cs_witness_from_bits();
        fee.bits.fill_with_bits_of_field_element(pb, cancellation.fee);
        fee.generate_r1cs_witness_from_bits();
        fFee.generate_r1cs_witness(toFloat(cancellation.fee, Float16Encoding));
        ensureAccuracyFee.generate_r1cs_witness();
        walletSplitPercentage.generate_r1cs_witness(cancellation.walletSplitPercentage);

        pb.val(filled) = cancellation.tradeHistoryUpdate_A.before.filled;
        pb.val(cancelled_before) = cancellation.tradeHistoryUpdate_A.before.cancelled;
        pb.val(orderID_before) = cancellation.tradeHistoryUpdate_A.before.orderID;

        pb.val(balanceT_A) = cancellation.balanceUpdateT_A.before.balance;
        pb.val(tradingHistoryRootT_A_before) = cancellation.balanceUpdateT_A.before.tradingHistoryRoot;

        pb.val(balanceF_A_before) = cancellation.balanceUpdateF_A.before.balance;
        pb.val(tradingHistoryRootF_A) = cancellation.balanceUpdateF_A.before.tradingHistoryRoot;

        pb.val(balancesRoot_W_before) = cancellation.accountUpdate_W.before.balancesRoot;
        pb.val(balanceF_W_before) = cancellation.balanceUpdateF_W.before.balance;
        pb.val(nonce_W) = cancellation.accountUpdate_W.before.nonce;
        pb.val(tradingHistoryRootF_W) = cancellation.balanceUpdateF_W.before.tradingHistoryRoot;

        pb.val(balanceF_O_before) = cancellation.balanceUpdateF_O.before.balance;
        pb.val(tradingHistoryRootF_O) = cancellation.balanceUpdateF_O.before.tradingHistoryRoot;

        nonce_before.bits.fill_with_bits_of_field_element(pb, cancellation.accountUpdate_A.before.nonce);
        nonce_before.generate_r1cs_witness_from_bits();
        nonce_after.generate_r1cs_witness();
        pb.val(balancesRoot_before) = cancellation.accountUpdate_A.before.balancesRoot;

        feeToWallet.generate_r1cs_witness();
        feeToOperator.generate_r1cs_witness();

        feePaymentWallet.generate_r1cs_witness();
        feePaymentOperator.generate_r1cs_witness();

        updateTradeHistory_A.generate_r1cs_witness(cancellation.tradeHistoryUpdate_A.proof);
        updateBalanceT_A.generate_r1cs_witness(cancellation.balanceUpdateT_A.proof);
        updateBalanceF_A.generate_r1cs_witness(cancellation.balanceUpdateF_A.proof);
        updateAccount_A.generate_r1cs_witness(cancellation.accountUpdate_A.proof);

        updateBalanceF_W.generate_r1cs_witness(cancellation.balanceUpdateF_W.proof);
        updateAccount_W.generate_r1cs_witness(cancellation.accountUpdate_W.proof);

        updateBalanceF_O.generate_r1cs_witness(cancellation.balanceUpdateF_O.proof);

        checkOrderID.generate_r1cs_witness();

        // Check signature
        hash.generate_r1cs_witness();
        signatureVerifier.generate_r1cs_witness(cancellation.signature);
    }

    void generate_r1cs_constraints()
    {
        fee.generate_r1cs_constraints(true);
        fFee.generate_r1cs_constraints();
        ensureAccuracyFee.generate_r1cs_constraints();
        nonce_before.generate_r1cs_constraints(true);
        nonce_after.generate_r1cs_constraints();
        walletSplitPercentage.generate_r1cs_constraints();

        // Fee payment calculations
        feeToWallet.generate_r1cs_constraints();
        feeToOperator.generate_r1cs_constraints();
        feePaymentWallet.generate_r1cs_constraints();
        feePaymentOperator.generate_r1cs_constraints();

        // Account
        updateTradeHistory_A.generate_r1cs_constraints();
        updateBalanceT_A.generate_r1cs_constraints();
        updateBalanceF_A.generate_r1cs_constraints();
        updateAccount_A.generate_r1cs_constraints();

        // Wallet
        updateBalanceF_W.generate_r1cs_constraints();
        updateAccount_W.generate_r1cs_constraints();

        // Operator
        updateBalanceF_O.generate_r1cs_constraints();

        checkOrderID.generate_r1cs_constraints();

        // Check signature
        hash.generate_r1cs_constraints();
        signatureVerifier.generate_r1cs_constraints();
    }
};

class OrderCancellationCircuit : public GadgetT
{
public:
    jubjub::Params params;

    bool onchainDataAvailability;
    unsigned int numCancels;
    std::vector<OrderCancellationGadget> cancels;

    PublicDataGadget publicData;

    Constants constants;

    libsnark::dual_variable_gadget<FieldT> exchangeID;
    libsnark::dual_variable_gadget<FieldT> merkleRootBefore;
    libsnark::dual_variable_gadget<FieldT> merkleRootAfter;

    libsnark::dual_variable_gadget<FieldT> operatorAccountID;
    const jubjub::VariablePointT publicKey;
    VariableT nonce;
    VariableT balancesRoot_before;
    std::unique_ptr<UpdateAccountGadget> updateAccount_O;

    OrderCancellationCircuit(ProtoboardT& pb, const std::string& prefix) :
        GadgetT(pb, prefix),

        publicData(pb, FMT(prefix, ".publicData")),

        constants(pb, FMT(prefix, ".constants")),

        exchangeID(pb, 32, FMT(prefix, ".exchangeID")),
        merkleRootBefore(pb, 256, FMT(prefix, ".merkleRootBefore")),
        merkleRootAfter(pb, 256, FMT(prefix, ".merkleRootAfter")),

        operatorAccountID(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".operatorAccountID")),
        publicKey(pb, FMT(prefix, ".publicKey")),
        nonce(make_variable(pb, 0, FMT(prefix, ".nonce"))),
        balancesRoot_before(make_variable(pb, 0, FMT(prefix, ".balancesRoot_before")))
    {

    }

    void generate_r1cs_constraints(bool onchainDataAvailability, int numCancels)
    {
        this->onchainDataAvailability = onchainDataAvailability;
        this->numCancels = numCancels;

        constants.generate_r1cs_constraints();

        publicData.add(exchangeID.bits);
        publicData.add(merkleRootBefore.bits);
        publicData.add(merkleRootAfter.bits);
        if (onchainDataAvailability)
        {
            publicData.add(constants.accountPadding);
            publicData.add(operatorAccountID.bits);
        }
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

            if (onchainDataAvailability)
            {
                // Store data from cancellation
                std::vector<VariableArrayT> ringPublicData = cancels.back().getPublicData();
                publicData.add(cancels.back().getPublicData());
            }
        }

        // Update operator account
        operatorAccountID.generate_r1cs_constraints(true);
        updateAccount_O.reset(new UpdateAccountGadget(pb, cancels.back().getNewAccountsRoot(), operatorAccountID.bits,
                {publicKey.x, publicKey.y, nonce, balancesRoot_before},
                {publicKey.x, publicKey.y, nonce, cancels.back().getNewOperatorBalancesRoot()},
                FMT(annotation_prefix, ".updateAccount_O")));
        updateAccount_O->generate_r1cs_constraints();

        // Check the input hash
        publicData.generate_r1cs_constraints();

        // Check the new merkle root
        forceEqual(pb, updateAccount_O->result(), merkleRootAfter.packed, "newMerkleRoot");
    }

    void printInfo()
    {
        std::cout << pb.num_constraints() << " constraints (" << (pb.num_constraints() / numCancels) << "/cancel)" << std::endl;
    }

    bool generateWitness(const Loopring::OrderCancellationBlock& block)
    {
        constants.generate_r1cs_witness();

        exchangeID.bits.fill_with_bits_of_field_element(pb, block.exchangeID);
        exchangeID.generate_r1cs_witness_from_bits();

        merkleRootBefore.bits.fill_with_bits_of_field_element(pb, block.merkleRootBefore);
        merkleRootBefore.generate_r1cs_witness_from_bits();
        merkleRootAfter.bits.fill_with_bits_of_field_element(pb, block.merkleRootAfter);
        merkleRootAfter.generate_r1cs_witness_from_bits();

        pb.val(balancesRoot_before) = block.accountUpdate_O.before.balancesRoot;

        for(unsigned int i = 0; i < block.cancels.size(); i++)
        {
            cancels[i].generate_r1cs_witness(block.cancels[i]);
        }

        operatorAccountID.bits.fill_with_bits_of_field_element(pb, block.operatorAccountID);
        operatorAccountID.generate_r1cs_witness_from_bits();
        pb.val(publicKey.x) = block.accountUpdate_O.before.publicKey.x;
        pb.val(publicKey.y) = block.accountUpdate_O.before.publicKey.y;
        pb.val(nonce) = block.accountUpdate_O.before.nonce;

        updateAccount_O->generate_r1cs_witness(block.accountUpdate_O.proof);

        publicData.generate_r1cs_witness();

        return true;
    }
};

}

#endif
