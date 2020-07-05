#ifndef _DATA_H_
#define _DATA_H_

#include "Constants.h"

//#include "../ThirdParty/json.hpp"
#include "ethsnarks.hpp"
#include "jubjub/point.hpp"
#include "jubjub/eddsa.hpp"

using json = nlohmann::json;


namespace Loopring
{

auto dummySpotTrade = R"({
    "fFillS_A": 0,
    "fFillS_B": 0,
    "orderA": {
        "accountID": 0,
        "allOrNone": false,
        "amountB": "79228162514264337593543950335",
        "amountS": "79228162514264337593543950335",
        "buy": true,
        "exchangeID": 0,
        "feeBips": 0,
        "maxFeeBips": 0,
        "orderID": "0",
        "rebateBips": 0,
        "tokenS": 0,
        "tokenB": 1,
        "validSince": 0,
        "validUntil": 4294967295
    },
    "orderB": {
        "accountID": 0,
        "allOrNone": false,
        "amountB": "79228162514264337593543950335",
        "amountS": "79228162514264337593543950335",
        "buy": true,
        "exchangeID": 2,
        "feeBips": 0,
        "maxFeeBips": 0,
        "orderID": "0",
        "rebateBips": 0,
        "reduceOnly": 0,
        "tokenS": 1,
        "tokenB": 0,
        "validSince": 0,
        "validUntil": 4294967295
    }
})"_json;

auto dummyTransfer = R"({
    "accountFromID": 0,
    "accountToID": 2,
    "amount": "0",
    "fee": "0",
    "feeTokenID": 0,
    "tokenID": 0,
    "validUntil": 4294967295,
    "type": 0,
    "ownerFrom": "0",
    "ownerTo": "2",
    "dualAuthorX": "0",
    "dualAuthorY": "0",
    "payerAccountToID": 2,
    "payerOwnerTo": "2",
    "payeeAccountToID": 2,
    "nonce": 0
})"_json;

auto dummyWithdraw = R"({
    "owner": "0",
    "accountID": 0,
    "tokenID": 0,
    "amount": "0",
    "feeTokenID": 0,
    "fee": "0",
    "to": "0",
    "dataHash": "0",
    "minGas": 0,
    "type": 0
})"_json;

auto dummyPublicKeyUpdate = R"({
    "owner": "0",
    "accountID": 0,
    "nonce": 0,
    "publicKeyX": "13060336632196495412858530687189935300033555341384637843571668213752389743866",
    "publicKeyY": "4915883150652842217472446614681036440072632592629277920562695676195366802174",
    "walletHash": "0",
    "feeTokenID": 0,
    "fee": "0"
})"_json;

auto dummyNewAccount = R"({
    "payerAccountID": 0,
    "feeTokenID": 0,
    "fee": "0",
    "nonce": 0,
    "newAccountID": 2,
    "newOwner": "1",
    "newPublicKeyX": "13060336632196495412858530687189935300033555341384637843571668213752389743866",
    "newPublicKeyY": "4915883150652842217472446614681036440072632592629277920562695676195366802174",
    "newWalletHash": "0"
})"_json;

auto dummyOwnerChange = R"({
    "accountID": 0,
    "feeTokenID": 0,
    "fee": "0",
    "newOwner": "0"
})"_json;

auto dummyDeposit = R"({
    "owner": "0",
    "accountID": 0,
    "tokenID": 0,
    "amount": "0",
    "index": "0"
})"_json;

auto dummySignature = R"({
    "Rx": "13060336632196495412858530687189935300033555341384637843571668213752389743866",
    "Ry": "4915883150652842217472446614681036440072632592629277920562695676195366802174",
    "s": "2049853744288428596543952232796911341686225132653835991176529722328469628710"
})"_json;

enum class TransactionType
{
    Noop = 0,
    SpotTrade,
    Deposit,
    NewAccount,
    Withdrawal,
    PublicKeyUpdate,
    Transfer,
    OwnerChange,

    COUNT
};

class Proof
{
public:
    std::vector<ethsnarks::FieldT> data;
};

static void from_json(const json& j, Proof& proof)
{
    for(unsigned int i = 0; i < j.size(); i++)
    {
        proof.data.push_back(ethsnarks::FieldT(j[i].get<std::string>().c_str()));
    }
}

class TradeHistoryLeaf
{
public:
    ethsnarks::FieldT filled;
    ethsnarks::FieldT orderID;
};

static void from_json(const json& j, TradeHistoryLeaf& leaf)
{
    leaf.filled = ethsnarks::FieldT(j.at("filled").get<std::string>().c_str());
    leaf.orderID = ethsnarks::FieldT(j.at("orderID").get<std::string>().c_str());
}

class BalanceLeaf
{
public:
    ethsnarks::FieldT balance;
    ethsnarks::FieldT index;
    ethsnarks::FieldT tradingHistoryRoot;
};

static void from_json(const json& j, BalanceLeaf& leaf)
{
    leaf.balance = ethsnarks::FieldT(j.at("balance").get<std::string>().c_str());
    leaf.index = ethsnarks::FieldT(j.at("index").get<std::string>().c_str());
    leaf.tradingHistoryRoot = ethsnarks::FieldT(j.at("tradingHistoryRoot").get<std::string>().c_str());
}

class Account
{
public:
    ethsnarks::FieldT owner;
    ethsnarks::jubjub::EdwardsPoint publicKey;
    ethsnarks::FieldT nonce;
    ethsnarks::FieldT walletHash;
    ethsnarks::FieldT balancesRoot;
};

static void from_json(const json& j, Account& account)
{
    account.owner = ethsnarks::FieldT(j.at("owner").get<std::string>().c_str());
    account.publicKey.x = ethsnarks::FieldT(j.at("publicKeyX").get<std::string>().c_str());
    account.publicKey.y = ethsnarks::FieldT(j.at("publicKeyY").get<std::string>().c_str());
    account.nonce = ethsnarks::FieldT(j.at("nonce"));
    account.walletHash = ethsnarks::FieldT(j.at("walletHash").get<std::string>().c_str());
    account.balancesRoot = ethsnarks::FieldT(j.at("balancesRoot").get<std::string>().c_str());
}

class BalanceUpdate
{
public:
    ethsnarks::FieldT tokenID;
    Proof proof;
    ethsnarks::FieldT rootBefore;
    ethsnarks::FieldT rootAfter;
    BalanceLeaf before;
    BalanceLeaf after;
};

static void from_json(const json& j, BalanceUpdate& balanceUpdate)
{
    balanceUpdate.tokenID = ethsnarks::FieldT(j.at("tokenID"));
    balanceUpdate.proof = j.at("proof").get<Proof>();
    balanceUpdate.rootBefore = ethsnarks::FieldT(j.at("rootBefore").get<std::string>().c_str());
    balanceUpdate.rootAfter = ethsnarks::FieldT(j.at("rootAfter").get<std::string>().c_str());
    balanceUpdate.before = j.at("before").get<BalanceLeaf>();
    balanceUpdate.after = j.at("after").get<BalanceLeaf>();
}

class TradeHistoryUpdate
{
public:
    ethsnarks::FieldT orderID;
    Proof proof;
    ethsnarks::FieldT rootBefore;
    ethsnarks::FieldT rootAfter;
    TradeHistoryLeaf before;
    TradeHistoryLeaf after;
};

static void from_json(const json& j, TradeHistoryUpdate& tradeHistoryUpdate)
{
    tradeHistoryUpdate.orderID = ethsnarks::FieldT(j.at("orderID").get<std::string>().c_str());
    tradeHistoryUpdate.proof = j.at("proof").get<Proof>();
    tradeHistoryUpdate.rootBefore = ethsnarks::FieldT(j.at("rootBefore").get<std::string>().c_str());
    tradeHistoryUpdate.rootAfter = ethsnarks::FieldT(j.at("rootAfter").get<std::string>().c_str());
    tradeHistoryUpdate.before = j.at("before").get<TradeHistoryLeaf>();
    tradeHistoryUpdate.after = j.at("after").get<TradeHistoryLeaf>();
}

class AccountUpdate
{
public:
    ethsnarks::FieldT accountID;
    Proof proof;
    ethsnarks::FieldT rootBefore;
    ethsnarks::FieldT rootAfter;
    Account before;
    Account after;
};

static void from_json(const json& j, AccountUpdate& accountUpdate)
{
    accountUpdate.accountID = ethsnarks::FieldT(j.at("accountID"));
    accountUpdate.proof = j.at("proof").get<Proof>();
    accountUpdate.rootBefore = ethsnarks::FieldT(j.at("rootBefore").get<std::string>().c_str());
    accountUpdate.rootAfter = ethsnarks::FieldT(j.at("rootAfter").get<std::string>().c_str());
    accountUpdate.before = j.at("before").get<Account>();
    accountUpdate.after = j.at("after").get<Account>();
}

class Signature
{
public:

    Signature()
    {

    }

    Signature(ethsnarks::jubjub::EdwardsPoint _R, ethsnarks::FieldT _s) : R(_R), s(_s)
    {

    }

    ethsnarks::jubjub::EdwardsPoint R;
    ethsnarks::FieldT s;
};

static void from_json(const json& j, Signature& signature)
{
    signature.R.x = ethsnarks::FieldT(j.at("Rx").get<std::string>().c_str());
    signature.R.y = ethsnarks::FieldT(j.at("Ry").get<std::string>().c_str());
    signature.s = ethsnarks::FieldT(j.at("s").get<std::string>().c_str());
}

class Order
{
public:
    ethsnarks::FieldT exchangeID;
    ethsnarks::FieldT orderID;
    ethsnarks::FieldT accountID;
    ethsnarks::FieldT tokenS;
    ethsnarks::FieldT tokenB;
    ethsnarks::FieldT amountS;
    ethsnarks::FieldT amountB;
    ethsnarks::FieldT allOrNone;
    ethsnarks::FieldT validSince;
    ethsnarks::FieldT validUntil;
    ethsnarks::FieldT maxFeeBips;
    ethsnarks::FieldT buy;

    ethsnarks::FieldT feeBips;
    ethsnarks::FieldT rebateBips;
};

static void from_json(const json& j, Order& order)
{
    order.exchangeID = ethsnarks::FieldT(j.at("exchangeID"));
    order.orderID = ethsnarks::FieldT(j.at("orderID").get<std::string>().c_str());
    order.accountID = ethsnarks::FieldT(j.at("accountID"));
    order.tokenS = ethsnarks::FieldT(j.at("tokenS"));
    order.tokenB = ethsnarks::FieldT(j.at("tokenB"));
    order.amountS = ethsnarks::FieldT(j.at("amountS").get<std::string>().c_str());
    order.amountB = ethsnarks::FieldT(j.at("amountB").get<std::string>().c_str());
    order.allOrNone = ethsnarks::FieldT(j.at("allOrNone").get<bool>() ? 1 : 0);
    order.validSince = ethsnarks::FieldT(j.at("validSince"));
    order.validUntil = ethsnarks::FieldT(j.at("validUntil"));
    order.maxFeeBips = ethsnarks::FieldT(j.at("maxFeeBips"));
    order.buy = ethsnarks::FieldT(j.at("buy").get<bool>() ? 1 : 0);

    order.feeBips = ethsnarks::FieldT(j.at("feeBips"));
    order.rebateBips = ethsnarks::FieldT(j.at("rebateBips"));
}

class SpotTrade
{
public:
    Order orderA;
    Order orderB;
    ethsnarks::FieldT fillS_A;
    ethsnarks::FieldT fillS_B;
};

static void from_json(const json& j, SpotTrade& spotTrade)
{
    spotTrade.orderA = j.at("orderA").get<Order>();
    spotTrade.orderB = j.at("orderB").get<Order>();
    spotTrade.fillS_A = ethsnarks::FieldT(j["fFillS_A"]);
    spotTrade.fillS_B = ethsnarks::FieldT(j["fFillS_B"]);
}

class Deposit
{
public:
    ethsnarks::FieldT owner;
    ethsnarks::FieldT accountID;
    ethsnarks::FieldT tokenID;
    ethsnarks::FieldT amount;
    ethsnarks::FieldT index;
};

static void from_json(const json& j, Deposit& deposit)
{
    deposit.owner = ethsnarks::FieldT(j.at("owner").get<std::string>().c_str());
    deposit.accountID = ethsnarks::FieldT(j.at("accountID"));
    deposit.tokenID = ethsnarks::FieldT(j.at("tokenID"));
    deposit.amount = ethsnarks::FieldT(j.at("amount").get<std::string>().c_str());
    deposit.index = ethsnarks::FieldT(j.at("index").get<std::string>().c_str());
}

class Withdrawal
{
public:
    ethsnarks::FieldT accountID;
    ethsnarks::FieldT tokenID;
    ethsnarks::FieldT amount;
    ethsnarks::FieldT feeTokenID;
    ethsnarks::FieldT fee;
    ethsnarks::FieldT to;
    ethsnarks::FieldT dataHash;
    ethsnarks::FieldT minGas;
    ethsnarks::FieldT type;
};

static void from_json(const json& j, Withdrawal& withdrawal)
{
    withdrawal.accountID = ethsnarks::FieldT(j.at("accountID"));
    withdrawal.tokenID = ethsnarks::FieldT(j.at("tokenID"));
    withdrawal.amount = ethsnarks::FieldT(j["amount"].get<std::string>().c_str());
    withdrawal.feeTokenID = ethsnarks::FieldT(j.at("feeTokenID"));
    withdrawal.fee = ethsnarks::FieldT(j["fee"].get<std::string>().c_str());
    withdrawal.to = ethsnarks::FieldT(j["to"].get<std::string>().c_str());
    withdrawal.dataHash = ethsnarks::FieldT(j["dataHash"].get<std::string>().c_str());
    withdrawal.minGas = ethsnarks::FieldT(j.at("minGas"));
    withdrawal.type = ethsnarks::FieldT(j.at("type"));
}


class PublicKeyUpdate
{
public:
    ethsnarks::FieldT accountID;
    ethsnarks::FieldT publicKeyX;
    ethsnarks::FieldT publicKeyY;
    ethsnarks::FieldT walletHash;
    ethsnarks::FieldT feeTokenID;
    ethsnarks::FieldT fee;
};

static void from_json(const json& j, PublicKeyUpdate& update)
{
    update.accountID = ethsnarks::FieldT(j.at("accountID"));
    update.publicKeyX = ethsnarks::FieldT(j["publicKeyX"].get<std::string>().c_str());
    update.publicKeyY = ethsnarks::FieldT(j["publicKeyY"].get<std::string>().c_str());
    update.walletHash = ethsnarks::FieldT(j["walletHash"].get<std::string>().c_str());
    update.feeTokenID = ethsnarks::FieldT(j.at("feeTokenID"));
    update.fee = ethsnarks::FieldT(j["fee"].get<std::string>().c_str());
}


class NewAccount
{
public:
    ethsnarks::FieldT payerAccountID;
    ethsnarks::FieldT feeTokenID;
    ethsnarks::FieldT fee;
    ethsnarks::FieldT newAccountID;
    ethsnarks::FieldT newOwner;
    ethsnarks::FieldT newPublicKeyX;
    ethsnarks::FieldT newPublicKeyY;
    ethsnarks::FieldT newWalletHash;
};

static void from_json(const json& j, NewAccount& create)
{
    create.payerAccountID = ethsnarks::FieldT(j.at("payerAccountID"));
    create.feeTokenID = ethsnarks::FieldT(j.at("feeTokenID"));
    create.fee = ethsnarks::FieldT(j["fee"].get<std::string>().c_str());
    create.newAccountID = ethsnarks::FieldT(j.at("newAccountID"));
    create.newOwner = ethsnarks::FieldT(j["newOwner"].get<std::string>().c_str());
    create.newPublicKeyX = ethsnarks::FieldT(j["newPublicKeyX"].get<std::string>().c_str());
    create.newPublicKeyY = ethsnarks::FieldT(j["newPublicKeyY"].get<std::string>().c_str());
    create.newWalletHash = ethsnarks::FieldT(j["newWalletHash"].get<std::string>().c_str());
}


class OwnerChange
{
public:
    ethsnarks::FieldT accountID;
    ethsnarks::FieldT feeTokenID;
    ethsnarks::FieldT fee;
    ethsnarks::FieldT newOwner;
};

static void from_json(const json& j, OwnerChange& change)
{
    change.accountID = ethsnarks::FieldT(j.at("accountID"));
    change.feeTokenID = ethsnarks::FieldT(j.at("feeTokenID"));
    change.fee = ethsnarks::FieldT(j["fee"].get<std::string>().c_str());
    change.newOwner = ethsnarks::FieldT(j["newOwner"].get<std::string>().c_str());
}

class Transfer
{
public:

    ethsnarks::FieldT accountFromID;
    ethsnarks::FieldT accountToID;
    ethsnarks::FieldT tokenID;
    ethsnarks::FieldT amount;
    ethsnarks::FieldT feeTokenID;
    ethsnarks::FieldT fee;
    ethsnarks::FieldT validUntil;
    ethsnarks::FieldT ownerTo;
    ethsnarks::FieldT dualAuthorX;
    ethsnarks::FieldT dualAuthorY;
    ethsnarks::FieldT payerAccountToID;
    ethsnarks::FieldT payerOwnerTo;
    ethsnarks::FieldT payeeAccountToID;
    ethsnarks::FieldT type;
};

static void from_json(const json& j, Transfer& transfer)
{
    transfer.accountFromID = ethsnarks::FieldT(j.at("accountFromID"));
    transfer.accountToID = ethsnarks::FieldT(j.at("accountToID"));
    transfer.tokenID = ethsnarks::FieldT(j.at("tokenID"));
    transfer.amount = ethsnarks::FieldT(j["amount"].get<std::string>().c_str());
    transfer.feeTokenID = ethsnarks::FieldT(j.at("feeTokenID"));
    transfer.fee = ethsnarks::FieldT(j["fee"].get<std::string>().c_str());
    transfer.validUntil = ethsnarks::FieldT(j.at("validUntil"));
    transfer.ownerTo = ethsnarks::FieldT(j["ownerTo"].get<std::string>().c_str());
    transfer.dualAuthorX = ethsnarks::FieldT(j["dualAuthorX"].get<std::string>().c_str());
    transfer.dualAuthorY = ethsnarks::FieldT(j["dualAuthorY"].get<std::string>().c_str());
    transfer.payerAccountToID = ethsnarks::FieldT(j.at("payerAccountToID"));
    transfer.payerOwnerTo = ethsnarks::FieldT(j["payerOwnerTo"].get<std::string>().c_str());
    transfer.payeeAccountToID = ethsnarks::FieldT(j.at("payeeAccountToID"));
    transfer.type = ethsnarks::FieldT(j.at("type"));
}

class Witness
{
public:
    TradeHistoryUpdate tradeHistoryUpdate_A;
    TradeHistoryUpdate tradeHistoryUpdate_B;

    BalanceUpdate balanceUpdateS_A;
    BalanceUpdate balanceUpdateB_A;
    AccountUpdate accountUpdate_A;

    BalanceUpdate balanceUpdateS_B;
    BalanceUpdate balanceUpdateB_B;
    AccountUpdate accountUpdate_B;

    BalanceUpdate balanceUpdateA_O;
    BalanceUpdate balanceUpdateB_O;
    AccountUpdate accountUpdate_O;

    BalanceUpdate balanceUpdateA_P;
    BalanceUpdate balanceUpdateB_P;

    BalanceUpdate balanceUpdateA_I;
    BalanceUpdate balanceUpdateB_I;

    Signature signatureA;
    Signature signatureB;

    ethsnarks::FieldT numConditionalTransactionsAfter;
};

static void from_json(const json& j, Witness& state)
{
    state.tradeHistoryUpdate_A = j.at("tradeHistoryUpdate_A").get<TradeHistoryUpdate>();
    state.tradeHistoryUpdate_B = j.at("tradeHistoryUpdate_B").get<TradeHistoryUpdate>();

    state.balanceUpdateS_A = j.at("balanceUpdateS_A").get<BalanceUpdate>();
    state.balanceUpdateB_A = j.at("balanceUpdateB_A").get<BalanceUpdate>();
    state.accountUpdate_A = j.at("accountUpdate_A").get<AccountUpdate>();

    state.balanceUpdateS_B = j.at("balanceUpdateS_B").get<BalanceUpdate>();
    state.balanceUpdateB_B = j.at("balanceUpdateB_B").get<BalanceUpdate>();
    state.accountUpdate_B = j.at("accountUpdate_B").get<AccountUpdate>();

    state.balanceUpdateA_O = j.at("balanceUpdateA_O").get<BalanceUpdate>();
    state.balanceUpdateB_O = j.at("balanceUpdateB_O").get<BalanceUpdate>();
    state.accountUpdate_O = j.at("accountUpdate_O").get<AccountUpdate>();

    state.balanceUpdateA_P = j.at("balanceUpdateA_P").get<BalanceUpdate>();
    state.balanceUpdateB_P = j.at("balanceUpdateB_P").get<BalanceUpdate>();

    state.balanceUpdateA_I = j.at("balanceUpdateA_I").get<BalanceUpdate>();
    state.balanceUpdateB_I = j.at("balanceUpdateB_I").get<BalanceUpdate>();

    state.signatureA = dummySignature.get<Signature>();
    state.signatureB = dummySignature.get<Signature>();

    state.numConditionalTransactionsAfter = ethsnarks::FieldT(j.at("numConditionalTransactionsAfter"));

    if (j.contains("signatureA"))
    {
        state.signatureA = j.at("signatureA").get<Signature>();
    }
    if (j.contains("signatureB"))
    {
        state.signatureB = j.at("signatureB").get<Signature>();
    }
    else
    {
        state.signatureB = state.signatureA;
    }
}

class UniversalTransaction
{
public:
    Witness witness;
    ethsnarks::FieldT type;
    SpotTrade spotTrade;
    Transfer transfer;
    NewAccount newAccount;
    Withdrawal withdraw;
    Deposit deposit;
    PublicKeyUpdate publicKeyUpdate;
    OwnerChange ownerChange;
};

static void from_json(const json& j, UniversalTransaction& transaction)
{
    transaction.witness = j.at("witness").get<Witness>();

    // Fill in dummy data for all tx types
    transaction.spotTrade = dummySpotTrade.get<Loopring::SpotTrade>();
    transaction.transfer = dummyTransfer.get<Loopring::Transfer>();
    transaction.withdraw = dummyWithdraw.get<Loopring::Withdrawal>();
    transaction.deposit = dummyDeposit.get<Loopring::Deposit>();
    transaction.publicKeyUpdate = dummyPublicKeyUpdate.get<Loopring::PublicKeyUpdate>();
    transaction.newAccount = dummyNewAccount.get<Loopring::NewAccount>();
    transaction.ownerChange = dummyOwnerChange.get<Loopring::OwnerChange>();

    // Patch some of the dummy tx's so they are valid against the current state
    // Deposit
    transaction.deposit.owner = transaction.witness.accountUpdate_A.before.owner;
    // Transfer
    transaction.transfer.ownerTo = transaction.witness.accountUpdate_B.before.owner;
    transaction.transfer.payerOwnerTo = transaction.witness.accountUpdate_B.before.owner;

    // Now get the actual transaction data for the actual transaction that will execute from the block
    if (j.contains("noop"))
    {
        transaction.type = ethsnarks::FieldT(int(Loopring::TransactionType::Noop));
    }
    if (j.contains("spotTrade"))
    {
        transaction.type = ethsnarks::FieldT(int(Loopring::TransactionType::SpotTrade));
        transaction.spotTrade = j.at("spotTrade").get<Loopring::SpotTrade>();
    }
    else if (j.contains("transfer"))
    {
        transaction.type = ethsnarks::FieldT(int(Loopring::TransactionType::Transfer));
        transaction.transfer = j.at("transfer").get<Loopring::Transfer>();
    }
    else if (j.contains("withdraw"))
    {
        transaction.type = ethsnarks::FieldT(int(Loopring::TransactionType::Withdrawal));
        transaction.withdraw = j.at("withdraw").get<Loopring::Withdrawal>();
    }
    else if (j.contains("deposit"))
    {
        transaction.type = ethsnarks::FieldT(int(Loopring::TransactionType::Deposit));
        transaction.deposit = j.at("deposit").get<Loopring::Deposit>();
    }
    else if (j.contains("publicKeyUpdate"))
    {
        transaction.type = ethsnarks::FieldT(int(Loopring::TransactionType::PublicKeyUpdate));
        transaction.publicKeyUpdate = j.at("publicKeyUpdate").get<Loopring::PublicKeyUpdate>();
    }
    else if (j.contains("newAccount"))
    {
        transaction.type = ethsnarks::FieldT(int(Loopring::TransactionType::NewAccount));
        transaction.newAccount = j.at("newAccount").get<Loopring::NewAccount>();
    }
    else if (j.contains("ownerChange"))
    {
        transaction.type = ethsnarks::FieldT(int(Loopring::TransactionType::OwnerChange));
        transaction.ownerChange = j.at("ownerChange").get<Loopring::OwnerChange>();
    }
}

class Block
{
public:

    ethsnarks::FieldT exchangeID;

    ethsnarks::FieldT merkleRootBefore;
    ethsnarks::FieldT merkleRootAfter;

    ethsnarks::FieldT timestamp;

    ethsnarks::FieldT protocolTakerFeeBips;
    ethsnarks::FieldT protocolMakerFeeBips;

    Signature signature;

    AccountUpdate accountUpdate_P;

    ethsnarks::FieldT operatorAccountID;
    AccountUpdate accountUpdate_O;

    AccountUpdate accountUpdate_I;

    std::vector<Loopring::UniversalTransaction> transactions;
};

static void from_json(const json& j, Block& block)
{
    block.exchangeID = ethsnarks::FieldT(j["exchangeID"].get<unsigned int>());

    block.merkleRootBefore = ethsnarks::FieldT(j["merkleRootBefore"].get<std::string>().c_str());
    block.merkleRootAfter = ethsnarks::FieldT(j["merkleRootAfter"].get<std::string>().c_str());

    block.timestamp = ethsnarks::FieldT(j["timestamp"].get<unsigned int>());

    block.protocolTakerFeeBips = ethsnarks::FieldT(j["protocolTakerFeeBips"].get<unsigned int>());
    block.protocolMakerFeeBips = ethsnarks::FieldT(j["protocolMakerFeeBips"].get<unsigned int>());

    block.signature = j.at("signature").get<Signature>();

    block.accountUpdate_P = j.at("accountUpdate_P").get<AccountUpdate>();

    block.operatorAccountID = ethsnarks::FieldT(j.at("operatorAccountID"));
    block.accountUpdate_O = j.at("accountUpdate_O").get<AccountUpdate>();

    block.accountUpdate_I = j.at("accountUpdate_I").get<AccountUpdate>();

    // Read transactions
    json jTransactions = j["transactions"];
    for(unsigned int i = 0; i < jTransactions.size(); i++)
    {
        block.transactions.emplace_back(jTransactions[i].get<Loopring::UniversalTransaction>());
    }
}

}

#endif
