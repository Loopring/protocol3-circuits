#ifndef _CONSTANTS_H_
#define _CONSTANTS_H_

namespace Loopring
{
    static const unsigned int TREE_DEPTH_TRADING_HISTORY = 7;
    static const unsigned int TREE_DEPTH_ACCOUNTS = 10;
    static const unsigned int TREE_DEPTH_TOKENS = 4;

    static const unsigned int NUM_BITS_MAX_VALUE = 253;
    static const unsigned int NUM_BITS_AMOUNT = 96;
    static const unsigned int NUM_BITS_TRADING_HISTORY = TREE_DEPTH_TRADING_HISTORY * 2;
    static const unsigned int NUM_BITS_ACCOUNT = TREE_DEPTH_ACCOUNTS * 2;
    static const unsigned int NUM_BITS_TOKEN = TREE_DEPTH_TOKENS * 2;
    static const unsigned int NUM_BITS_ORDERID = 20;
    static const unsigned int NUM_BITS_TIMESTAMP = 32;
    static const unsigned int NUM_BITS_NONCE = 32;
    static const unsigned int NUM_BITS_BIPS = 6;
    static const unsigned int NUM_BITS_LABEL = 16;

    static const char* EMPTY_TRADE_HISTORY = "6592749167578234498153410564243369229486412054742481069049239297514590357090";
    static const char* MAX_AMOUNT = "79228162514264337593543950335"; // 2^96 - 1

    struct FloatEncoding
    {
        unsigned int numBitsExponent;
        unsigned int numBitsMantissa;
        unsigned int exponentBase;
    };
    static const FloatEncoding Float28Encoding = {5, 23, 10};
    static const FloatEncoding Float24Encoding = {5, 19, 10};
    static const FloatEncoding Float16Encoding = {5, 11, 10};
    static const FloatEncoding Float12Encoding = {5,  7, 10};
    static const FloatEncoding Float8Encoding  = {5,  3, 10};

    struct Accuracy
    {
        unsigned int numerator;
        unsigned int denominator;
    };
    static const Accuracy Float28Accuracy = {12, 10000000};
    static const Accuracy Float24Accuracy = { 2, 100000};
    static const Accuracy Float16Accuracy = { 5, 1000};
    static const Accuracy Float12Accuracy = { 8, 100};
}

#endif