#ifndef _UTILS_H_
#define _UTILS_H_

#include "Constants.h"
#include "Data.h"

#include "../ThirdParty/BigInt.hpp"
#include "ethsnarks.hpp"
#include "utils.hpp"
#include "jubjub/point.hpp"
#include "jubjub/eddsa.hpp"
#include "gadgets/merkle_tree.hpp"
#include "gadgets/sha256_many.hpp"
#include "gadgets/subadd.hpp"

using namespace ethsnarks;


namespace Loopring
{

void print(const char* description, const ethsnarks::FieldT& value)
{
    std::cout << description << ": ";
    value.as_bigint().print();
}

void print(const ProtoboardT& pb, const char* description, const ethsnarks::VariableT& variable)
{
    print(description, pb.val(variable));
}

void printBits(const char* name, const libff::bit_vector& _bits, bool reverse = false)
{
    libff::bit_vector bits = _bits;
    if(reverse)
    {
        std::reverse(std::begin(bits), std::end(bits));
    }
    unsigned int numBytes = (bits.size() + 7) / 8;
    uint8_t* full_output_bytes = new uint8_t[numBytes];
    bv_to_bytes(bits, full_output_bytes);
    char* hexstr = new char[numBytes*2 + 1];
    hexstr[numBytes*2] = '\0';
    for(int i = 0; i < bits.size()/8; i++)
    {
        sprintf(hexstr + i*2, "%02x", full_output_bytes[i]);
    }
    std::cout << name << hexstr << std::endl;
    delete [] full_output_bytes;
    delete [] hexstr;
}

/**
* Convert an array of variable arrays into a flat contiguous array of variables
*/
const VariableArrayT flattenReverse( const std::vector<VariableArrayT> &in_scalars )
{
    size_t total_sz = 0;
    for( const auto& scalar : in_scalars )
        total_sz += scalar.size();

    VariableArrayT result;
    result.resize(total_sz);

    size_t offset = 0;
    for( const auto& scalar : in_scalars )
    {
        for (int i = int(scalar.size()) - 1; i >= 0; i--)
        {
            result[offset++].index = scalar[i].index;
        }
    }

    return result;
}

const VariableArrayT reverse(const VariableArrayT& values)
{
    return flattenReverse({values});
}

const VariableArrayT subArray(const VariableArrayT& bits, unsigned int start, unsigned int length)
{
    VariableArrayT result;
    result.resize(length);

    unsigned int index = 0;
    for (int i = start; i < start + length; i++)
    {
        result[index++].index = bits[i].index;
    }

    return result;
}

inline const VariableArrayT var_array(const std::vector<VariableT>& inputs)
{
    return VariableArrayT(inputs.begin(), inputs.end());
}

BigInt toBigInt(ethsnarks::FieldT value)
{
    BigInt bi = 0;
    for(unsigned int i = 0; i < value.as_bigint().num_bits(); i++)
    {
        bi = bi * 2 + (value.as_bigint().test_bit(value.as_bigint().num_bits() - 1 - i) ? 1 : 0);
    }
    return bi;
}

unsigned int toFloat(BigInt value, const FloatEncoding& encoding)
{
  const unsigned int maxExponent = (1 << encoding.numBitsExponent) - 1;
  const unsigned int maxMantissa = (1 << encoding.numBitsMantissa) - 1;
  BigInt maxExponentValue = 1;
  for (unsigned int i = 0; i < maxExponent; i++)
  {
      maxExponentValue *= encoding.exponentBase;
  }
  BigInt maxValue = BigInt(maxMantissa) * BigInt(maxExponentValue);
  assert(value <= maxValue);

  unsigned int exponent = 0;
  BigInt r = value / BigInt(maxMantissa);
  BigInt d = 1;
  while (r >= encoding.exponentBase || d * maxMantissa < value)
  {
      r = r / encoding.exponentBase;
      exponent += 1;
      d = d * encoding.exponentBase;
  }
  BigInt mantissa = value / d;

  assert(exponent <= maxExponent);
  assert(mantissa <= maxMantissa);
  const unsigned int f = (exponent << encoding.numBitsMantissa) + mantissa.to_long();
  return f;
}

unsigned int toFloat(ethsnarks::FieldT value, const FloatEncoding& encoding)
{
  return toFloat(toBigInt(value), encoding);
}

BigInt fromFloat(unsigned int f, const FloatEncoding& encoding)
{
  const unsigned int exponent = f >> encoding.numBitsMantissa;
  const unsigned int mantissa = f & ((1 << encoding.numBitsMantissa) - 1);
  BigInt multiplier = 1;
  for (unsigned int i = 0; i < exponent; i++)
  {
      multiplier *= 10;
  }
  BigInt value = BigInt(mantissa) * multiplier;
  return value;
}

}

#endif
