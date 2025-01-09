// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_OVERFLOW_H
#define BITCOIN_UTIL_OVERFLOW_H

#include <concepts>
#include <limits>
#include <optional>
#include <type_traits>

template <class T>
[[nodiscard]] bool AdditionOverflow(const T i, const T j) noexcept
{
    static_assert(std::is_integral<T>::value, "Integral required.");
    if constexpr (std::numeric_limits<T>::is_signed) {
        return (i > 0 && j > std::numeric_limits<T>::max() - i) ||
               (i < 0 && j < std::numeric_limits<T>::min() - i);
    }
    return std::numeric_limits<T>::max() - i < j;
}

template <class T>
[[nodiscard]] std::optional<T> CheckedAdd(const T i, const T j) noexcept
{
    if (AdditionOverflow(i, j)) {
        return std::nullopt;
    }
    return i + j;
}

template <class T>
[[nodiscard]] T SaturatingAdd(const T i, const T j) noexcept
{
    if constexpr (std::numeric_limits<T>::is_signed) {
        if (i > 0 && j > std::numeric_limits<T>::max() - i) {
            return std::numeric_limits<T>::max();
        }
        if (i < 0 && j < std::numeric_limits<T>::min() - i) {
            return std::numeric_limits<T>::min();
        }
    } else {
        if (std::numeric_limits<T>::max() - i < j) {
            return std::numeric_limits<T>::max();
        }
    }
    return i + j;
}

/**
 * @brief Left bit shift with overflow checking.
 * @param i The input value to be left shifted.
 * @param shift The number of bits to left shift.
 * @return The result of the left shift, or std::nullopt in case of
 *         overflow or negative input value.
 */
template <std::unsigned_integral Output, std::integral Input>
constexpr std::optional<Output> CheckedLeftShift(Input i, unsigned shift) noexcept
{
    if constexpr (std::is_signed_v<Input>) {
        if (i < 0) return std::nullopt;
    }
    if (std::make_unsigned_t<Input>(i) > Output(std::numeric_limits<Output>::max() >> shift)) {
        return std::nullopt;
    }
    return i << shift;
}

/**
 * @brief Left bit shift with safe minimum and maximum values.
 * @param i The input value to be left shifted.
 * @param shift The number of bits to left shift.
 * @return The result of the left shift, with the return value clamped
 *         between zero and the maximum Output value if overflow occurs.
 */
template <std::unsigned_integral Output, std::integral Input>
constexpr Output SaturatingLeftShift(Input i, unsigned shift) noexcept
{
    auto default_value{std::numeric_limits<Output>::max()};
    if constexpr (std::is_signed_v<Input>) {
        if (i < 0) default_value = 0;
    }
    return CheckedLeftShift<Output>(i, shift).value_or(default_value);
}

#endif // BITCOIN_UTIL_OVERFLOW_H
