// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_RESULT_H
#define BITCOIN_UTIL_RESULT_H

#include <attributes.h>
#include <util/translation.h>

#include <memory>
#include <optional>
#include <tuple>
#include <utility>
#include <vector>

namespace util {
namespace detail {
//! Empty string list
const std::vector<bilingual_str> EMPTY_LIST{};

//! Helper function to join messages in space separated string.
bilingual_str JoinMessages(const std::vector<bilingual_str>& errors, const std::vector<bilingual_str>& warnings);

//! Helper function to move messages from one vector to another.
void MoveMessages(std::vector<bilingual_str>& src, std::vector<bilingual_str>& dest);

//! Subsitute for std::monostate that doesn't depend on std::variant.
struct MonoState{};

//! Error information only allocated if there are errors or warnings.
template <typename F>
struct ErrorInfo {
    std::optional<std::conditional_t<std::is_same_v<F, void>, MonoState, F>> failure{};
    std::vector<bilingual_str> errors{};
    std::vector<bilingual_str> warnings{};
};

//! Result base class which is inherited by Result<T, F>.
//! T is the type of the success return value, or void if there is none.
//! F is the type of the failure return value, or void if there is none.
template <typename T, typename F>
class ResultBase;

//! Result base specialization for empty (T=void) value type. Holds error
//! information and provides accessor methods.
template <typename F>
class ResultBase<void, F>
{
protected:
    std::unique_ptr<ErrorInfo<F>> m_info;

    ErrorInfo<F>& Info() LIFETIMEBOUND
    {
        if (!m_info) m_info = std::make_unique<ErrorInfo<F>>();
        return *m_info;
    }

    //! Value setter methods that do nothing because this class has value type T=void.
    void ConstructValue() {}
    template <typename O>
    void MoveValue(O& other) {}
    void DestroyValue() {}

public:
    //! Success check.
    explicit operator bool() const { return !m_info || !m_info->failure; }

    //! Error retrieval.
    const auto& GetFailure() const LIFETIMEBOUND { assert(!*this); return *m_info->failure; }
    const std::vector<bilingual_str>& GetErrors() const LIFETIMEBOUND { return m_info ? m_info->errors : EMPTY_LIST; }
    const std::vector<bilingual_str>& GetWarnings() const LIFETIMEBOUND { return m_info ? m_info->warnings : EMPTY_LIST; }
};

//! Result base class for T value type. Holds value and provides accessor methods.
template <typename T, typename F>
class ResultBase : public ResultBase<void, F>
{
protected:
    //! Result success value. Uses anonymous union so success value is never
    //! constructed in failure case.
    union { T m_value; };

    template <typename... Args>
    void ConstructValue(Args&&... args) { new (&m_value) T{std::forward<Args>(args)...}; }
    template <typename O>
    void MoveValue(O& other) { new (&m_value) T{std::move(other.m_value)}; }
    void DestroyValue() { m_value.~T(); }

    //! Empty constructor that needs to be declared because the class contains a union.
    ResultBase() {}
    ~ResultBase() { if (*this) DestroyValue(); }

    template <typename, typename>
    friend class ResultBase;

public:
    //! std::optional methods, so functions returning optional<T> can change to
    //! return Result<T> with minimal changes to existing code, and vice versa.
    bool has_value() const { return bool{*this}; }
    const T& value() const LIFETIMEBOUND { assert(*this); return m_value; }
    T& value() LIFETIMEBOUND { assert(*this); return m_value; }
    template <class U>
    T value_or(U&& default_value) const&
    {
        return has_value() ? value() : std::forward<U>(default_value);
    }
    template <class U>
    T value_or(U&& default_value) &&
    {
        return has_value() ? std::move(value()) : std::forward<U>(default_value);
    }
    const T* operator->() const LIFETIMEBOUND { return &value(); }
    const T& operator*() const LIFETIMEBOUND { return value(); }
    T* operator->() LIFETIMEBOUND { return &value(); }
    T& operator*() LIFETIMEBOUND { return value(); }
};
} // namespace detail

//! Wrapper types to pass error and warning strings to Result constructors.
struct Error {
    bilingual_str message;
};
struct Warning {
    bilingual_str message;
};

//! The util::Result class provides a standard way for functions to return error
//! and warning strings in addition to optional result values.
//!
//! It is intended for high-level functions that need to report error strings to
//! end users. Lower-level functions that don't need this error-reporting and
//! only need error-handling should avoid util::Result and instead use standard
//! classes like std::optional, std::variant, and std::tuple, or custom structs
//! and enum types to return function results.
//!
//! Usage examples can be found in \example ../test/result_tests.cpp, but in
//! general code returning `util::Result<T>` values is very similar to code
//! returning `std::optional<T>` values. Existing functions returning
//! `std::optional<T>` can be updated to return `util::Result<T>` and return
//! error strings usually just replacing `return std::nullopt;` with `return
//! util::Error{error_string};`.
//!
//! Most code does not need different error-handling behavior for different
//! types of errors, and can suffice just using the type `T` success value on
//! success, and descriptive error strings when there's a failure. But
//! applications that do need more complicated error-handling behavior can
//! override the default `F = void` failure type and get failure values by
//! calling result.GetFailure().
template <typename T, typename F = void>
class Result : public detail::ResultBase<T, F>
{
protected:
    template <typename Fn, typename... Args>
    void Construct(const Fn& fn, Args&&... args)
    {
        fn(std::forward<Args>(args)...);
    }

    template <typename Fn, typename... Args>
    void Construct(const Fn& fn, Error error, Args&&... args)
    {
        this->AddError(std::move(error.message));
        Construct([&](auto&&... x) {
            this->Info().failure.emplace(std::forward<decltype(x)>(x)...);
        }, std::forward<Args>(args)...);
    }

    template <typename Fn, typename... Args>
    void Construct(const Fn& fn, Warning warning, Args&&... args)
    {
        this->AddWarning(std::move(warning.message));
        Construct(fn, std::forward<Args>(args)...);
    }

    template <typename Fn, typename OT, typename OF, typename... Args>
    void Construct(const Fn& fn, Result<OT, OF>&& other, Args&&... args)
    {
        this->MoveMessages(other);
        Construct(fn, std::forward<Args>(args)...);
    }

    template <typename OT, typename OF>
    void MoveConstruct(Result<OT, OF>& other)
    {
        this->MoveMessages(other);
        if (other) {
            this->MoveValue(other);
        } else {
            this->Info().failure = std::move(other.m_info->failure);
        }
    }

    template <typename, typename>
    friend class Result;

public:
    template <typename... Args>
    Result(Args&&... args)
    {
        Construct([this](auto&&... x) { this->ConstructValue(std::forward<decltype(x)>(x)...); }, std::forward<Args>(args)...);
    }

    template <typename OT, typename OF>
    Result(Result<OT, OF>&& other) { MoveConstruct(other); }

    Result& Set(Result&& other) LIFETIMEBOUND
    {
        if (*this) {
            this->DestroyValue();
        } else {
            this->m_info->failure.reset();
        }
        MoveConstruct(other);
        return *this;
    }

    void AddError(bilingual_str error)
    {
        if (!error.empty()) this->Info().errors.emplace_back(std::move(error));
    }

    void AddWarning(bilingual_str warning)
    {
        if (!warning.empty()) this->Info().warnings.emplace_back(std::move(warning));
    }

    template<typename S>
    void MoveMessages(S& src)
    {
        if (src.m_info) {
            if (!src.m_info->errors.empty()) detail::MoveMessages(src.m_info->errors, this->Info().errors);
            if (!src.m_info->warnings.empty()) detail::MoveMessages(src.m_info->warnings, this->Info().warnings);
        }
    }

    //! Operator moving warning and error messages from this result object to
    //! another one. Only moves message strings, does not change success or
    //! failure values of either Result object.
    template<typename O>
    Result&& operator>>(O&& other LIFETIMEBOUND) &&
    {
        other.MoveMessages(*this);
        return std::move(*this);
    }
};

//! Join error and warning messages in a space separated string. This is
//! intended for simple applications where there's probably only one error or
//! warning message to report, but multiple messages should not be lost if they
//! are present. More complicated applications should use GetErrors() and
//! GetWarning() methods directly.
template <typename T, typename F>
bilingual_str ErrorString(const Result<T, F>& result) { return detail::JoinMessages(result.GetErrors(), result.GetWarnings()); }
} // namespace util

#endif // BITCOIN_UTIL_RESULT_H
