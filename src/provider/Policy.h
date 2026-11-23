#pragma once

#include <string_view>

namespace guard {
enum class Decision { Uncovered, InformationMissing, NoMatch, Block };
bool IsPowerShell7(std::wstring_view app) noexcept;
Decision Evaluate(std::wstring_view text) noexcept;
}
