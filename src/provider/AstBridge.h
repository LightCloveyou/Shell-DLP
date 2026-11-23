#pragma once
#include <string>
#include <string_view>

namespace guard {
struct AstResult {
    int decision = -1;
    std::string json;
};
unsigned AmsiContentLimit() noexcept;
AstResult ParseAst(std::wstring_view text) noexcept;
}
