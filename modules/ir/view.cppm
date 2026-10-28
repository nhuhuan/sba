module;
#include <cstdint>
#include <span>

export module sba.ir:view;

import :syntax;
import :semantics;
import :context;

export namespace SBA::IR {

    /* ----------------------------- Operation ------------------------------ */

    struct Operation {
        Operator opcode;
        std::span<const Operand> operands;

        constexpr Operand dst() const noexcept {
            return operands.empty() ? Operand{} : operands.front();
        }

        constexpr std::span<const Operand> src() const noexcept {
            return operands.size() > 1 ? operands.subspan(1) :
                                         std::span<const Operand>{};
        }
    };

    /* -------------------------------- View -------------------------------- */

    class View {
    private:
        const uint8_t* data_;

        Instruction::Tag tag() const noexcept { return { *data_ }; }

    public:
        constexpr explicit View(const uint8_t* data) noexcept : data_(data) {}

        bool valid() const noexcept {
            return tag().valid();
        }

        uint8_t count() const noexcept {
            return tag().count();
        }

        uint8_t length() const noexcept {
            return tag().length();
        }

        struct Iterator {
            const Operator* opcode_ptr;
            const Operand* operand_ptr;
            uint8_t index;

            Operation operator*() const noexcept {
                Operator opcode = opcode_ptr[index];
                return Operation {
                    .opcode   = opcode,
                    .operands = std::span(operand_ptr, arity(opcode))
                };
            }

            Iterator& operator++() noexcept {
                operand_ptr += arity(opcode_ptr[index]);
                index++;
                return *this;
            }

            bool operator!=(const Iterator& other) const noexcept {
                return index != other.index;
            }
        };

        Iterator begin() const noexcept {
            const auto* opcode_ptr = (const Operator*)(data_ + sizeof(Instruction::Tag));
            return Iterator {
                .opcode_ptr  = opcode_ptr,
                .operand_ptr = (const Operand*)(opcode_ptr + count()),
                .index       = 0
            };
        }

        Iterator end() const noexcept {
            return Iterator {
                .opcode_ptr = nullptr,
                .operand_ptr = nullptr,
                .index = count()
            };
        }
    };

    inline View Context::operator[](Instruction i) const noexcept {
        return View { &ins[i.index] };
    }

}
