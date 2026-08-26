module;
#include <vector>

namespace llvm {
	class Target;
	class MCInstrInfo;
	class MCRegisterInfo;
	class MCSubtargetInfo;
	class MCAsmInfo;
}

export module sba.lift:target;

import sba.arch;
import sba.ir;

namespace SBA::Lift {

	using namespace SBA::IR;
	using SBA::Arch::Target;

	template <Target T>
	inline std::vector<Operand> llvm_registers;

	template <Target T>
	inline const llvm::Target* target = nullptr;

	template <Target T>
	inline const llvm::MCInstrInfo* info_inst = nullptr;

	template <Target T>
	inline const llvm::MCRegisterInfo* info_reg = nullptr;

	template <Target T>
	inline const llvm::MCSubtargetInfo* info_cpu = nullptr;

	template <Target T>
	inline const llvm::MCAsmInfo* info_asm = nullptr;

}
