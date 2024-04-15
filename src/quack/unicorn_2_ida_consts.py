from enum import Enum, auto

import unicorn

import ida_idp
import ida_typeinf

class LocationType(Enum):
    arg = auto()
    result = auto()

linux_x64_fastcall = {
    LocationType.arg : [
        unicorn.x86_const.UC_X86_REG_RDI,
        unicorn.x86_const.UC_X86_REG_RSI,
        unicorn.x86_const.UC_X86_REG_RDX,
        unicorn.x86_const.UC_X86_REG_RCX,
        unicorn.x86_const.UC_X86_REG_R8,
        unicorn.x86_const.UC_X86_REG_R9
    ],
    LocationType.result :[
        unicorn.x86_const.UC_X86_REG_RAX
    ]
}

windows_x64_fastcall = {
    LocationType.arg :[
        unicorn.x86_const.UC_X86_REG_RCX,
        unicorn.x86_const.UC_X86_REG_RDX,
        unicorn.x86_const.UC_X86_REG_R8,
        unicorn.x86_const.UC_X86_REG_R9
    ],
    LocationType.result :[
        unicorn.x86_const.UC_X86_REG_RAX
    ]
}

default_x86_return_regs = {
    LocationType.arg :[
    ],
    LocationType.result :[
        unicorn.x86_const.UC_X86_REG_EAX
    ]
}

default_arm32_call = {
    LocationType.arg : [
        unicorn.arm_const.UC_ARM_REG_R0,
        unicorn.arm_const.UC_ARM_REG_R1,
        unicorn.arm_const.UC_ARM_REG_R2,
        unicorn.arm_const.UC_ARM_REG_R3,
    ],
    LocationType.result :[
        unicorn.arm_const.UC_ARM_REG_R0,
    ]
}

default_arm64_call = {
    LocationType.arg : [
        unicorn.arm64_const.UC_ARM64_REG_X0,
        unicorn.arm64_const.UC_ARM64_REG_X1,
        unicorn.arm64_const.UC_ARM64_REG_X2,
        unicorn.arm64_const.UC_ARM64_REG_X3,
    ],
    LocationType.result :[
        unicorn.arm64_const.UC_ARM64_REG_X0,
    ]
}

default_mips_call = {
    LocationType.arg : [
        unicorn.mips_const.UC_MIPS_REG_A0,
        unicorn.mips_const.UC_MIPS_REG_A1,
        unicorn.mips_const.UC_MIPS_REG_A2,
        unicorn.mips_const.UC_MIPS_REG_A3
        
    ],
    LocationType.result :[
        unicorn.mips_const.UC_MIPS_REG_V0
    ]
}

calling_conventions = {
    ida_idp.PLFM_386: {
        32: {
            ida_typeinf.COMP_MS: {
                ida_typeinf.CM_CC_CDECL : default_x86_return_regs,
                ida_typeinf.CM_CC_STDCALL : default_x86_return_regs
            }
        },
        64: {
            ida_typeinf.COMP_GNU: {
                ida_typeinf.CM_CC_FASTCALL : linux_x64_fastcall
            },
            ida_typeinf.COMP_MS: {
                ida_typeinf.CM_CC_FASTCALL : windows_x64_fastcall,
                ida_typeinf.CM_CC_CDECL : windows_x64_fastcall,
                ida_typeinf.CM_CC_STDCALL : windows_x64_fastcall
            }
        }
    },
    ida_idp.PLFM_ARM: {
        32: {
            ida_typeinf.COMP_GNU: {
                ida_typeinf.CM_CC_FASTCALL : default_arm32_call
            },
        },
        64: {
            ida_typeinf.COMP_GNU: {
                ida_typeinf.CM_CC_FASTCALL : default_arm64_call
            },
        }
    },
    ida_idp.PLFM_MIPS: {
        32: {
            ida_typeinf.COMP_GNU: {
                ida_typeinf.CM_CC_FASTCALL :default_mips_call,
                ida_typeinf.CM_CC_UNKNOWN : default_mips_call,
                ida_typeinf.CM_CC_CDECL : default_mips_call
            },
        },
        64: {
            ida_typeinf.COMP_GNU: {
                ida_typeinf.CM_CC_FASTCALL : default_mips_call
            },
        }
    }
}

x86_x64_reg_map = {
        "rax": {
            8: unicorn.x86_const.UC_X86_REG_RAX,
            4: unicorn.x86_const.UC_X86_REG_EAX,
            2: unicorn.x86_const.UC_X86_REG_AX,
            1: unicorn.x86_const.UC_X86_REG_AL
        },
        "rbx": {
            8: unicorn.x86_const.UC_X86_REG_RBX,
            4: unicorn.x86_const.UC_X86_REG_EBX,
            2: unicorn.x86_const.UC_X86_REG_BX,
            1: unicorn.x86_const.UC_X86_REG_BL
        },
        "rcx": {
            8: unicorn.x86_const.UC_X86_REG_RCX,
            4: unicorn.x86_const.UC_X86_REG_ECX,
            2: unicorn.x86_const.UC_X86_REG_CX,
            1: unicorn.x86_const.UC_X86_REG_CL
        },
        "rdx": {
            8: unicorn.x86_const.UC_X86_REG_RDX,
            4: unicorn.x86_const.UC_X86_REG_EDX,
            2: unicorn.x86_const.UC_X86_REG_DX,
            1: unicorn.x86_const.UC_X86_REG_DL
        },
        "rdi": {
            8: unicorn.x86_const.UC_X86_REG_RDI,
            4: unicorn.x86_const.UC_X86_REG_EDI,
            2: unicorn.x86_const.UC_X86_REG_DI,
            1: unicorn.x86_const.UC_X86_REG_DIL,
        },
        "rsi": {
            8: unicorn.x86_const.UC_X86_REG_RSI,
            4: unicorn.x86_const.UC_X86_REG_ESI,
            2: unicorn.x86_const.UC_X86_REG_SI,
            1: unicorn.x86_const.UC_X86_REG_SIL,
        },
        "r8": {
            8: unicorn.x86_const.UC_X86_REG_R8,
            4: unicorn.x86_const.UC_X86_REG_R8D,
            2: unicorn.x86_const.UC_X86_REG_R8W,
            1: unicorn.x86_const.UC_X86_REG_R8B,
        },
        "r9": {
            8: unicorn.x86_const.UC_X86_REG_R9,
            4: unicorn.x86_const.UC_X86_REG_R9D,
            2: unicorn.x86_const.UC_X86_REG_R9W,
            1: unicorn.x86_const.UC_X86_REG_R9B,
        },
        "r10": {
            8: unicorn.x86_const.UC_X86_REG_R10,
            4: unicorn.x86_const.UC_X86_REG_R10D,
            2: unicorn.x86_const.UC_X86_REG_R10W,
            1: unicorn.x86_const.UC_X86_REG_R10B,
        },
        "r11": {
            8: unicorn.x86_const.UC_X86_REG_R11,
            4: unicorn.x86_const.UC_X86_REG_R11D,
            2: unicorn.x86_const.UC_X86_REG_R11W,
            1: unicorn.x86_const.UC_X86_REG_R11B,
        },
        "r12": {
            8: unicorn.x86_const.UC_X86_REG_R12,
            4: unicorn.x86_const.UC_X86_REG_R12D,
            2: unicorn.x86_const.UC_X86_REG_R12W,
            1: unicorn.x86_const.UC_X86_REG_R12B,
        },
        "r13": {
            8: unicorn.x86_const.UC_X86_REG_R13,
            4: unicorn.x86_const.UC_X86_REG_R13D,
            2: unicorn.x86_const.UC_X86_REG_R13W,
            1: unicorn.x86_const.UC_X86_REG_R13B,
        },
        "r14": {
            8: unicorn.x86_const.UC_X86_REG_R14,
            4: unicorn.x86_const.UC_X86_REG_R14D,
            2: unicorn.x86_const.UC_X86_REG_R14W,
            1: unicorn.x86_const.UC_X86_REG_R14B,
        },
        "r15": {
            8: unicorn.x86_const.UC_X86_REG_R15,
            4: unicorn.x86_const.UC_X86_REG_R15D,
            2: unicorn.x86_const.UC_X86_REG_R15W,
            1: unicorn.x86_const.UC_X86_REG_R15B,
        },
        "xmm0": {
            8: unicorn.x86_const.UC_X86_REG_XMM0
        },
        "xmm1": {
            8: unicorn.x86_const.UC_X86_REG_XMM1
        },
        "xmm2": {
            8: unicorn.x86_const.UC_X86_REG_XMM2
        },
}

arch_info = {
    ida_idp.PLFM_386 :{
        32:  (unicorn.UC_ARCH_X86, unicorn.UC_MODE_32, unicorn.x86_const.UC_X86_REG_ESP, 4),
        64: (unicorn.UC_ARCH_X86, unicorn.UC_MODE_64, unicorn.x86_const.UC_X86_REG_RSP, 8)
    },
    ida_idp.PLFM_ARM :{
        32: (unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM, unicorn.arm_const.UC_ARM_REG_SP, 4),
        64: (unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM, unicorn.arm64_const.UC_ARM64_REG_SP, 8)
    },
    ida_idp.PLFM_MIPS :{
        32: (unicorn.UC_ARCH_MIPS, unicorn.UC_MODE_MIPS32, unicorn.mips_const.UC_MIPS_REG_SP, 4),
        64: (unicorn.UC_ARCH_MIPS, unicorn.UC_MODE_MIPS64, unicorn.mips_const.UC_MIPS_REG_SP, 8)
    }
}
