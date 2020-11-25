
#ifndef FRV_FRVDEC_H_
#define FRV_FRVDEC_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  FRV_UNDEF = -1,
  FRV_PARTIAL = -2,
};

enum {
  FRV_REG_INV = (uint8_t) -1,
};

enum {
  FRV_INVALID = 0,
  // RV32I
  FRV_LB, FRV_LH, FRV_LW, FRV_LD, FRV_LBU, FRV_LHU, FRV_LWU,
  FRV_SB, FRV_SH, FRV_SW, FRV_SD,
  FRV_ADDI, FRV_SLLI, FRV_SLTI, FRV_SLTIU, FRV_XORI, FRV_SRAI, FRV_SRLI, FRV_ORI, FRV_ANDI,
  FRV_ADD, FRV_SLL, FRV_SLT, FRV_SLTU, FRV_XOR, FRV_SRL, FRV_OR, FRV_AND, FRV_SUB, FRV_SRA,
  FRV_FENCE, FRV_FENCEI,
  FRV_AUIPC, FRV_LUI,
  FRV_JAL, FRV_JALR,
  FRV_BEQ, FRV_BNE, FRV_BLT, FRV_BGE, FRV_BLTU, FRV_BGEU,
  FRV_ECALL,
  // RV64I
  FRV_ADDIW, FRV_SLLIW, FRV_SRAIW, FRV_SRLIW,
  FRV_ADDW, FRV_SLLW, FRV_SRLW, FRV_SUBW, FRV_SRAW,

  // RV32M, RV64M
  FRV_MUL, FRV_MULH, FRV_MULHSU, FRV_MULHU, FRV_DIV, FRV_DIVU, FRV_REM, FRV_REMU,
  FRV_MULW, FRV_DIVW, FRV_DIVUW, FRV_REMW, FRV_REMUW,

  // RV32A/RV64A
  FRV_LRW, FRV_SCW, FRV_LRD, FRV_SCD,
  FRV_AMOADDW, FRV_AMOSWAPW, FRV_AMOXORW, FRV_AMOORW, FRV_AMOANDW,
  FRV_AMOMINW, FRV_AMOMAXW, FRV_AMOMINUW, FRV_AMOMAXUW,
  FRV_AMOADDD, FRV_AMOSWAPD, FRV_AMOXORD, FRV_AMOORD, FRV_AMOANDD,
  FRV_AMOMIND, FRV_AMOMAXD, FRV_AMOMINUD, FRV_AMOMAXUD,

  // RV32/RV64 Zicsr
  FRV_CSRRW, FRV_CSRRS, FRV_CSRRC, FRV_CSRRWI, FRV_CSRRSI, FRV_CSRRCI,
};

typedef struct FrvInst FrvInst;
// Note: structure layout is unstable.
struct FrvInst {
  uint16_t mnem;
  uint8_t rd;
  uint8_t rs1;
  uint8_t rs2;
  uint8_t rs3;
  uint8_t misc;
  int32_t imm;
};

int frv_decode(size_t bufsz, const uint8_t* buf, FrvInst* frv_inst);

// Note: actual format is unstable.
void frv_format(const FrvInst* inst, size_t len, char* buf);

#ifdef __cplusplus
}
#endif

#endif
