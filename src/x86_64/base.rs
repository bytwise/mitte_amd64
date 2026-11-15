use mitte_core::EmitSlice;

use super::types::*;
use super::reg::{Reg8, Reg16, Reg32, Reg64};
use super::ptr::{Mem, Byte, Word, DWord, QWord};
use super::error::Error;
use super::fixup::FixupKind;
use super::encoding::*;

use crate::macros::forward;


pub trait Emit: EmitSlice {
    fn emit_jcc_rel8_label<Label>(&mut self, cond: Condition, label: &mut Label)
        -> Result<(), Error<Self::Error>>
    where Self: mitte_core::Emit,
          Label: mitte_core::Label<Self, FixupKind>
    {
        self.emit_branch(
            label,
            FixupKind::PcRel8,
            |e, offset| {
                e.emit_jcc_rel8(cond, (offset as i8).into())
            },
        )
    }

    fn emit_jcc_rel32_label<Label>(&mut self, cond: Condition, label: &mut Label)
        -> Result<(), Error<Self::Error>>
    where Self: mitte_core::Emit,
          Label: mitte_core::Label<Self, FixupKind>
    {
        self.emit_branch(
            label,
            FixupKind::PcRel32,
            |e, offset| {
                e.emit_jcc_rel32(cond, (offset as i32).into())
            },
        )
    }

    fn emit_jmp_rel8_label<Label>(&mut self, label: &mut Label) -> Result<(), Error<Self::Error>>
    where Self: mitte_core::Emit,
          Label: mitte_core::Label<Self, FixupKind>
    {
        self.emit_branch(
            label,
            FixupKind::PcRel8,
            |e, offset| {
                e.emit_jmp_rel8((offset as i8).into())
            },
        )
    }

    fn emit_jmp_rel32_label<Label>(&mut self, label: &mut Label) -> Result<(), Error<Self::Error>>
    where Self: mitte_core::Emit,
          Label: mitte_core::Label<Self, FixupKind>
    {
        self.emit_branch(
            label,
            FixupKind::PcRel32,
            |e, offset| {
                e.emit_jmp_rel32((offset as i32).into())
            },
        )
    }

    forward! {
        emit_adc_al_i8(src: u8) => (Size8, 0x14);
        emit_adc_ax_i16(src: u16) => (Size16, 0x15);
        emit_adc_eax_i32(src: u32) => (Size32, 0x15);
        emit_adc_rax_i32(src: i32) => (Size64, 0x15);

        emit_adc_ri8(dst: Reg8, src: u8) => (0x80, ModRmIndex(2));
        emit_adc_ri16(dst: Reg16, src: u16) => (0x81, ModRmIndex(2));
        emit_adc_ri32(dst: Reg32, src: u32) => (0x81, ModRmIndex(2));
        emit_adc_r64_i32(dst: Reg64, src: i32) => (0x81, ModRmIndex(2));

        emit_adc_r16_i8(dst: Reg16, src: i8) => (0x83, ModRmIndex(2));
        emit_adc_r32_i8(dst: Reg32, src: i8) => (0x83, ModRmIndex(2));
        emit_adc_r64_i8(dst: Reg64, src: i8) => (0x83, ModRmIndex(2));

        emit_adc_rr8(dst: Reg8, src: Reg8) => (MR, 0x10);
        emit_adc_rr16(dst: Reg16, src: Reg16) => (MR, 0x11);
        emit_adc_rr32(dst: Reg32, src: Reg32) => (MR, 0x11);
        emit_adc_rr64(dst: Reg64, src: Reg64) => (MR, 0x11);

        emit_adc_rm8<P>(dst: Reg8, src: Byte<P>) where P: Mem => (0x12);
        emit_adc_rm16<P>(dst: Reg16, src: Word<P>) where P: Mem => (0x13);
        emit_adc_rm32<P>(dst: Reg32, src: DWord<P>) where P: Mem => (0x13);
        emit_adc_rm64<P>(dst: Reg64, src: QWord<P>) where P: Mem => (0x13);

        emit_adc_mi8<P>(dst: Byte<P>, src: u8) where P: Mem => (0x80, ModRmIndex(2));
        emit_adc_mi16<P>(dst: Word<P>, src: u16) where P: Mem => (0x81, ModRmIndex(2));
        emit_adc_mi32<P>(dst: DWord<P>, src: u32) where P: Mem => (0x81, ModRmIndex(2));
        emit_adc_m64_i32<P>(dst: QWord<P>, src: i32) where P: Mem => (0x81, ModRmIndex(2));

        emit_adc_m16_i8<P>(dst: Word<P>, src: i8) where P: Mem => (0x83, ModRmIndex(2));
        emit_adc_m32_i8<P>(dst: DWord<P>, src: i8) where P: Mem => (0x83, ModRmIndex(2));
        emit_adc_m64_i8<P>(dst: QWord<P>, src: i8) where P: Mem => (0x83, ModRmIndex(2));

        emit_adc_mr8<P>(dst: Byte<P>, src: Reg8) where P: Mem => (0x10);
        emit_adc_mr16<P>(dst: Word<P>, src: Reg16) where P: Mem => (0x11);
        emit_adc_mr32<P>(dst: DWord<P>, src: Reg32) where P: Mem => (0x11);
        emit_adc_mr64<P>(dst: QWord<P>, src: Reg64) where P: Mem => (0x11);

        emit_add_al_i8(src: u8) => (Size8, 0x04);
        emit_add_ax_i16(src: u16) => (Size16, 0x05);
        emit_add_eax_i32(src: u32) => (Size32, 0x05);
        emit_add_rax_i32(src: i32) => (Size64, 0x05);

        emit_add_ri8(dst: Reg8, src: u8) => (0x80, ModRmIndex(0));
        emit_add_ri16(dst: Reg16, src: u16) => (0x81, ModRmIndex(0));
        emit_add_ri32(dst: Reg32, src: u32) => (0x81, ModRmIndex(0));
        emit_add_r64_i32(dst: Reg64, src: i32) => (0x81, ModRmIndex(0));

        emit_add_r16_i8(dst: Reg16, src: i8) => (0x83, ModRmIndex(0));
        emit_add_r32_i8(dst: Reg32, src: i8) => (0x83, ModRmIndex(0));
        emit_add_r64_i8(dst: Reg64, src: i8) => (0x83, ModRmIndex(0));

        emit_add_rr8(dst: Reg8, src: Reg8) => (MR, 0x00);
        emit_add_rr16(dst: Reg16, src: Reg16) => (MR, 0x01);
        emit_add_rr32(dst: Reg32, src: Reg32) => (MR, 0x01);
        emit_add_rr64(dst: Reg64, src: Reg64) => (MR, 0x01);

        emit_add_rm8<P>(dst: Reg8, src: Byte<P>) where P: Mem => (0x02);
        emit_add_rm16<P>(dst: Reg16, src: Word<P>) where P: Mem => (0x03);
        emit_add_rm32<P>(dst: Reg32, src: DWord<P>) where P: Mem => (0x03);
        emit_add_rm64<P>(dst: Reg64, src: QWord<P>) where P: Mem => (0x03);

        emit_add_mi8<P>(dst: Byte<P>, src: u8) where P: Mem => (0x80, ModRmIndex(0));
        emit_add_mi16<P>(dst: Word<P>, src: u16) where P: Mem => (0x81, ModRmIndex(0));
        emit_add_mi32<P>(dst: DWord<P>, src: u32) where P: Mem => (0x81, ModRmIndex(0));
        emit_add_m64_i32<P>(dst: QWord<P>, src: i32) where P: Mem => (0x81, ModRmIndex(0));

        emit_add_m16_i8<P>(dst: Word<P>, src: i8) where P: Mem => (0x83, ModRmIndex(0));
        emit_add_m32_i8<P>(dst: DWord<P>, src: i8) where P: Mem => (0x83, ModRmIndex(0));
        emit_add_m64_i8<P>(dst: QWord<P>, src: i8) where P: Mem => (0x83, ModRmIndex(0));

        emit_add_mr8<P>(dst: Byte<P>, src: Reg8) where P: Mem => (0x00);
        emit_add_mr16<P>(dst: Word<P>, src: Reg16) where P: Mem => (0x01);
        emit_add_mr32<P>(dst: DWord<P>, src: Reg32) where P: Mem => (0x01);
        emit_add_mr64<P>(dst: QWord<P>, src: Reg64) where P: Mem => (0x01);

        emit_and_al_i8(src: u8) => (Size8, 0x24);
        emit_and_ax_i16(src: u16) => (Size16, 0x25);
        emit_and_eax_i32(src: u32) => (Size32, 0x25);
        emit_and_rax_i32(src: i32) => (Size64, 0x25);

        emit_and_ri8(dst: Reg8, src: u8) => (0x80, ModRmIndex(4));
        emit_and_ri16(dst: Reg16, src: u16) => (0x81, ModRmIndex(4));
        emit_and_ri32(dst: Reg32, src: u32) => (0x81, ModRmIndex(4));
        emit_and_r64_i32(dst: Reg64, src: i32) => (0x81, ModRmIndex(4));

        emit_and_r16_i8(dst: Reg16, src: i8) => (0x83, ModRmIndex(4));
        emit_and_r32_i8(dst: Reg32, src: i8) => (0x83, ModRmIndex(4));
        emit_and_r64_i8(dst: Reg64, src: i8) => (0x83, ModRmIndex(4));

        emit_and_rr8(dst: Reg8, src: Reg8) => (MR, 0x20);
        emit_and_rr16(dst: Reg16, src: Reg16) => (MR, 0x21);
        emit_and_rr32(dst: Reg32, src: Reg32) => (MR, 0x21);
        emit_and_rr64(dst: Reg64, src: Reg64) => (MR, 0x21);

        emit_and_rm8<P>(dst: Reg8, src: Byte<P>) where P: Mem => (0x22);
        emit_and_rm16<P>(dst: Reg16, src: Word<P>) where P: Mem => (0x23);
        emit_and_rm32<P>(dst: Reg32, src: DWord<P>) where P: Mem => (0x23);
        emit_and_rm64<P>(dst: Reg64, src: QWord<P>) where P: Mem => (0x23);

        emit_and_mi8<P>(dst: Byte<P>, src: u8) where P: Mem => (0x80, ModRmIndex(4));
        emit_and_mi16<P>(dst: Word<P>, src: u16) where P: Mem => (0x81, ModRmIndex(4));
        emit_and_mi32<P>(dst: DWord<P>, src: u32) where P: Mem => (0x81, ModRmIndex(4));
        emit_and_m64_i32<P>(dst: QWord<P>, src: i32) where P: Mem => (0x81, ModRmIndex(4));

        emit_and_m16_i8<P>(dst: Word<P>, src: i8) where P: Mem => (0x83, ModRmIndex(4));
        emit_and_m32_i8<P>(dst: DWord<P>, src: i8) where P: Mem => (0x83, ModRmIndex(4));
        emit_and_m64_i8<P>(dst: QWord<P>, src: i8) where P: Mem => (0x83, ModRmIndex(4));

        emit_and_mr8<P>(dst: Byte<P>, src: Reg8) where P: Mem => (0x20);
        emit_and_mr16<P>(dst: Word<P>, src: Reg16) where P: Mem => (0x21);
        emit_and_mr32<P>(dst: DWord<P>, src: Reg32) where P: Mem => (0x21);
        emit_and_mr64<P>(dst: QWord<P>, src: Reg64) where P: Mem => (0x21);

        emit_bsf_rr16(dst: Reg16, src: Reg16) => (RM, 0x0f, 0xbc);
        emit_bsf_rr32(dst: Reg32, src: Reg32) => (RM, 0x0f, 0xbc);
        emit_bsf_rr64(dst: Reg64, src: Reg64) => (RM, 0x0f, 0xbc);

        emit_bsf_rm16<P>(dst: Reg16, src: Word<P>) where P: Mem => (0x0f, 0xbc);
        emit_bsf_rm32<P>(dst: Reg32, src: DWord<P>) where P: Mem => (0x0f, 0xbc);
        emit_bsf_rm64<P>(dst: Reg64, src: QWord<P>) where P: Mem => (0x0f, 0xbc);

        emit_bsr_rr16(dst: Reg16, src: Reg16) => (RM, 0x0f, 0xbd);
        emit_bsr_rr32(dst: Reg32, src: Reg32) => (RM, 0x0f, 0xbd);
        emit_bsr_rr64(dst: Reg64, src: Reg64) => (RM, 0x0f, 0xbd);

        emit_bsr_rm16<P>(dst: Reg16, src: Word<P>) where P: Mem => (0x0f, 0xbd);
        emit_bsr_rm32<P>(dst: Reg32, src: DWord<P>) where P: Mem => (0x0f, 0xbd);
        emit_bsr_rm64<P>(dst: Reg64, src: QWord<P>) where P: Mem => (0x0f, 0xbd);

        emit_call_rel32(offset: Rel32) => (0xe8);
        emit_call_r64(reg: Reg64) => (NoRexW, 0xff, ModRmIndex(2));

        emit_cdq() => (0x99);

        emit_cmovcc_rr16(cond: Condition, dst: Reg16, src: Reg16) => (RM, 0x0f, OpPlusCondition(0x40));
        emit_cmovcc_rr32(cond: Condition, dst: Reg32, src: Reg32) => (RM, 0x0f, OpPlusCondition(0x40));
        emit_cmovcc_rr64(cond: Condition, dst: Reg64, src: Reg64) => (RM, 0x0f, OpPlusCondition(0x40));

        emit_cmovcc_rm16<P>(cond: Condition, dst: Reg16, src: Word<P>) where P: Mem => (0x0f, OpPlusCondition(0x40));
        emit_cmovcc_rm32<P>(cond: Condition, dst: Reg32, src: DWord<P>) where P: Mem => (0x0f, OpPlusCondition(0x40));
        emit_cmovcc_rm64<P>(cond: Condition, dst: Reg64, src: QWord<P>) where P: Mem => (0x0f, OpPlusCondition(0x40));

        emit_cmp_al_i8(src: u8) => (Size8, 0x3c);
        emit_cmp_ax_i16(src: u16) => (Size16, 0x3d);
        emit_cmp_eax_i32(src: u32) => (Size32, 0x3d);
        emit_cmp_rax_i32(src: i32) => (Size64, 0x3d);

        emit_cmp_ri8(dst: Reg8, src: u8) => (0x80, ModRmIndex(7));
        emit_cmp_ri16(dst: Reg16, src: u16) => (0x81, ModRmIndex(7));
        emit_cmp_ri32(dst: Reg32, src: u32) => (0x81, ModRmIndex(7));
        emit_cmp_r64_i32(dst: Reg64, src: i32) => (0x81, ModRmIndex(7));

        emit_cmp_r16_i8(dst: Reg16, src: i8) => (0x83, ModRmIndex(7));
        emit_cmp_r32_i8(dst: Reg32, src: i8) => (0x83, ModRmIndex(7));
        emit_cmp_r64_i8(dst: Reg64, src: i8) => (0x83, ModRmIndex(7));

        emit_cmp_rr8(dst: Reg8, src: Reg8) => (MR, 0x38);
        emit_cmp_rr16(dst: Reg16, src: Reg16) => (MR, 0x39);
        emit_cmp_rr32(dst: Reg32, src: Reg32) => (MR, 0x39);
        emit_cmp_rr64(dst: Reg64, src: Reg64) => (MR, 0x39);

        emit_cmp_rm8<P>(dst: Reg8, src: Byte<P>) where P: Mem => (0x3a);
        emit_cmp_rm16<P>(dst: Reg16, src: Word<P>) where P: Mem => (0x3b);
        emit_cmp_rm32<P>(dst: Reg32, src: DWord<P>) where P: Mem => (0x3b);
        emit_cmp_rm64<P>(dst: Reg64, src: QWord<P>) where P: Mem => (0x3b);

        emit_cmp_mi8<P>(dst: Byte<P>, src: u8) where P: Mem => (0x80, ModRmIndex(7));
        emit_cmp_mi16<P>(dst: Word<P>, src: u16) where P: Mem => (0x81, ModRmIndex(7));
        emit_cmp_mi32<P>(dst: DWord<P>, src: u32) where P: Mem => (0x81, ModRmIndex(7));
        emit_cmp_m64_i32<P>(dst: QWord<P>, src: i32) where P: Mem => (0x81, ModRmIndex(7));

        emit_cmp_m16_i8<P>(dst: Word<P>, src: i8) where P: Mem => (0x83, ModRmIndex(7));
        emit_cmp_m32_i8<P>(dst: DWord<P>, src: i8) where P: Mem => (0x83, ModRmIndex(7));
        emit_cmp_m64_i8<P>(dst: QWord<P>, src: i8) where P: Mem => (0x83, ModRmIndex(7));

        emit_cmp_mr8<P>(dst: Byte<P>, src: Reg8) where P: Mem => (0x38);
        emit_cmp_mr16<P>(dst: Word<P>, src: Reg16) where P: Mem => (0x39);
        emit_cmp_mr32<P>(dst: DWord<P>, src: Reg32) where P: Mem => (0x39);
        emit_cmp_mr64<P>(dst: QWord<P>, src: Reg64) where P: Mem => (0x39);

        emit_dec_r8(dst: Reg8) => (0xfe, ModRmIndex(1));
        emit_dec_r16(dst: Reg16) => (0xff, ModRmIndex(1));
        emit_dec_r32(dst: Reg32) => (0xff, ModRmIndex(1));
        emit_dec_r64(dst: Reg64) => (0xff, ModRmIndex(1));

        emit_dec_m8<P>(dst: Byte<P>) where P: Mem => (0xfe, ModRmIndex(1));
        emit_dec_m16<P>(dst: Word<P>) where P: Mem => (0xff, ModRmIndex(1));
        emit_dec_m32<P>(dst: DWord<P>) where P: Mem => (0xff, ModRmIndex(1));
        emit_dec_m64<P>(dst: QWord<P>) where P: Mem => (0xff, ModRmIndex(1));

        emit_div_r8(dst: Reg8) => (0xf6, ModRmIndex(6));
        emit_div_r16(dst: Reg16) => (0xf7, ModRmIndex(6));
        emit_div_r32(dst: Reg32) => (0xf7, ModRmIndex(6));
        emit_div_r64(dst: Reg64) => (0xf7, ModRmIndex(6));

        emit_div_m8<P>(dst: Byte<P>) where P: Mem => (0xf6, ModRmIndex(6));
        emit_div_m16<P>(dst: Word<P>) where P: Mem => (0xf7, ModRmIndex(6));
        emit_div_m32<P>(dst: DWord<P>) where P: Mem => (0xf7, ModRmIndex(6));
        emit_div_m64<P>(dst: QWord<P>) where P: Mem => (0xf7, ModRmIndex(6));

        emit_inc_r8(dst: Reg8) => (0xfe, ModRmIndex(0));
        emit_inc_r16(dst: Reg16) => (0xff, ModRmIndex(0));
        emit_inc_r32(dst: Reg32) => (0xff, ModRmIndex(0));
        emit_inc_r64(dst: Reg64) => (0xff, ModRmIndex(0));

        emit_jcc_rel8(cond: Condition, offset: Rel8) => (OpPlusCondition(0x70));
        emit_jcc_rel32(cond: Condition, offset: Rel32) => (0x0f, OpPlusCondition(0x80));

        emit_jmp_rel8(offset: Rel8) => (0xeb);
        emit_jmp_rel32(offset: Rel32) => (0xe9);
        emit_jmp_r64(reg: Reg64) => (NoRexW, 0xff, ModRmIndex(4));

        emit_idiv_r8(src: Reg8) => (0xf6, ModRmIndex(7));
        emit_idiv_r16(src: Reg16) => (0xf7, ModRmIndex(7));
        emit_idiv_r32(src: Reg32) => (0xf7, ModRmIndex(7));
        emit_idiv_r64(src: Reg64) => (0xf7, ModRmIndex(7));

        emit_idiv_m8<P>(src: Byte<P>) where P: Mem => (0xf6, ModRmIndex(7));
        emit_idiv_m16<P>(src: Word<P>) where P: Mem => (0xf7, ModRmIndex(7));
        emit_idiv_m32<P>(src: DWord<P>) where P: Mem => (0xf7, ModRmIndex(7));
        emit_idiv_m64<P>(src: QWord<P>) where P: Mem => (0xf7, ModRmIndex(7));

        emit_imul_r8(src: Reg8) => (0xf6, ModRmIndex(5));
        emit_imul_r16(src: Reg16) => (0xf7, ModRmIndex(5));
        emit_imul_r32(src: Reg32) => (0xf7, ModRmIndex(5));
        emit_imul_r64(src: Reg64) => (0xf7, ModRmIndex(5));

        emit_imul_m8<P>(src: Byte<P>) where P: Mem => (0xf6, ModRmIndex(5));
        emit_imul_m16<P>(src: Word<P>) where P: Mem => (0xf7, ModRmIndex(5));
        emit_imul_m32<P>(src: DWord<P>) where P: Mem => (0xf7, ModRmIndex(5));
        emit_imul_m64<P>(src: QWord<P>) where P: Mem => (0xf7, ModRmIndex(5));

        emit_inc_m8<P>(dst: Byte<P>) where P: Mem => (0xfe, ModRmIndex(0));
        emit_inc_m16<P>(dst: Word<P>) where P: Mem => (0xff, ModRmIndex(0));
        emit_inc_m32<P>(dst: DWord<P>) where P: Mem => (0xff, ModRmIndex(0));
        emit_inc_m64<P>(dst: QWord<P>) where P: Mem => (0xff, ModRmIndex(0));

        emit_lea_rm16<P>(dst: Reg16, p: Word<P>) where P: Mem => (0x8d);
        emit_lea_rm32<P>(dst: Reg32, p: DWord<P>) where P: Mem => (0x8d);
        emit_lea_rm64<P>(dst: Reg64, p: QWord<P>) where P: Mem => (0x8d);

        emit_mul_r8(src: Reg8) => (0xf6, ModRmIndex(4));
        emit_mul_r16(src: Reg16) => (0xf7, ModRmIndex(4));
        emit_mul_r32(src: Reg32) => (0xf7, ModRmIndex(4));
        emit_mul_r64(src: Reg64) => (0xf7, ModRmIndex(4));

        emit_mul_m8<P>(src: Byte<P>) where P: Mem => (0xf6, ModRmIndex(4));
        emit_mul_m16<P>(src: Word<P>) where P: Mem => (0xf7, ModRmIndex(4));
        emit_mul_m32<P>(src: DWord<P>) where P: Mem => (0xf7, ModRmIndex(4));
        emit_mul_m64<P>(src: QWord<P>) where P: Mem => (0xf7, ModRmIndex(4));

        emit_mov_ri8(dst: Reg8, src: u8) => (OpPlusReg(0xb0));
        emit_mov_ri16(dst: Reg16, src: u16) => (OpPlusReg(0xb8));
        emit_mov_ri32(dst: Reg32, src: u32) => (OpPlusReg(0xb8));
        emit_mov_ri64(dst: Reg64, src: u64) => (OpPlusReg(0xb8));
        emit_mov_r64_i32(dst: Reg64, src: i32) => (0xc7, ModRmIndex(0));

        emit_mov_rr8(dst: Reg8, src: Reg8) => (MR, 0x88);
        emit_mov_rr16(dst: Reg16, src: Reg16) => (MR, 0x89);
        emit_mov_rr32(dst: Reg32, src: Reg32) => (MR, 0x89);
        emit_mov_rr64(dst: Reg64, src: Reg64) => (MR, 0x89);

        emit_mov_rm8<P>(dst: Reg8, src: Byte<P>) where P: Mem => (0x8a);
        emit_mov_rm16<P>(dst: Reg16, src: Word<P>) where P: Mem => (0x8b);
        emit_mov_rm32<P>(dst: Reg32, src: DWord<P>) where P: Mem => (0x8b);
        emit_mov_rm64<P>(dst: Reg64, src: QWord<P>) where P: Mem => (0x8b);

        emit_mov_mi8<P>(dst: Byte<P>, src: u8) where P: Mem => (0xc6, ModRmIndex(0));
        emit_mov_mi16<P>(dst: Word<P>, src: u16) where P: Mem => (0xc7, ModRmIndex(0));
        emit_mov_mi32<P>(dst: DWord<P>, src: u32) where P: Mem => (0xc7, ModRmIndex(0));
        emit_mov_m64_i32<P>(dst: QWord<P>, src: i32) where P: Mem => (0xc7, ModRmIndex(0));

        emit_mov_mr8<P>(dst: Byte<P>, src: Reg8) where P: Mem => (0x88);
        emit_mov_mr16<P>(dst: Word<P>, src: Reg16) where P: Mem => (0x89);
        emit_mov_mr32<P>(dst: DWord<P>, src: Reg32) where P: Mem => (0x89);
        emit_mov_mr64<P>(dst: QWord<P>, src: Reg64) where P: Mem => (0x89);

        emit_movsx_r16_r8(dst: Reg16, src: Reg8) => (RM, Size16, 0x0f, 0xbe);
        emit_movsx_r32_r8(dst: Reg32, src: Reg8) => (RM, Size32, 0x0f, 0xbe);
        emit_movsx_r64_r8(dst: Reg64, src: Reg8) => (RM, Size64, 0x0f, 0xbe);
        emit_movsx_r32_r16(dst: Reg32, src: Reg16) => (RM, Size32, 0x0f, 0xbf);
        emit_movsx_r64_r16(dst: Reg64, src: Reg16) => (RM, Size64, 0x0f, 0xbf);

        emit_movsx_r16_m8<P>(dst: Reg16, src: Byte<P>) where P: Mem => (Size16, 0x0f, 0xbe);
        emit_movsx_r32_m8<P>(dst: Reg32, src: Byte<P>) where P: Mem => (Size32, 0x0f, 0xbe);
        emit_movsx_r64_m8<P>(dst: Reg64, src: Byte<P>) where P: Mem => (Size64, 0x0f, 0xbe);
        emit_movsx_r32_m16<P>(dst: Reg32, src: Word<P>) where P: Mem => (Size32, 0x0f, 0xbf);
        emit_movsx_r64_m16<P>(dst: Reg64, src: Word<P>) where P: Mem => (Size64, 0x0f, 0xbf);

        emit_movzx_r16_r8(dst: Reg16, src: Reg8) => (RM, Size16, 0x0f, 0xb6);
        emit_movzx_r32_r8(dst: Reg32, src: Reg8) => (RM, Size32, 0x0f, 0xb6);
        emit_movzx_r64_r8(dst: Reg64, src: Reg8) => (RM, Size64, 0x0f, 0xb6);
        emit_movzx_r32_r16(dst: Reg32, src: Reg16) => (RM, Size32, 0x0f, 0xb7);
        emit_movzx_r64_r16(dst: Reg64, src: Reg16) => (RM, Size64, 0x0f, 0xb7);

        emit_movzx_r16_m8<P>(dst: Reg16, src: Byte<P>) where P: Mem => (Size16, 0x0f, 0xb6);
        emit_movzx_r32_m8<P>(dst: Reg32, src: Byte<P>) where P: Mem => (Size32, 0x0f, 0xb6);
        emit_movzx_r64_m8<P>(dst: Reg64, src: Byte<P>) where P: Mem => (Size64, 0x0f, 0xb6);
        emit_movzx_r32_m16<P>(dst: Reg32, src: Word<P>) where P: Mem => (Size32, 0x0f, 0xb7);
        emit_movzx_r64_m16<P>(dst: Reg64, src: Word<P>) where P: Mem => (Size64, 0x0f, 0xb7);

        emit_neg_r8(dst: Reg8) => (0xf6, ModRmIndex(3));
        emit_neg_r16(dst: Reg16) => (0xf7, ModRmIndex(3));
        emit_neg_r32(dst: Reg32) => (0xf7, ModRmIndex(3));
        emit_neg_r64(dst: Reg64) => (0xf7, ModRmIndex(3));

        emit_neg_m8<P>(dst: Byte<P>) where P: Mem => (0xf6, ModRmIndex(3));
        emit_neg_m16<P>(dst: Word<P>) where P: Mem => (0xf7, ModRmIndex(3));
        emit_neg_m32<P>(dst: DWord<P>) where P: Mem => (0xf7, ModRmIndex(3));
        emit_neg_m64<P>(dst: QWord<P>) where P: Mem => (0xf7, ModRmIndex(3));

        emit_nop() => (0x90);

        emit_not_r8(dst: Reg8) => (0xf6, ModRmIndex(2));
        emit_not_r16(dst: Reg16) => (0xf7, ModRmIndex(2));
        emit_not_r32(dst: Reg32) => (0xf7, ModRmIndex(2));
        emit_not_r64(dst: Reg64) => (0xf7, ModRmIndex(2));

        emit_not_m8<P>(dst: Byte<P>) where P: Mem => (0xf6, ModRmIndex(2));
        emit_not_m16<P>(dst: Word<P>) where P: Mem => (0xf7, ModRmIndex(2));
        emit_not_m32<P>(dst: DWord<P>) where P: Mem => (0xf7, ModRmIndex(2));
        emit_not_m64<P>(dst: QWord<P>) where P: Mem => (0xf7, ModRmIndex(2));

        emit_or_al_i8(src: u8) => (Size8, 0x0c);
        emit_or_ax_i16(src: u16) => (Size16, 0x0d);
        emit_or_eax_i32(src: u32) => (Size32, 0x0d);
        emit_or_rax_i32(src: i32) => (Size64, 0x0d);

        emit_or_ri8(dst: Reg8, src: u8) => (0x80, ModRmIndex(1));
        emit_or_ri16(dst: Reg16, src: u16) => (0x81, ModRmIndex(1));
        emit_or_ri32(dst: Reg32, src: u32) => (0x81, ModRmIndex(1));
        emit_or_r64_i32(dst: Reg64, src: i32) => (0x81, ModRmIndex(1));

        emit_or_r16_i8(dst: Reg16, src: i8) => (0x83, ModRmIndex(1));
        emit_or_r32_i8(dst: Reg32, src: i8) => (0x83, ModRmIndex(1));
        emit_or_r64_i8(dst: Reg64, src: i8) => (0x83, ModRmIndex(1));

        emit_or_rr8(dst: Reg8, src: Reg8) => (MR, 0x08);
        emit_or_rr16(dst: Reg16, src: Reg16) => (MR, 0x09);
        emit_or_rr32(dst: Reg32, src: Reg32) => (MR, 0x09);
        emit_or_rr64(dst: Reg64, src: Reg64) => (MR, 0x09);

        emit_or_rm8<P>(dst: Reg8, src: Byte<P>) where P: Mem => (0x0a);
        emit_or_rm16<P>(dst: Reg16, src: Word<P>) where P: Mem => (0x0b);
        emit_or_rm32<P>(dst: Reg32, src: DWord<P>) where P: Mem => (0x0b);
        emit_or_rm64<P>(dst: Reg64, src: QWord<P>) where P: Mem => (0x0b);

        emit_or_mi8<P>(dst: Byte<P>, src: u8) where P: Mem => (0x80, ModRmIndex(1));
        emit_or_mi16<P>(dst: Word<P>, src: u16) where P: Mem => (0x81, ModRmIndex(1));
        emit_or_mi32<P>(dst: DWord<P>, src: u32) where P: Mem => (0x81, ModRmIndex(1));
        emit_or_m64_i32<P>(dst: QWord<P>, src: i32) where P: Mem => (0x81, ModRmIndex(1));

        emit_or_m16_i8<P>(dst: Word<P>, src: i8) where P: Mem => (0x83, ModRmIndex(1));
        emit_or_m32_i8<P>(dst: DWord<P>, src: i8) where P: Mem => (0x83, ModRmIndex(1));
        emit_or_m64_i8<P>(dst: QWord<P>, src: i8) where P: Mem => (0x83, ModRmIndex(1));

        emit_or_mr8<P>(dst: Byte<P>, src: Reg8) where P: Mem => (0x08);
        emit_or_mr16<P>(dst: Word<P>, src: Reg16) where P: Mem => (0x09);
        emit_or_mr32<P>(dst: DWord<P>, src: Reg32) where P: Mem => (0x09);
        emit_or_mr64<P>(dst: QWord<P>, src: Reg64) where P: Mem => (0x09);

        emit_pop_r16(reg: Reg16) => (OpPlusReg(0x58));
        emit_pop_r64(reg: Reg64) => (NoRexW, OpPlusReg(0x58));

        emit_pop_m16<P>(p: Word<P>) where P: Mem => (0x8f, ModRmIndex(0));
        emit_pop_m64<P>(p: QWord<P>) where P: Mem => (NoRexW, 0x8f, ModRmIndex(0));

        emit_push_i8(imm: i8) => (Size8, 0x6a);
        emit_push_i16(imm: u16) => (Size16, 0x68);
        emit_push_i32(imm: i32) => (Size32, 0x68);

        emit_push_r16(reg: Reg16) => (OpPlusReg(0x50));
        emit_push_r64(reg: Reg64) => (NoRexW, OpPlusReg(0x50));

        emit_push_m16<P>(p: Word<P>) where P: Mem => (0xff, ModRmIndex(6));
        emit_push_m64<P>(p: QWord<P>) where P: Mem => (NoRexW, 0xff, ModRmIndex(6));

        emit_ret() => (0xc3);

        emit_sar_r8_1(dst: Reg8) => (0xd0, ModRmIndex(7));
        emit_sar_r16_1(dst: Reg16) => (0xd1, ModRmIndex(7));
        emit_sar_r32_1(dst: Reg32) => (0xd1, ModRmIndex(7));
        emit_sar_r64_1(dst: Reg64) => (0xd1, ModRmIndex(7));

        emit_sar_ri8(dst: Reg8, shift: u8) => (0xc0, ModRmIndex(7));
        emit_sar_ri16(dst: Reg16, shift: u8) => (0xc1, ModRmIndex(7));
        emit_sar_ri32(dst: Reg32, shift: u8) => (0xc1, ModRmIndex(7));
        emit_sar_ri64(dst: Reg64, shift: u8) => (0xc1, ModRmIndex(7));

        emit_sar_r8_cl(dst: Reg8) => (0xd2, ModRmIndex(7));
        emit_sar_r16_cl(dst: Reg16) => (0xd3, ModRmIndex(7));
        emit_sar_r32_cl(dst: Reg32) => (0xd3, ModRmIndex(7));
        emit_sar_r64_cl(dst: Reg64) => (0xd3, ModRmIndex(7));

        emit_sar_m8_1<P>(dst: Byte<P>) where P: Mem => (0xd0, ModRmIndex(7));
        emit_sar_m16_1<P>(dst: Word<P>) where P: Mem => (0xd1, ModRmIndex(7));
        emit_sar_m32_1<P>(dst: Word<P>) where P: Mem => (0xd1, ModRmIndex(7));
        emit_sar_m64_1<P>(dst: Word<P>) where P: Mem => (0xd1, ModRmIndex(7));

        emit_sar_mi8<P>(dst: Byte<P>, shift: u8) where P: Mem => (0xc0, ModRmIndex(7));
        emit_sar_mi16<P>(dst: Word<P>, shift: u8) where P: Mem => (0xc1, ModRmIndex(7));
        emit_sar_mi32<P>(dst: Word<P>, shift: u8) where P: Mem => (0xc1, ModRmIndex(7));
        emit_sar_mi64<P>(dst: Word<P>, shift: u8) where P: Mem => (0xc1, ModRmIndex(7));

        emit_sar_m8_cl<P>(dst: Byte<P>) where P: Mem => (0xd2, ModRmIndex(7));
        emit_sar_m16_cl<P>(dst: Word<P>) where P: Mem => (0xd3, ModRmIndex(7));
        emit_sar_m32_cl<P>(dst: Word<P>) where P: Mem => (0xd3, ModRmIndex(7));
        emit_sar_m64_cl<P>(dst: Word<P>) where P: Mem => (0xd3, ModRmIndex(7));

        emit_sbb_al_i8(src: u8) => (Size8, 0x1c);
        emit_sbb_ax_i16(src: u16) => (Size16, 0x1d);
        emit_sbb_eax_i32(src: u32) => (Size32, 0x1d);
        emit_sbb_rax_i32(src: i32) => (Size64, 0x1d);

        emit_sbb_ri8(dst: Reg8, src: u8) => (0x80, ModRmIndex(3));
        emit_sbb_ri16(dst: Reg16, src: u16) => (0x81, ModRmIndex(3));
        emit_sbb_ri32(dst: Reg32, src: u32) => (0x81, ModRmIndex(3));
        emit_sbb_r64_i32(dst: Reg64, src: i32) => (0x81, ModRmIndex(3));

        emit_sbb_r16_i8(dst: Reg16, src: i8) => (0x83, ModRmIndex(3));
        emit_sbb_r32_i8(dst: Reg32, src: i8) => (0x83, ModRmIndex(3));
        emit_sbb_r64_i8(dst: Reg64, src: i8) => (0x83, ModRmIndex(3));

        emit_sbb_rr8(dst: Reg8, src: Reg8) => (MR, 0x18);
        emit_sbb_rr16(dst: Reg16, src: Reg16) => (MR, 0x19);
        emit_sbb_rr32(dst: Reg32, src: Reg32) => (MR, 0x19);
        emit_sbb_rr64(dst: Reg64, src: Reg64) => (MR, 0x19);

        emit_sbb_rm8<P>(dst: Reg8, src: Byte<P>) where P: Mem => (0x1a);
        emit_sbb_rm16<P>(dst: Reg16, src: Word<P>) where P: Mem => (0x1b);
        emit_sbb_rm32<P>(dst: Reg32, src: DWord<P>) where P: Mem => (0x1b);
        emit_sbb_rm64<P>(dst: Reg64, src: QWord<P>) where P: Mem => (0x1b);

        emit_sbb_mi8<P>(dst: Byte<P>, src: u8) where P: Mem => (0x80, ModRmIndex(3));
        emit_sbb_mi16<P>(dst: Word<P>, src: u16) where P: Mem => (0x81, ModRmIndex(3));
        emit_sbb_mi32<P>(dst: DWord<P>, src: u32) where P: Mem => (0x81, ModRmIndex(3));
        emit_sbb_m64_i32<P>(dst: QWord<P>, src: i32) where P: Mem => (0x81, ModRmIndex(3));

        emit_sbb_m16_i8<P>(dst: Word<P>, src: i8) where P: Mem => (0x83, ModRmIndex(3));
        emit_sbb_m32_i8<P>(dst: DWord<P>, src: i8) where P: Mem => (0x83, ModRmIndex(3));
        emit_sbb_m64_i8<P>(dst: QWord<P>, src: i8) where P: Mem => (0x83, ModRmIndex(3));

        emit_sbb_mr8<P>(dst: Byte<P>, src: Reg8) where P: Mem => (0x18);
        emit_sbb_mr16<P>(dst: Word<P>, src: Reg16) where P: Mem => (0x19);
        emit_sbb_mr32<P>(dst: DWord<P>, src: Reg32) where P: Mem => (0x19);
        emit_sbb_mr64<P>(dst: QWord<P>, src: Reg64) where P: Mem => (0x19);

        emit_setcc_r8(cond: Condition, dst: Reg8) => (0x0f, OpPlusCondition(0x90));
        emit_setcc_m8<P>(cond: Condition, dst: Byte<P>) where P: Mem => (0x0f, OpPlusCondition(0x90));

        emit_shl_r8_1(dst: Reg8) => (0xd0, ModRmIndex(4));
        emit_shl_r16_1(dst: Reg16) => (0xd1, ModRmIndex(4));
        emit_shl_r32_1(dst: Reg32) => (0xd1, ModRmIndex(4));
        emit_shl_r64_1(dst: Reg64) => (0xd1, ModRmIndex(4));

        emit_shl_ri8(dst: Reg8, shift: u8) => (0xc0, ModRmIndex(4));
        emit_shl_ri16(dst: Reg16, shift: u8) => (0xc1, ModRmIndex(4));
        emit_shl_ri32(dst: Reg32, shift: u8) => (0xc1, ModRmIndex(4));
        emit_shl_ri64(dst: Reg64, shift: u8) => (0xc1, ModRmIndex(4));

        emit_shl_r8_cl(dst: Reg8) => (0xd2, ModRmIndex(4));
        emit_shl_r16_cl(dst: Reg16) => (0xd3, ModRmIndex(4));
        emit_shl_r32_cl(dst: Reg32) => (0xd3, ModRmIndex(4));
        emit_shl_r64_cl(dst: Reg64) => (0xd3, ModRmIndex(4));

        emit_shl_m8_1<P>(dst: Byte<P>) where P: Mem => (0xd0, ModRmIndex(4));
        emit_shl_m16_1<P>(dst: Word<P>) where P: Mem => (0xd1, ModRmIndex(4));
        emit_shl_m32_1<P>(dst: Word<P>) where P: Mem => (0xd1, ModRmIndex(4));
        emit_shl_m64_1<P>(dst: Word<P>) where P: Mem => (0xd1, ModRmIndex(4));

        emit_shl_mi8<P>(dst: Byte<P>, shift: u8) where P: Mem => (0xc0, ModRmIndex(4));
        emit_shl_mi16<P>(dst: Word<P>, shift: u8) where P: Mem => (0xc1, ModRmIndex(4));
        emit_shl_mi32<P>(dst: Word<P>, shift: u8) where P: Mem => (0xc1, ModRmIndex(4));
        emit_shl_mi64<P>(dst: Word<P>, shift: u8) where P: Mem => (0xc1, ModRmIndex(4));

        emit_shl_m8_cl<P>(dst: Byte<P>) where P: Mem => (0xd2, ModRmIndex(4));
        emit_shl_m16_cl<P>(dst: Word<P>) where P: Mem => (0xd3, ModRmIndex(4));
        emit_shl_m32_cl<P>(dst: Word<P>) where P: Mem => (0xd3, ModRmIndex(4));
        emit_shl_m64_cl<P>(dst: Word<P>) where P: Mem => (0xd3, ModRmIndex(4));

        emit_shr_r8_1(dst: Reg8) => (0xd0, ModRmIndex(5));
        emit_shr_r16_1(dst: Reg16) => (0xd1, ModRmIndex(5));
        emit_shr_r32_1(dst: Reg32) => (0xd1, ModRmIndex(5));
        emit_shr_r64_1(dst: Reg64) => (0xd1, ModRmIndex(5));

        emit_shr_ri8(dst: Reg8, shift: u8) => (0xc0, ModRmIndex(5));
        emit_shr_ri16(dst: Reg16, shift: u8) => (0xc1, ModRmIndex(5));
        emit_shr_ri32(dst: Reg32, shift: u8) => (0xc1, ModRmIndex(5));
        emit_shr_ri64(dst: Reg64, shift: u8) => (0xc1, ModRmIndex(5));

        emit_shr_r8_cl(dst: Reg8) => (0xd2, ModRmIndex(5));
        emit_shr_r16_cl(dst: Reg16) => (0xd3, ModRmIndex(5));
        emit_shr_r32_cl(dst: Reg32) => (0xd3, ModRmIndex(5));
        emit_shr_r64_cl(dst: Reg64) => (0xd3, ModRmIndex(5));

        emit_shr_m8_1<P>(dst: Byte<P>) where P: Mem => (0xd0, ModRmIndex(5));
        emit_shr_m16_1<P>(dst: Word<P>) where P: Mem => (0xd1, ModRmIndex(5));
        emit_shr_m32_1<P>(dst: Word<P>) where P: Mem => (0xd1, ModRmIndex(5));
        emit_shr_m64_1<P>(dst: Word<P>) where P: Mem => (0xd1, ModRmIndex(5));

        emit_shr_mi8<P>(dst: Byte<P>, shift: u8) where P: Mem => (0xc0, ModRmIndex(5));
        emit_shr_mi16<P>(dst: Word<P>, shift: u8) where P: Mem => (0xc1, ModRmIndex(5));
        emit_shr_mi32<P>(dst: Word<P>, shift: u8) where P: Mem => (0xc1, ModRmIndex(5));
        emit_shr_mi64<P>(dst: Word<P>, shift: u8) where P: Mem => (0xc1, ModRmIndex(5));

        emit_shr_m8_cl<P>(dst: Byte<P>) where P: Mem => (0xd2, ModRmIndex(5));
        emit_shr_m16_cl<P>(dst: Word<P>) where P: Mem => (0xd3, ModRmIndex(5));
        emit_shr_m32_cl<P>(dst: Word<P>) where P: Mem => (0xd3, ModRmIndex(5));
        emit_shr_m64_cl<P>(dst: Word<P>) where P: Mem => (0xd3, ModRmIndex(5));

        emit_sub_al_i8(src: u8) => (Size8, 0x2c);
        emit_sub_ax_i16(src: u16) => (Size16, 0x2d);
        emit_sub_eax_i32(src: u32) => (Size32, 0x2d);
        emit_sub_rax_i32(src: i32) => (Size64, 0x2d);

        emit_sub_ri8(dst: Reg8, src: u8) => (0x80, ModRmIndex(5));
        emit_sub_ri16(dst: Reg16, src: u16) => (0x81, ModRmIndex(5));
        emit_sub_ri32(dst: Reg32, src: u32) => (0x81, ModRmIndex(5));
        emit_sub_r64_i32(dst: Reg64, src: i32) => (0x81, ModRmIndex(5));

        emit_sub_r16_i8(dst: Reg16, src: i8) => (0x83, ModRmIndex(5));
        emit_sub_r32_i8(dst: Reg32, src: i8) => (0x83, ModRmIndex(5));
        emit_sub_r64_i8(dst: Reg64, src: i8) => (0x83, ModRmIndex(5));

        emit_sub_rr8(dst: Reg8, src: Reg8) => (MR, 0x28);
        emit_sub_rr16(dst: Reg16, src: Reg16) => (MR, 0x29);
        emit_sub_rr32(dst: Reg32, src: Reg32) => (MR, 0x29);
        emit_sub_rr64(dst: Reg64, src: Reg64) => (MR, 0x29);

        emit_sub_rm8<P>(dst: Reg8, src: Byte<P>) where P: Mem => (0x2a);
        emit_sub_rm16<P>(dst: Reg16, src: Word<P>) where P: Mem => (0x2b);
        emit_sub_rm32<P>(dst: Reg32, src: DWord<P>) where P: Mem => (0x2b);
        emit_sub_rm64<P>(dst: Reg64, src: QWord<P>) where P: Mem => (0x2b);

        emit_sub_mi8<P>(dst: Byte<P>, src: u8) where P: Mem => (0x80, ModRmIndex(5));
        emit_sub_mi16<P>(dst: Word<P>, src: u16) where P: Mem => (0x81, ModRmIndex(5));
        emit_sub_mi32<P>(dst: DWord<P>, src: u32) where P: Mem => (0x81, ModRmIndex(5));
        emit_sub_m64_i32<P>(dst: QWord<P>, src: i32) where P: Mem => (0x81, ModRmIndex(5));

        emit_sub_m16_i8<P>(dst: Word<P>, src: i8) where P: Mem => (0x83, ModRmIndex(5));
        emit_sub_m32_i8<P>(dst: DWord<P>, src: i8) where P: Mem => (0x83, ModRmIndex(5));
        emit_sub_m64_i8<P>(dst: QWord<P>, src: i8) where P: Mem => (0x83, ModRmIndex(5));

        emit_sub_mr8<P>(dst: Byte<P>, src: Reg8) where P: Mem => (0x28);
        emit_sub_mr16<P>(dst: Word<P>, src: Reg16) where P: Mem => (0x29);
        emit_sub_mr32<P>(dst: DWord<P>, src: Reg32) where P: Mem => (0x29);
        emit_sub_mr64<P>(dst: QWord<P>, src: Reg64) where P: Mem => (0x29);

        emit_test_al_i8(reg: u8) => (Size8, 0xa8);
        emit_test_ax_i16(reg: u16) => (Size16, 0xa9);
        emit_test_eax_i32(reg: u32) => (Size32, 0xa9);
        emit_test_rax_i32(reg: i32) => (Size64, 0xa9);

        emit_test_ri8(reg: Reg8, imm: u8) => (0xf6, ModRmIndex(0));
        emit_test_ri16(reg: Reg16, imm: u16) => (0xf7, ModRmIndex(0));
        emit_test_ri32(reg: Reg32, imm: u32) => (0xf7, ModRmIndex(0));
        emit_test_r64_i32(reg: Reg64, imm: i32) => (0xf7, ModRmIndex(0));

        emit_test_rr8(reg1: Reg8,  reg2: Reg8) => (MR, 0x84);
        emit_test_rr16(reg1: Reg16, reg2: Reg16) => (MR, 0x85);
        emit_test_rr32(reg1: Reg32, reg2: Reg32) => (MR, 0x85);
        emit_test_rr64(reg1: Reg64, reg2: Reg64) => (MR, 0x85);

        emit_test_mi8<P>(ptr: Byte<P>, imm: u8) where P: Mem => (0xf6, ModRmIndex(0));
        emit_test_mi16<P>(ptr: Word<P>, imm: u16) where P: Mem => (0xf7, ModRmIndex(0));
        emit_test_mi32<P>(ptr: DWord<P>, imm: u32) where P: Mem => (0xf7, ModRmIndex(0));
        emit_test_m64_i32<P>(ptr: QWord<P>, imm: i32) where P: Mem => (0xf7, ModRmIndex(0));

        emit_test_mr8<P>(ptr: Byte<P>, reg: Reg8) where P: Mem => (0x84);
        emit_test_mr16<P>(ptr: Word<P>, reg: Reg16) where P: Mem => (0x85);
        emit_test_mr32<P>(ptr: DWord<P>, reg: Reg32) where P: Mem => (0x85);
        emit_test_mr64<P>(ptr: QWord<P>, reg: Reg64) where P: Mem => (0x85);

        emit_ud2() => (0x0f, 0x0b);

        emit_xchg_r16_ax(dst: Reg16) => (OpPlusReg(0x90));
        emit_xchg_r32_eax(dst: Reg32) => (OpPlusReg(0x90));
        emit_xchg_r64_rax(dst: Reg64) => (OpPlusReg(0x90));

        emit_xchg_rr8(dst: Reg8, src: Reg8) => (MR, 0x86);
        emit_xchg_rr16(dst: Reg16, src: Reg16) => (MR, 0x87);
        emit_xchg_rr32(dst: Reg32, src: Reg32) => (MR, 0x87);
        emit_xchg_rr64(dst: Reg64, src: Reg64) => (MR, 0x87);

        emit_xchg_mr8<P>(dst: Byte<P>, src: Reg8) where P: Mem => (0x86);
        emit_xchg_mr16<P>(dst: Word<P>, src: Reg16) where P: Mem => (0x87);
        emit_xchg_mr32<P>(dst: DWord<P>, src: Reg32) where P: Mem => (0x87);
        emit_xchg_mr64<P>(dst: QWord<P>, src: Reg64) where P: Mem => (0x87);

        emit_xor_al_i8(src: u8) => (Size8, 0x34);
        emit_xor_ax_i16(src: u16) => (Size16, 0x35);
        emit_xor_eax_i32(src: u32) => (Size32, 0x35);
        emit_xor_rax_i32(src: i32) => (Size64, 0x35);

        emit_xor_ri8(dst: Reg8, src: u8) => (0x80, ModRmIndex(6));
        emit_xor_ri16(dst: Reg16, src: u16) => (0x81, ModRmIndex(6));
        emit_xor_ri32(dst: Reg32, src: u32) => (0x81, ModRmIndex(6));
        emit_xor_r64_i32(dst: Reg64, src: i32) => (0x81, ModRmIndex(6));

        emit_xor_r16_i8(dst: Reg16, src: i8) => (0x83, ModRmIndex(6));
        emit_xor_r32_i8(dst: Reg32, src: i8) => (0x83, ModRmIndex(6));
        emit_xor_r64_i8(dst: Reg64, src: i8) => (0x83, ModRmIndex(6));

        emit_xor_rr8(dst: Reg8, src: Reg8) => (MR, 0x30);
        emit_xor_rr16(dst: Reg16, src: Reg16) => (MR, 0x31);
        emit_xor_rr32(dst: Reg32, src: Reg32) => (MR, 0x31);
        emit_xor_rr64(dst: Reg64, src: Reg64) => (MR, 0x31);

        emit_xor_rm8<P>(dst: Reg8, src: Byte<P>) where P: Mem => (0x32);
        emit_xor_rm16<P>(dst: Reg16, src: Word<P>) where P: Mem => (0x33);
        emit_xor_rm32<P>(dst: Reg32, src: DWord<P>) where P: Mem => (0x33);
        emit_xor_rm64<P>(dst: Reg64, src: QWord<P>) where P: Mem => (0x33);

        emit_xor_mi8<P>(dst: Byte<P>, src: u8) where P: Mem => (0x80, ModRmIndex(6));
        emit_xor_mi16<P>(dst: Word<P>, src: u16) where P: Mem => (0x81, ModRmIndex(6));
        emit_xor_mi32<P>(dst: DWord<P>, src: u32) where P: Mem => (0x81, ModRmIndex(6));
        emit_xor_m64_i32<P>(dst: QWord<P>, src: i32) where P: Mem => (0x81, ModRmIndex(6));

        emit_xor_m16_i8<P>(dst: Word<P>, src: i8) where P: Mem => (0x83, ModRmIndex(6));
        emit_xor_m32_i8<P>(dst: DWord<P>, src: i8) where P: Mem => (0x83, ModRmIndex(6));
        emit_xor_m64_i8<P>(dst: QWord<P>, src: i8) where P: Mem => (0x83, ModRmIndex(6));

        emit_xor_mr8<P>(dst: Byte<P>, src: Reg8) where P: Mem => (0x30);
        emit_xor_mr16<P>(dst: Word<P>, src: Reg16) where P: Mem => (0x31);
        emit_xor_mr32<P>(dst: DWord<P>, src: Reg32) where P: Mem => (0x31);
        emit_xor_mr64<P>(dst: QWord<P>, src: Reg64) where P: Mem => (0x31);
    }
}

impl<E> Emit for E where E: EmitSlice + ?Sized {}
