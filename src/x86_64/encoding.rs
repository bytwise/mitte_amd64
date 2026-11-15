use mitte_core::EmitSlice;

use super::types::*;
use super::common::*;
use super::reg::{Reg8, Reg16, Reg32, Reg64};
use super::ptr::{Mem, Byte, Word, DWord, QWord};
use super::error::Error;
use crate::buffer::Buffer;


pub struct MR;
pub struct RM;

pub struct Size8;
pub struct Size16;
pub struct Size32;
pub struct Size64;

pub struct Prefix(pub u8);

const REXW_PREFIX: u8 = 0x48;
const OPERAND_SIZE_PREFIX: u8 = 0x66;

pub struct NoRexW;

pub struct OpPlusCondition(pub u8);
pub struct OpPlusReg(pub u8);

pub struct ModRmIndex(pub u8);


trait Imm {
    fn write(&self, buffer: &mut Buffer);
}

impl Imm for u8 {
    #[inline]
    fn write(&self, buffer: &mut Buffer) {
        buffer.write_u8(*self);
    }
}

impl Imm for i8 {
    #[inline]
    fn write(&self, buffer: &mut Buffer) {
        buffer.write_u8(*self as u8);
    }
}

impl Imm for u16 {
    #[inline]
    fn write(&self, buffer: &mut Buffer) {
        buffer.write_u16(*self);
    }
}

impl Imm for u32 {
    #[inline]
    fn write(&self, buffer: &mut Buffer) {
        buffer.write_u32(*self);
    }
}

impl Imm for i32 {
    #[inline]
    fn write(&self, buffer: &mut Buffer) {
        buffer.write_u32(*self as u32);
    }
}


pub trait Encode<Args> {
    fn encode<E>(emitter: &mut E, args: Args, this: Self) -> Result<(), Error<E::Error>>
        where E: EmitSlice + ?Sized;
}

// () impls

impl Encode<()> for u8 {
    fn encode<E>(emitter: &mut E, _: (), op: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        emitter.emit_slice(&[op])?;
        Ok(())
    }
}

impl Encode<()> for (u8, u8) {
    fn encode<E>(emitter: &mut E, _: (), this: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op1, op2) = this;
        emitter.emit_slice(&[op1, op2])?;
        Ok(())
    }
}

// (imm) impls

impl Encode<u8> for (Size8, u8) {
    fn encode<E>(emitter: &mut E, imm: u8, this: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (Size8, op) = this;
        emitter.emit_slice(&[op, imm])?;
        Ok(())
    }
}

impl Encode<i8> for (Size8, u8) {
    fn encode<E>(emitter: &mut E, imm: i8, this: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (Size8, op) = this;
        emitter.emit_slice(&[op, imm as u8])?;
        Ok(())
    }
}

impl Encode<u16> for (Size16, u8) {
    fn encode<E>(emitter: &mut E, imm: u16, this: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (Size16, op) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(OPERAND_SIZE_PREFIX);
        buffer.write_u8(op);
        buffer.write_u16(imm);
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl Encode<i16> for (Size16, u8) {
    fn encode<E>(emitter: &mut E, imm: i16, this: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        Encode::encode(emitter, imm as u16, this)
    }
}

impl Encode<u32> for (Size32, u8) {
    fn encode<E>(emitter: &mut E, imm: u32, this: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (Size32, op) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(op);
        buffer.write_u32(imm);
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl Encode<i32> for (Size32, u8) {
    fn encode<E>(emitter: &mut E, imm: i32, this: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        Encode::encode(emitter, imm as u32, this)
    }
}

impl Encode<i32> for (Size64, u8) {
    fn encode<E>(emitter: &mut E, imm: i32, this: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (Size64, op) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(REXW_PREFIX);
        buffer.write_u8(op);
        buffer.write_u32(imm as u32);
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl Encode<Rel8> for u8 {
    fn encode<E>(emitter: &mut E, offset: Rel8, op: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        emitter.emit_slice(&[op, (offset.offset - 2) as u8])?;
        Ok(())
    }
}

impl Encode<Rel32> for u8 {
    fn encode<E>(emitter: &mut E, offset: Rel32, op: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let mut buffer = Buffer::new();
        buffer.write_u8(op);
        buffer.write_u32((offset.offset - 5) as u32);
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

// (cond, imm) impls

impl Encode<(Condition, Rel8)> for OpPlusCondition {
    fn encode<E>(emitter: &mut E, (cond, offset): (Condition, Rel8), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let OpPlusCondition(op) = this;
        emitter.emit_slice(&[op | cond as u8, (offset.offset - 2) as u8])?;
        Ok(())
    }
}

impl Encode<(Condition, Rel32)> for (u8, OpPlusCondition) {
    fn encode<E>(emitter: &mut E, (cond, offset): (Condition, Rel32), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op1, OpPlusCondition(op2)) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(op1);
        buffer.write_u8(op2 | cond as u8);
        buffer.write_u32((offset.offset - 6) as u32);
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

// (reg) impls

impl Encode<Reg8> for (u8, ModRmIndex) {
    fn encode<E>(emitter: &mut E, reg: Reg8, this: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op, ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl Encode<Reg16> for OpPlusReg {
    fn encode<E>(emitter: &mut E, reg: Reg16, this: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let OpPlusReg(op) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(OPERAND_SIZE_PREFIX);
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op | reg.rm());
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl Encode<Reg16> for (u8, ModRmIndex) {
    fn encode<E>(emitter: &mut E, reg: Reg16, this: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op, ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(OPERAND_SIZE_PREFIX);
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl Encode<Reg32> for OpPlusReg {
    fn encode<E>(emitter: &mut E, reg: Reg32, this: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let OpPlusReg(op) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op | reg.rm());
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl Encode<Reg32> for (u8, ModRmIndex) {
    fn encode<E>(emitter: &mut E, reg: Reg32, this: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op, ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl Encode<Reg64> for OpPlusReg {
    fn encode<E>(emitter: &mut E, reg: Reg64, this: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let OpPlusReg(op) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(rexw_b(reg)?);
        buffer.write_u8(op | reg.rm());
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl Encode<Reg64> for (NoRexW, OpPlusReg) {
    fn encode<E>(emitter: &mut E, reg: Reg64, this: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (NoRexW, op) = this;
        Encode::encode(emitter, reg.to_reg32(), op)
    }
}

impl Encode<Reg64> for (u8, ModRmIndex) {
    fn encode<E>(emitter: &mut E, reg: Reg64, this: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op, ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(rexw_b(reg)?);
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl Encode<Reg64> for (NoRexW, u8, ModRmIndex) {
    fn encode<E>(emitter: &mut E, reg: Reg64, this: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (NoRexW, op, modrm_index) = this;
        Encode::encode(emitter, reg.to_reg32(), (op, modrm_index))
    }
}

// (cond, reg) impls

impl Encode<(Condition, Reg8)> for (u8, OpPlusCondition) {
    fn encode<E>(emitter: &mut E, (cond, reg): (Condition, Reg8), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op1, OpPlusCondition(op2)) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2 | cond as u8);
        buffer.write_u8(modrm(3, 0, reg.rm()));
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

// (ptr) impls

impl<P> Encode<P> for (u8, ModRmIndex)
where P: Mem
{
    fn encode<E>(emitter: &mut E, ptr: P, this: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op, ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex()? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<Byte<P>> for (u8, ModRmIndex)
where P: Mem
{
    fn encode<E>(emitter: &mut E, ptr: Byte<P>, this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op, modrm_index) = this;
        Encode::encode(emitter, ptr.0, (op, modrm_index))
    }
}

impl<P> Encode<Word<P>> for (u8, ModRmIndex)
where P: Mem
{
    fn encode<E>(emitter: &mut E, ptr: Word<P>, this: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op, ModRmIndex(modrm_index)) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(OPERAND_SIZE_PREFIX);
        if let Some(rex) = ptr.rex()? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<DWord<P>> for (u8, ModRmIndex)
where P: Mem
{
    fn encode<E>(emitter: &mut E, ptr: DWord<P>, this: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        Encode::encode(emitter, ptr.0, this)
    }
}

impl<P> Encode<QWord<P>> for (u8, ModRmIndex)
where P: Mem
{
    fn encode<E>(emitter: &mut E, ptr: QWord<P>, this: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op, ModRmIndex(modrm_index)) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(ptr.rexw()?);
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<QWord<P>> for (NoRexW, u8, ModRmIndex)
where P: Mem
{
    fn encode<E>(emitter: &mut E, ptr: QWord<P>, this: Self) -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (NoRexW, op, modrm_index) = this;
        Encode::encode(emitter, ptr.0, (op, modrm_index))
    }
}

// (cond, ptr) impls

impl<P> Encode<(Condition, Byte<P>)> for (u8, OpPlusCondition)
where P: Mem
{
    fn encode<E>(emitter: &mut E, (cond, ptr): (Condition, Byte<P>), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op1, OpPlusCondition(op2)) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex()? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2 | cond as u8);
        Args::write(&mut buffer, ptr, 0)?;
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

// (reg, imm) impls

impl<I> Encode<(RegisterIndex, I)> for OpPlusReg
where I: Imm
{
    fn encode<E>(emitter: &mut E, (reg, imm): (RegisterIndex, I), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let OpPlusReg(op) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op | reg.rm());
        imm.write(&mut buffer);
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl<I, const N: usize> Encode<(RegisterIndex, I)> for ([u8; N], ModRmIndex)
where I: Imm
{
    fn encode<E>(emitter: &mut E, (reg, imm): (RegisterIndex, I), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (ops, ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        for op in ops {
            buffer.write_u8(op);
        }
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        imm.write(&mut buffer);
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl<I, const N: usize> Encode<(RegisterIndex, I)> for (Prefix, [u8; N], ModRmIndex)
where I: Imm
{
    fn encode<E>(emitter: &mut E, (reg, imm): (RegisterIndex, I), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (Prefix(prefix), ops, ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        for op in ops {
            buffer.write_u8(op);
        }
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        imm.write(&mut buffer);
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl Encode<(Reg8, u8)> for OpPlusReg {
    fn encode<E>(emitter: &mut E, (reg, imm): (Reg8, u8), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        Encode::encode(emitter, (reg.index(), imm), this)
    }
}

impl Encode<(Reg8, u8)> for (u8, ModRmIndex) {
    fn encode<E>(emitter: &mut E, (reg, imm): (Reg8, u8), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op, modrm_index) = this;
        Encode::encode(emitter, (reg.index(), imm), ([op], modrm_index))
    }
}

impl Encode<(Reg16, u16)> for OpPlusReg {
    fn encode<E>(emitter: &mut E, (reg, imm): (Reg16, u16), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let OpPlusReg(op) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(OPERAND_SIZE_PREFIX);
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op | reg.rm());
        buffer.write_u16(imm);
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl<I> Encode<(Reg16, I)> for (u8, ModRmIndex)
where I: Imm
{
    fn encode<E>(emitter: &mut E, (reg, imm): (Reg16, I), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op, ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(OPERAND_SIZE_PREFIX);
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        imm.write(&mut buffer);
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl Encode<(Reg32, u32)> for OpPlusReg {
    fn encode<E>(emitter: &mut E, (reg, imm): (Reg32, u32), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        Encode::encode(emitter, (reg.index(), imm), this)
    }
}

impl<I> Encode<(Reg32, I)> for (u8, ModRmIndex)
where I: Imm
{
    fn encode<E>(emitter: &mut E, (reg, imm): (Reg32, I), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op, modrm_index) = this;
        Encode::encode(emitter, (reg.index(), imm), ([op], modrm_index))
    }
}

impl Encode<(Reg64, u64)> for OpPlusReg {
    fn encode<E>(emitter: &mut E, (reg, imm): (Reg64, u64), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let OpPlusReg(op) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(rexw_b(reg)?);
        buffer.write_u8(op | reg.rm());
        buffer.write_u64(imm);
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl<I> Encode<(Reg64, I)> for (u8, ModRmIndex)
where I: Imm
{
    fn encode<E>(emitter: &mut E, (reg, imm): (Reg64, I), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op, ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(rexw_b(reg)?);
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        imm.write(&mut buffer);
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

// (reg, reg) impls

impl<const N: usize> Encode<(RegisterIndex, RegisterIndex)> for [u8; N] {
    fn encode<E>(emitter: &mut E, (reg1, reg2): (RegisterIndex, RegisterIndex), ops: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_rb(reg1, reg2)? {
            buffer.write_u8(rex);
        }
        for op in ops {
            buffer.write_u8(op);
        }
        buffer.write_u8(modrm(3, reg1.rm(), reg2.rm()));
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl<const N: usize> Encode<(RegisterIndex, RegisterIndex)> for (Prefix, [u8; N]) {
    fn encode<E>(emitter: &mut E, (reg1, reg2): (RegisterIndex, RegisterIndex), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (Prefix(prefix), ops) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = rex_rb(reg1, reg2)? {
            buffer.write_u8(rex);
        }
        for op in ops {
            buffer.write_u8(op);
        }
        buffer.write_u8(modrm(3, reg1.rm(), reg2.rm()));
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl Encode<(Reg8, Reg8)> for (MR, u8) {
    fn encode<E>(emitter: &mut E, (reg1, reg2): (Reg8, Reg8), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (MR, op) = this;
        // check for Reg8 specific errors before erasing types
        let _ = rex_rb(reg2, reg1)?;
        Encode::encode(emitter, (reg2.index(), reg1.index()), [op])
    }
}

impl Encode<(Reg16, Reg8)> for (RM, Size16, u8, u8) {
    fn encode<E>(emitter: &mut E, (reg1, reg2): (Reg16, Reg8), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (RM, Size16, op1, op2) = this;
        Encode::encode(
            emitter, (reg1.index(), reg2.index()), (Prefix(OPERAND_SIZE_PREFIX), [op1, op2])
        )
    }
}

impl Encode<(Reg16, Reg16)> for (MR, u8) {
    fn encode<E>(emitter: &mut E, (reg1, reg2): (Reg16, Reg16), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (MR, op) = this;
        Encode::encode(emitter, (reg2.index(), reg1.index()), (Prefix(OPERAND_SIZE_PREFIX), [op]))
    }
}

impl Encode<(Reg16, Reg16)> for (RM, u8, u8) {
    fn encode<E>(emitter: &mut E, (reg1, reg2): (Reg16, Reg16), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (RM, op1, op2) = this;
        Encode::encode(
            emitter, (reg1.index(), reg2.index()), (Prefix(OPERAND_SIZE_PREFIX), [op1, op2])
        )
    }
}

impl<R> Encode<(Reg32, R)> for (RM, Size32, u8, u8)
where R: Register
{
    fn encode<E>(emitter: &mut E, (reg1, reg2): (Reg32, R), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (RM, Size32, op1, op2) = this;
        Encode::encode(
            emitter, (reg1.index(), reg2.index()), [op1, op2]
        )
    }
}

impl Encode<(Reg32, Reg32)> for (MR, u8) {
    fn encode<E>(emitter: &mut E, (reg1, reg2): (Reg32, Reg32), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (MR, op) = this;
        Encode::encode(emitter, (reg2.index(), reg1.index()), [op])
    }
}

impl Encode<(Reg32, Reg32)> for (RM, u8, u8) {
    fn encode<E>(emitter: &mut E, (reg1, reg2): (Reg32, Reg32), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (RM, op1, op2) = this;
        Encode::encode(emitter, (reg1.index(), reg2.index()), [op1, op2])
    }
}

impl<R> Encode<(Reg64, R)> for (RM, Size64, u8, u8)
where R: Register
{
    fn encode<E>(emitter: &mut E, (reg1, reg2): (Reg64, R), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (RM, Size64, op1, op2) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(rexw_rb(reg1, reg2)?);
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        buffer.write_u8(modrm(3, reg1.rm(), reg2.rm()));
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl Encode<(Reg64, Reg64)> for (MR, u8) {
    fn encode<E>(emitter: &mut E, (reg1, reg2): (Reg64, Reg64), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (MR, op) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(rexw_rb(reg2, reg1)?);
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, reg2.rm(), reg1.rm()));
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl Encode<(Reg64, Reg64)> for (RM, u8, u8) {
    fn encode<E>(emitter: &mut E, (reg1, reg2): (Reg64, Reg64), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (RM, op1, op2) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(rexw_rb(reg1, reg2)?);
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        buffer.write_u8(modrm(3, reg1.rm(), reg2.rm()));
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

// (cond, reg, reg) impls

impl Encode<(Condition, Reg16, Reg16)> for (RM, u8, OpPlusCondition) {
    fn encode<E>(emitter: &mut E, (cond, reg1, reg2): (Condition, Reg16, Reg16), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (RM, op1, OpPlusCondition(op2)) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(OPERAND_SIZE_PREFIX);
        if let Some(rex) = rex_rb(reg1, reg2)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2 | cond as u8);
        buffer.write_u8(modrm(3, reg1.rm(), reg2.rm()));
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl Encode<(Condition, Reg32, Reg32)> for (RM, u8, OpPlusCondition) {
    fn encode<E>(emitter: &mut E, (cond, reg1, reg2): (Condition, Reg32, Reg32), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (RM, op1, OpPlusCondition(op2)) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_rb(reg1, reg2)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2 | cond as u8);
        buffer.write_u8(modrm(3, reg1.rm(), reg2.rm()));
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl Encode<(Condition, Reg64, Reg64)> for (RM, u8, OpPlusCondition) {
    fn encode<E>(emitter: &mut E, (cond, reg1, reg2): (Condition, Reg64, Reg64), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (RM, op1, OpPlusCondition(op2)) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(rexw_rb(reg1, reg2)?);
        buffer.write_u8(op1);
        buffer.write_u8(op2 | cond as u8);
        buffer.write_u8(modrm(3, reg1.rm(), reg2.rm()));
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

// (reg, ptr) impls

impl<P, const N: usize> Encode<(RegisterIndex, P)> for [u8; N]
where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (RegisterIndex, P), ops: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex_reg(reg)? {
            buffer.write_u8(rex);
        }
        for op in ops {
            buffer.write_u8(op);
        }
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl<P, const N: usize> Encode<(RegisterIndex, P)> for (Prefix, [u8; N])
where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (RegisterIndex, P), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (Prefix(prefix), ops) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = ptr.rex_reg(reg)? {
            buffer.write_u8(rex);
        }
        for op in ops {
            buffer.write_u8(op);
        }
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<(Reg8, Byte<P>)> for u8
where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg8, Byte<P>), op: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        Encode::encode(emitter, (reg.index(), ptr.0), [op])
    }
}

impl<P> Encode<(Reg16, Byte<P>)> for (Size16, u8, u8)
where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg16, Byte<P>), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (Size16, op1, op2) = this;
        Encode::encode(emitter, (reg.index(), ptr.0), (Prefix(OPERAND_SIZE_PREFIX), [op1, op2]))
    }
}

impl<P> Encode<(Reg16, Word<P>)> for u8
where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg16, Word<P>), op: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        Encode::encode(emitter, (reg.index(), ptr.0), (Prefix(OPERAND_SIZE_PREFIX), [op]))
    }
}

impl<P> Encode<(Reg16, Word<P>)> for (u8, u8)
where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg16, Word<P>), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op1, op2) = this;
        Encode::encode(emitter, (reg.index(), ptr.0), (Prefix(OPERAND_SIZE_PREFIX), [op1, op2]))
    }
}

impl<P> Encode<(Reg32, Byte<P>)> for (Size32, u8, u8)
where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg32, Byte<P>), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (Size32, op1, op2) = this;
        Encode::encode(emitter, (reg.index(), ptr.0), [op1, op2])
    }
}

impl<P> Encode<(Reg32, Word<P>)> for (Size32, u8, u8)
where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg32, Word<P>), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (Size32, op1, op2) = this;
        Encode::encode(emitter, (reg.index(), ptr.0), [op1, op2])
    }
}

impl<P> Encode<(Reg32, DWord<P>)> for u8
where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg32, DWord<P>), op: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        Encode::encode(emitter, (reg.index(), ptr.0), [op])
    }
}

impl<P> Encode<(Reg32, DWord<P>)> for (u8, u8)
where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg32, DWord<P>), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op1, op2) = this;
        Encode::encode(emitter, (reg.index(), ptr.0), [op1, op2])
    }
}

impl<P, const N: usize> Encode<(Reg64, P)> for [u8; N]
where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg64, P), ops: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let mut buffer = Buffer::new();
        buffer.write_u8(ptr.rexw_reg(reg)?);
        for op in ops {
            buffer.write_u8(op);
        }
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<(Reg64, Byte<P>)> for (Size64, u8, u8)
where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg64, Byte<P>), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (Size64, op1, op2) = this;
        Encode::encode(emitter, (reg, ptr.0), [op1, op2])
    }
}

impl<P> Encode<(Reg64, Word<P>)> for (Size64, u8, u8)
where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg64, Word<P>), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (Size64, op1, op2) = this;
        Encode::encode(emitter, (reg, ptr.0), [op1, op2])
    }
}

impl<P> Encode<(Reg64, QWord<P>)> for u8
where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg64, QWord<P>), op: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        Encode::encode(emitter, (reg, ptr.0), [op])
    }
}

impl<P> Encode<(Reg64, QWord<P>)> for (u8, u8)
where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg64, QWord<P>), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op1, op2) = this;
        Encode::encode(emitter, (reg, ptr.0), [op1, op2])
    }
}

// (cond, reg, ptr) impls

impl<P> Encode<(Condition, Reg16, Word<P>)> for (u8, OpPlusCondition)
where P: Mem
{
    fn encode<E>(emitter: &mut E, (cond, reg, ptr): (Condition, Reg16, Word<P>), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op1, OpPlusCondition(op2)) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(OPERAND_SIZE_PREFIX);
        if let Some(rex) = ptr.rex_reg(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2 | cond as u8);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<(Condition, Reg32, DWord<P>)> for (u8, OpPlusCondition)
where P: Mem
{
    fn encode<E>(emitter: &mut E, (cond, reg, ptr): (Condition, Reg32, DWord<P>), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op1, OpPlusCondition(op2)) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex_reg(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2 | cond as u8);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<(Condition, Reg64, QWord<P>)> for (u8, OpPlusCondition)
where P: Mem
{
    fn encode<E>(emitter: &mut E, (cond, reg, ptr): (Condition, Reg64, QWord<P>), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op1, OpPlusCondition(op2)) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(ptr.rexw_reg(reg)?);
        buffer.write_u8(op1);
        buffer.write_u8(op2 | cond as u8);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

// (ptr, imm) impls

impl<P, I, const N: usize> Encode<(P, I)> for ([u8; N], ModRmIndex)
where P: Mem, I: Imm
{
    fn encode<E>(emitter: &mut E, (ptr, imm): (P, I), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (ops, ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex()? {
            buffer.write_u8(rex);
        }
        for op in ops {
            buffer.write_u8(op);
        }
        Args::write(&mut buffer, ptr, modrm_index)?;
        imm.write(&mut buffer);
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl<P, I, const N: usize> Encode<(P, I)> for (Prefix, [u8; N], ModRmIndex)
where P: Mem, I: Imm
{
    fn encode<E>(emitter: &mut E, (ptr, imm): (P, I), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (Prefix(prefix), ops, ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = ptr.rex()? {
            buffer.write_u8(rex);
        }
        for op in ops {
            buffer.write_u8(op);
        }
        Args::write(&mut buffer, ptr, modrm_index)?;
        imm.write(&mut buffer);
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<(Byte<P>, u8)> for (u8, ModRmIndex)
where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, imm): (Byte<P>, u8), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op, modrm_index) = this;
        Encode::encode(emitter, (ptr.0, imm), ([op], modrm_index))
    }
}

impl<P, I> Encode<(Word<P>, I)> for (u8, ModRmIndex)
where P: Mem, I: Imm
{
    fn encode<E>(emitter: &mut E, (ptr, imm): (Word<P>, I), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op, modrm_index) = this;
        Encode::encode(emitter, (ptr.0, imm), (Prefix(OPERAND_SIZE_PREFIX), [op], modrm_index))
    }
}

impl<P, I> Encode<(DWord<P>, I)> for (u8, ModRmIndex)
where P: Mem, I: Imm
{
    fn encode<E>(emitter: &mut E, (ptr, imm): (DWord<P>, I), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op, modrm_index) = this;
        Encode::encode(emitter, (ptr.0, imm), ([op], modrm_index))
    }
}

impl<P, I> Encode<(QWord<P>, I)> for (u8, ModRmIndex)
where P: Mem, I: Imm
{
    fn encode<E>(emitter: &mut E, (ptr, imm): (QWord<P>, I), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (op, ModRmIndex(modrm_index)) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(ptr.rexw()?);
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        imm.write(&mut buffer);
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

// (ptr, reg) impls

impl<P, const N: usize> Encode<(P, RegisterIndex)> for [u8; N]
where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, reg): (P, RegisterIndex), ops: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex_reg(reg)? {
            buffer.write_u8(rex);
        }
        for op in ops {
            buffer.write_u8(op);
        }
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl<P, const N: usize> Encode<(P, RegisterIndex)> for (Prefix, [u8; N])
where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, reg): (P, RegisterIndex), this: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let (Prefix(prefix), ops) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = ptr.rex_reg(reg)? {
            buffer.write_u8(rex);
        }
        for op in ops {
            buffer.write_u8(op);
        }
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<(Byte<P>, Reg8)> for u8
where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, reg): (Byte<P>, Reg8), op: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        Encode::encode(emitter, (ptr.0, reg.index()), [op])
    }
}

impl<P> Encode<(Word<P>, Reg16)> for u8
where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, reg): (Word<P>, Reg16), op: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        Encode::encode(emitter, (ptr.0, reg.index()), (Prefix(OPERAND_SIZE_PREFIX), [op]))
    }
}

impl<P> Encode<(DWord<P>, Reg32)> for u8
where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, reg): (DWord<P>, Reg32), op: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        Encode::encode(emitter, (ptr.0, reg.index()), [op])
    }
}

impl<P> Encode<(QWord<P>, Reg64)> for u8
where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, reg): (QWord<P>, Reg64), op: Self)
        -> Result<(), Error<E::Error>>
    where E: EmitSlice + ?Sized
    {
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(ptr.rexw_reg(reg)?);
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.emit_slice(&buffer)?;
        Ok(())
    }
}
