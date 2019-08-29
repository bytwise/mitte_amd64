use EmitBytes;
use common::*;
use reg::{Reg8, Reg16, Reg32, Reg64};
use ptr::{Mem, Byte, Word, DWord, QWord};
use error::Error;
use buffer::Buffer;


pub struct None;
pub struct D;
pub struct I;
pub struct M;
pub struct O;
pub struct M1;
pub struct MI;
pub struct MC;
pub struct MR;
pub struct RM;
pub struct OI;
pub struct XchgSrc;
pub struct XchgDst;

pub struct Prefix(pub u8);

pub struct RexW;

pub struct Op(pub u8);
pub struct OpPlusReg(pub u8);

pub struct ModRm;
pub struct ModRmIndex(pub u8);

pub struct Imm8;
pub struct Imm16;
pub struct Imm32;
pub struct Imm64;


pub trait Encode<Encoding, Args> {
    fn encode<E>(emitter: &mut E, args: Args, this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes;
}

impl Encode<None, ()> for Op {
    fn encode<E>(emitter: &mut E, _: (), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let Op(op) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(op);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<None, ()> for (Op, Op) {
    fn encode<E>(emitter: &mut E, _: (), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op1), Op(op2)) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<I, u8> for (Op, Imm8) {
    fn encode<E>(emitter: &mut E, imm: u8, this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), Imm8) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(op);
        buffer.write_u8(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<D, i8> for (Op, Imm8) {
    fn encode<E>(emitter: &mut E, imm: i8, this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), Imm8) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(op);
        buffer.write_u8(imm as u8);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<I, u16> for (Prefix, Op, Imm16) {
    fn encode<E>(emitter: &mut E, imm: u16, this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Prefix(prefix), Op(op), Imm16) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        buffer.write_u8(op);
        buffer.write_u16(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<I, u32> for (Op, Imm32) {
    fn encode<E>(emitter: &mut E, imm: u32, this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), Imm32) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(op);
        buffer.write_u32(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<D, i32> for (Op, Imm32) {
    fn encode<E>(emitter: &mut E, imm: i32, this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), Imm32) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(op);
        buffer.write_u32(imm as u32);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<D, i32> for (Op, Op, Imm32) {
    fn encode<E>(emitter: &mut E, imm: i32, this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op1), Op(op2), Imm32) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        buffer.write_u32(imm as u32);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<O, Reg8> for OpPlusReg {
    fn encode<E>(emitter: &mut E, reg: Reg8, this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let OpPlusReg(op) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op | reg.rm());
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<M, Reg8> for (Op, ModRmIndex) {
    fn encode<E>(emitter: &mut E, reg: Reg8, this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<M, Reg8> for (Op, Op, ModRmIndex) {
    fn encode<E>(emitter: &mut E, reg: Reg8, this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op1), Op(op2), ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<O, Reg16> for (Prefix, OpPlusReg) {
    fn encode<E>(emitter: &mut E, reg: Reg16, this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Prefix(prefix), OpPlusReg(op)) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op | reg.rm());
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<M, Reg16> for (Prefix, Op, ModRmIndex) {
    fn encode<E>(emitter: &mut E, reg: Reg16, this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Prefix(prefix), Op(op), ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<M, Reg32> for (Op, ModRmIndex) {
    fn encode<E>(emitter: &mut E, reg: Reg32, this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<O, Reg64> for OpPlusReg {
    fn encode<E>(emitter: &mut E, reg: Reg64, this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let OpPlusReg(op) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg.to_reg32())? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op | reg.rm());
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<M, Reg64> for (Op, ModRmIndex) {
    fn encode<E>(emitter: &mut E, reg: Reg64, this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg.to_reg32())? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<M, Reg64> for (RexW, Op, ModRmIndex) {
    fn encode<E>(emitter: &mut E, reg: Reg64, this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (RexW, Op(op), ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<M, Byte<P>> for (Op, Op, ModRmIndex)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, ptr: Byte<P>, this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op1), Op(op2), ModRmIndex(modrm_index)) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex()? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        Args::write(&mut buffer, ptr, modrm_index)?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<M, Byte<P>> for (Op, ModRmIndex)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, ptr: Byte<P>, this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRmIndex(modrm_index)) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex()? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<M, Word<P>> for (Prefix, Op, ModRmIndex)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, ptr: Word<P>, this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Prefix(prefix), Op(op), ModRmIndex(modrm_index)) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = ptr.rex()? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<M, DWord<P>> for (Op, ModRmIndex)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, ptr: DWord<P>, this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRmIndex(modrm_index)) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex()? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<M, QWord<P>> for (Op, ModRmIndex)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, ptr: QWord<P>, this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRmIndex(modrm_index)) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex()? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<M, QWord<P>> for (RexW, Op, ModRmIndex)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, ptr: QWord<P>, this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (RexW, Op(op), ModRmIndex(modrm_index)) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(ptr.rexw()?);
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<I, (Reg8, u8)> for (Op, Imm8) {
    fn encode<E>(emitter: &mut E, (al, imm): (Reg8, u8), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(al == Reg8::Al);
        let (Op(op), Imm8) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(op);
        buffer.write_u8(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<OI, (Reg8, u8)> for (OpPlusReg, Imm8) {
    fn encode<E>(emitter: &mut E, (reg, imm): (Reg8, u8), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (OpPlusReg(op), Imm8) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op | reg.rm());
        buffer.write_u8(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<M1, (Reg8, u8)> for (Op, ModRmIndex) {
    fn encode<E>(emitter: &mut E, (reg, imm): (Reg8, u8), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(imm == 1);
        let (Op(op), ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<MI, (Reg8, u8)> for (Op, ModRmIndex, Imm8) {
    fn encode<E>(emitter: &mut E, (reg, imm): (Reg8, u8), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRmIndex(modrm_index), Imm8) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        buffer.write_u8(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<MC, (Reg8, Reg8)> for (Op, ModRmIndex) {
    fn encode<E>(emitter: &mut E, (reg, cl): (Reg8, Reg8), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(cl == Reg8::Cl);
        let (Op(op), ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<MR, (Reg8, Reg8)> for (Op, ModRm) {
    fn encode<E>(emitter: &mut E, (reg1, reg2): (Reg8, Reg8), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRm) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_rb(reg2, reg1)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, reg2.rm(), reg1.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<RM, (Reg8, Byte<P>)> for (Op, ModRm)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg8, Byte<P>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRm) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex_reg(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<I, (Reg16, u16)> for (Prefix, Op, Imm16) {
    fn encode<E>(emitter: &mut E, (ax, imm): (Reg16, u16), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(ax == Reg16::Ax);
        let (Prefix(prefix), Op(op), Imm16) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        buffer.write_u8(op);
        buffer.write_u16(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<M1, (Reg16, u8)> for (Prefix, Op, ModRmIndex) {
    fn encode<E>(emitter: &mut E, (reg, imm): (Reg16, u8), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(imm == 1);
        let (Prefix(prefix), Op(op), ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<MI, (Reg16, u8)> for (Prefix, Op, ModRmIndex, Imm8) {
    fn encode<E>(emitter: &mut E, (reg, imm): (Reg16, u8), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Prefix(prefix), Op(op), ModRmIndex(modrm_index), Imm8) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        buffer.write_u8(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<OI, (Reg16, u16)> for (Prefix, OpPlusReg, Imm16) {
    fn encode<E>(emitter: &mut E, (reg, imm): (Reg16, u16), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Prefix(prefix), OpPlusReg(op), Imm16) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op | reg.rm());
        buffer.write_u16(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<MI, (Reg16, u16)> for (Prefix, Op, ModRmIndex, Imm16) {
    fn encode<E>(emitter: &mut E, (reg, imm): (Reg16, u16), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Prefix(prefix), Op(op), ModRmIndex(modrm_index), Imm16) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        buffer.write_u16(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<MC, (Reg16, Reg8)> for (Prefix, Op, ModRmIndex) {
    fn encode<E>(emitter: &mut E, (reg, cl): (Reg16, Reg8), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(cl == Reg8::Cl);
        let (Prefix(prefix), Op(op), ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<RM, (Reg16, Reg8)> for (Prefix, Op, Op, ModRm) {
    fn encode<E>(emitter: &mut E, (reg1, reg2): (Reg16, Reg8), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Prefix(prefix), Op(op1), Op(op2), ModRm) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = rex_rb(reg1, reg2)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        buffer.write_u8(modrm(3, reg1.rm(), reg2.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<XchgSrc, (Reg16, Reg16)> for (Prefix, OpPlusReg) {
    fn encode<E>(emitter: &mut E, (ax, reg): (Reg16, Reg16), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(ax == Reg16::Ax);
        let (Prefix(prefix), OpPlusReg(op)) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op | reg.rm());
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<XchgDst, (Reg16, Reg16)> for (Prefix, OpPlusReg) {
    fn encode<E>(emitter: &mut E, (reg, ax): (Reg16, Reg16), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(ax == Reg16::Ax);
        let (Prefix(prefix), OpPlusReg(op)) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op | reg.rm());
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<MR, (Reg16, Reg16)> for (Prefix, Op, ModRm) {
    fn encode<E>(emitter: &mut E, (reg1, reg2): (Reg16, Reg16), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Prefix(prefix), Op(op), ModRm) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = rex_rb(reg2, reg1)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, reg2.rm(), reg1.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<RM, (Reg16, Reg16)> for (Prefix, Op, Op, ModRm) {
    fn encode<E>(emitter: &mut E, (reg1, reg2): (Reg16, Reg16), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Prefix(prefix), Op(op1), Op(op2), ModRm) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = rex_rb(reg1, reg2)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        buffer.write_u8(modrm(3, reg1.rm(), reg2.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<RM, (Reg16, Byte<P>)> for (Prefix, Op, Op, ModRm)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg16, Byte<P>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Prefix(prefix), Op(op1), Op(op2), ModRm) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = ptr.rex_reg(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<RM, (Reg16, Word<P>)> for (Prefix, Op, ModRm)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg16, Word<P>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Prefix(prefix), Op(op), ModRm) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = ptr.rex_reg(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<RM, (Reg16, Word<P>)> for (Prefix, Op, Op, ModRm)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg16, Word<P>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Prefix(prefix), Op(op1), Op(op2), ModRm) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = ptr.rex_reg(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<M1, (Reg32, u8)> for (Op, ModRmIndex) {
    fn encode<E>(emitter: &mut E, (reg, imm): (Reg32, u8), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(imm == 1);
        let (Op(op), ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<MI, (Reg32, u8)> for (Op, ModRmIndex, Imm8) {
    fn encode<E>(emitter: &mut E, (reg, imm): (Reg32, u8), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRmIndex(modrm_index), Imm8) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        buffer.write_u8(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<I, (Reg32, u32)> for (Op, Imm32) {
    fn encode<E>(emitter: &mut E, (eax, imm): (Reg32, u32), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(eax == Reg32::Eax);
        let (Op(op), Imm32) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(op);
        buffer.write_u32(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<OI, (Reg32, u32)> for (OpPlusReg, Imm32) {
    fn encode<E>(emitter: &mut E, (reg, imm): (Reg32, u32), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (OpPlusReg(op), Imm32) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op | reg.rm());
        buffer.write_u32(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<MI, (Reg32, u32)> for (Op, ModRmIndex, Imm32) {
    fn encode<E>(emitter: &mut E, (reg, imm): (Reg32, u32), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRmIndex(modrm_index), Imm32) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        buffer.write_u32(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<MC, (Reg32, Reg8)> for (Op, ModRmIndex) {
    fn encode<E>(emitter: &mut E, (reg, cl): (Reg32, Reg8), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(cl == Reg8::Cl);
        let (Op(op), ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<RM, (Reg32, Reg8)> for (Op, Op, ModRm) {
    fn encode<E>(emitter: &mut E, (reg1, reg2): (Reg32, Reg8), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op1), Op(op2), ModRm) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_rb(reg1, reg2)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        buffer.write_u8(modrm(3, reg1.rm(), reg2.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<RM, (Reg32, Reg16)> for (Op, Op, ModRm) {
    fn encode<E>(emitter: &mut E, (reg1, reg2): (Reg32, Reg16), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op1), Op(op2), ModRm) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_rb(reg1, reg2)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        buffer.write_u8(modrm(3, reg1.rm(), reg2.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<XchgSrc, (Reg32, Reg32)> for OpPlusReg {
    fn encode<E>(emitter: &mut E, (eax, reg): (Reg32, Reg32), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(eax == Reg32::Eax);
        let OpPlusReg(op) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op | reg.rm());
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<XchgDst, (Reg32, Reg32)> for OpPlusReg {
    fn encode<E>(emitter: &mut E, (reg, eax): (Reg32, Reg32), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(eax == Reg32::Eax);
        let OpPlusReg(op) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op | reg.rm());
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<MR, (Reg32, Reg32)> for (Op, ModRm) {
    fn encode<E>(emitter: &mut E, (reg1, reg2): (Reg32, Reg32), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRm) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_rb(reg2, reg1)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, reg2.rm(), reg1.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<RM, (Reg32, Reg32)> for (Op, Op, ModRm) {
    fn encode<E>(emitter: &mut E, (reg1, reg2): (Reg32, Reg32), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op1), Op(op2), ModRm) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_rb(reg1, reg2)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        buffer.write_u8(modrm(3, reg1.rm(), reg2.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<RM, (Reg32, Byte<P>)> for (Op, Op, ModRm)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg32, Byte<P>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op1), Op(op2), ModRm) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex_reg(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<RM, (Reg32, Word<P>)> for (Op, Op, ModRm)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg32, Word<P>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op1), Op(op2), ModRm) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex_reg(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<RM, (Reg32, DWord<P>)> for (Op, ModRm)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg32, DWord<P>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRm) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex_reg(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<RM, (Reg32, DWord<P>)> for (Op, Op, ModRm)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg32, DWord<P>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op1), Op(op2), ModRm) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex_reg(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<M1, (Reg64, u8)> for (RexW, Op, ModRmIndex) {
    fn encode<E>(emitter: &mut E, (reg, imm): (Reg64, u8), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(imm == 1);
        let (RexW, Op(op), ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<MI, (Reg64, u8)> for (RexW, Op, ModRmIndex, Imm8) {
    fn encode<E>(emitter: &mut E, (reg, imm): (Reg64, u8), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (RexW, Op(op), ModRmIndex(modrm_index), Imm8) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        buffer.write_u8(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<I, (Reg64, u32)> for (RexW, Op, Imm32) {
    fn encode<E>(emitter: &mut E, (rax, imm): (Reg64, u32), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(rax == Reg64::Rax);
        let (RexW, Op(op), Imm32) = this;
        let mut buffer = Buffer::new();
        buffer.write_u8(0x48);
        buffer.write_u8(op);
        buffer.write_u32(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<MI, (Reg64, u32)> for (RexW, Op, ModRmIndex, Imm32) {
    fn encode<E>(emitter: &mut E, (reg, imm): (Reg64, u32), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (RexW, Op(op), ModRmIndex(modrm_index), Imm32) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        buffer.write_u32(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<OI, (Reg64, u64)> for (RexW, OpPlusReg, Imm64) {
    fn encode<E>(emitter: &mut E, (reg, imm): (Reg64, u64), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (RexW, OpPlusReg(op), Imm64) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op | reg.rm());
        buffer.write_u64(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<MC, (Reg64, Reg8)> for (RexW, Op, ModRmIndex) {
    fn encode<E>(emitter: &mut E, (reg, cl): (Reg64, Reg8), this: Self) -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(cl == Reg8::Cl);
        let (RexW, Op(op), ModRmIndex(modrm_index)) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, modrm_index, reg.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<RM, (Reg64, Reg8)> for (RexW, Op, Op, ModRm) {
    fn encode<E>(emitter: &mut E, (reg1, reg2): (Reg64, Reg8), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (RexW, Op(op1), Op(op2), ModRm) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_rb(reg1, reg2)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        buffer.write_u8(modrm(3, reg1.rm(), reg2.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<RM, (Reg64, Reg16)> for (RexW, Op, Op, ModRm) {
    fn encode<E>(emitter: &mut E, (reg1, reg2): (Reg64, Reg16), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (RexW, Op(op1), Op(op2), ModRm) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_rb(reg1, reg2)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        buffer.write_u8(modrm(3, reg1.rm(), reg2.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<XchgSrc, (Reg64, Reg64)> for (RexW, OpPlusReg) {
    fn encode<E>(emitter: &mut E, (rax, reg): (Reg64, Reg64), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(rax == Reg64::Rax);
        let (RexW, OpPlusReg(op)) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op | reg.rm());
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<XchgDst, (Reg64, Reg64)> for (RexW, OpPlusReg) {
    fn encode<E>(emitter: &mut E, (reg, rax): (Reg64, Reg64), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(rax == Reg64::Rax);
        let (RexW, OpPlusReg(op)) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_b(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op | reg.rm());
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<MR, (Reg64, Reg64)> for (RexW, Op, ModRm) {
    fn encode<E>(emitter: &mut E, (reg1, reg2): (Reg64, Reg64), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (RexW, Op(op), ModRm) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_rb(reg2, reg1)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        buffer.write_u8(modrm(3, reg2.rm(), reg1.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl Encode<RM, (Reg64, Reg64)> for (RexW, Op, Op, ModRm) {
    fn encode<E>(emitter: &mut E, (reg1, reg2): (Reg64, Reg64), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (RexW, Op(op1), Op(op2), ModRm) = this;
        let mut buffer = Buffer::new();
        if let Some(rex) = rex_rb(reg1, reg2)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        buffer.write_u8(modrm(3, reg1.rm(), reg2.rm()));
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<RM, (Reg64, Byte<P>)> for (RexW, Op, Op, ModRm)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg64, Byte<P>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (RexW, Op(op1), Op(op2), ModRm) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(ptr.rexw_reg(reg)?);
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<RM, (Reg64, Word<P>)> for (RexW, Op, Op, ModRm)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg64, Word<P>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (RexW, Op(op1), Op(op2), ModRm) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(ptr.rexw_reg(reg)?);
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<RM, (Reg64, QWord<P>)> for (RexW, Op, ModRm)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg64, QWord<P>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (RexW, Op(op), ModRm) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(ptr.rexw_reg(reg)?);
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<RM, (Reg64, QWord<P>)> for (RexW, Op, Op, ModRm)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg64, QWord<P>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (RexW, Op(op1), Op(op2), ModRm) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(ptr.rexw_reg(reg)?);
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<M1, (Byte<P>, u8)> for (Op, ModRmIndex)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, imm): (Byte<P>, u8), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(imm == 1);
        let (Op(op), ModRmIndex(modrm_index)) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex()? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<MI, (Byte<P>, u8)> for (Op, ModRmIndex, Imm8)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, imm): (Byte<P>, u8), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRmIndex(modrm_index), Imm8) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex()? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        buffer.write_u8(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<MC, (Byte<P>, Reg8)> for (Op, ModRmIndex)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, cl): (Byte<P>, Reg8), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(cl == Reg8::Cl);
        let (Op(op), ModRmIndex(modrm_index)) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex()? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<MR, (Byte<P>, Reg8)> for (Op, ModRm)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, reg): (Byte<P>, Reg8), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRm) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex_reg(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<M1, (Word<P>, u8)> for (Prefix, Op, ModRmIndex)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, imm): (Word<P>, u8), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(imm == 1);
        let (Prefix(prefix), Op(op), ModRmIndex(modrm_index)) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = ptr.rex()? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<MI, (Word<P>, u8)> for (Prefix, Op, ModRmIndex, Imm8)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, imm): (Word<P>, u8), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Prefix(prefix), Op(op), ModRmIndex(modrm_index), Imm8) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = ptr.rex()? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        buffer.write_u8(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<MI, (Word<P>, u16)> for (Prefix, Op, ModRmIndex, Imm16)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, imm): (Word<P>, u16), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Prefix(prefix), Op(op), ModRmIndex(modrm_index), Imm16) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = ptr.rex()? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        buffer.write_u16(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<MC, (Word<P>, Reg8)> for (Prefix, Op, ModRmIndex)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, cl): (Word<P>, Reg8), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(cl == Reg8::Cl);
        let (Prefix(prefix), Op(op), ModRmIndex(modrm_index)) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = ptr.rex()? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<MR, (Word<P>, Reg16)> for (Prefix, Op, ModRm)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, reg): (Word<P>, Reg16), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Prefix(prefix), Op(op), ModRm) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = ptr.rex_reg(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<M1, (DWord<P>, u8)> for (Op, ModRmIndex)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, imm): (DWord<P>, u8), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(imm == 1);
        let (Op(op), ModRmIndex(modrm_index)) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex()? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<MI, (DWord<P>, u8)> for (Op, ModRmIndex, Imm8)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, imm): (DWord<P>, u8), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRmIndex(modrm_index), Imm8) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex()? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        buffer.write_u8(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<MI, (DWord<P>, u32)> for (Op, ModRmIndex, Imm32)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, imm): (DWord<P>, u32), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRmIndex(modrm_index), Imm32) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex()? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        buffer.write_u32(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<MC, (DWord<P>, Reg8)> for (Op, ModRmIndex)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, cl): (DWord<P>, Reg8), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(cl == Reg8::Cl);
        let (Op(op), ModRmIndex(modrm_index)) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex()? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<MR, (DWord<P>, Reg32)> for (Op, ModRm)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, reg): (DWord<P>, Reg32), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRm) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        if let Some(rex) = ptr.rex_reg(reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<M1, (QWord<P>, u8)> for (RexW, Op, ModRmIndex)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, imm): (QWord<P>, u8), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(imm == 1);
        let (RexW, Op(op), ModRmIndex(modrm_index)) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(ptr.rexw()?);
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<MI, (QWord<P>, u8)> for (RexW, Op, ModRmIndex, Imm8)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, imm): (QWord<P>, u8), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (RexW, Op(op), ModRmIndex(modrm_index), Imm8) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(ptr.rexw()?);
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        buffer.write_u8(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<MI, (QWord<P>, u32)> for (RexW, Op, ModRmIndex, Imm32)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, imm): (QWord<P>, u32), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (RexW, Op(op), ModRmIndex(modrm_index), Imm32) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(ptr.rexw()?);
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        buffer.write_u32(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<MC, (QWord<P>, Reg8)> for (RexW, Op, ModRmIndex)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, cl): (QWord<P>, Reg8), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        debug_assert!(cl == Reg8::Cl);
        let (RexW, Op(op), ModRmIndex(modrm_index)) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(ptr.rexw()?);
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<P> Encode<MR, (QWord<P>, Reg64)> for (RexW, Op, ModRm)
    where P: Mem
{
    fn encode<E>(emitter: &mut E, (ptr, reg): (QWord<P>, Reg64), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (RexW, Op(op), ModRm) = this;
        let ptr = ptr.0;
        let mut buffer = Buffer::new();
        buffer.write_u8(ptr.rexw_reg(reg)?);
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}
