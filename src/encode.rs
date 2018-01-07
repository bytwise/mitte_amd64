use EmitBytes;
use common::*;
use reg::{Reg8, Reg16, Reg32, Reg64};
use ptr::{Ptr, BytePtr, WordPtr, DWordPtr, QWordPtr};
use error::Error;
use buffer::Buffer;


pub struct None;
pub struct D;
pub struct I;
pub struct M;
pub struct O;
pub struct MI;
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

impl<B, X, D> Encode<M, BytePtr<B, X, D>> for (Op, Op, ModRmIndex)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<()>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, ptr: BytePtr<B, X, D>, this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op1), Op(op2), ModRmIndex(modrm_index)) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        if let Some(rex) = Rex::rex(ptr.clone(), ())? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        Args::write(&mut buffer, ptr, modrm_index)?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<B, X, D> Encode<M, BytePtr<B, X, D>> for (Op, ModRmIndex)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<()>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, ptr: BytePtr<B, X, D>, this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRmIndex(modrm_index)) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        if let Some(rex) = Rex::rex(ptr.clone(), ())? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<B, X, D> Encode<M, WordPtr<B, X, D>> for (Prefix, Op, ModRmIndex)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<()>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, ptr: WordPtr<B, X, D>, this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Prefix(prefix), Op(op), ModRmIndex(modrm_index)) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = Rex::rex(ptr.clone(), ())? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<B, X, D> Encode<M, DWordPtr<B, X, D>> for (Op, ModRmIndex)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<()>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, ptr: DWordPtr<B, X, D>, this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRmIndex(modrm_index)) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        if let Some(rex) = Rex::rex(ptr.clone(), ())? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<B, X, D> Encode<M, QWordPtr<B, X, D>> for (Op, ModRmIndex)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<()>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, ptr: QWordPtr<B, X, D>, this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRmIndex(modrm_index)) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        if let Some(rex) = Rex::rex(ptr.clone(), ())? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<B, X, D> Encode<M, QWordPtr<B, X, D>> for (RexW, Op, ModRmIndex)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<()>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, ptr: QWordPtr<B, X, D>, this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (RexW, Op(op), ModRmIndex(modrm_index)) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        buffer.write_u8(Rex::rexw(ptr.clone(), ())?);
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

impl Encode<M, (Reg8, Reg8)> for (Op, ModRmIndex) {
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

impl<B, X, D> Encode<RM, (Reg8, BytePtr<B, X, D>)> for (Op, ModRm)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<Reg8>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg8, BytePtr<B, X, D>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRm) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        if let Some(rex) = Rex::rex(ptr.clone(), reg)? {
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

impl Encode<M, (Reg16, Reg8)> for (Prefix, Op, ModRmIndex) {
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

impl<B, X, D> Encode<RM, (Reg16, BytePtr<B, X, D>)> for (Prefix, Op, Op, ModRm)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<Reg16>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg16, BytePtr<B, X, D>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Prefix(prefix), Op(op1), Op(op2), ModRm) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = Rex::rex(ptr.clone(), reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<B, X, D> Encode<RM, (Reg16, WordPtr<B, X, D>)> for (Prefix, Op, ModRm)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<Reg16>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg16, WordPtr<B, X, D>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Prefix(prefix), Op(op), ModRm) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = Rex::rex(ptr.clone(), reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<B, X, D> Encode<RM, (Reg16, WordPtr<B, X, D>)> for (Prefix, Op, Op, ModRm)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<Reg16>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg16, WordPtr<B, X, D>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Prefix(prefix), Op(op1), Op(op2), ModRm) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = Rex::rex(ptr.clone(), reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        Args::write(&mut buffer, ptr, reg.rm())?;
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

impl Encode<M, (Reg32, Reg8)> for (Op, ModRmIndex) {
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

impl<B, X, D> Encode<RM, (Reg32, BytePtr<B, X, D>)> for (Op, Op, ModRm)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<Reg32>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg32, BytePtr<B, X, D>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op1), Op(op2), ModRm) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        if let Some(rex) = Rex::rex(ptr.clone(), reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<B, X, D> Encode<RM, (Reg32, WordPtr<B, X, D>)> for (Op, Op, ModRm)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<Reg32>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg32, WordPtr<B, X, D>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op1), Op(op2), ModRm) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        if let Some(rex) = Rex::rex(ptr.clone(), reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<B, X, D> Encode<RM, (Reg32, DWordPtr<B, X, D>)> for (Op, ModRm)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<Reg32>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg32, DWordPtr<B, X, D>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRm) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        if let Some(rex) = Rex::rex(ptr.clone(), reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<B, X, D> Encode<RM, (Reg32, DWordPtr<B, X, D>)> for (Op, Op, ModRm)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<Reg32>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg32, DWordPtr<B, X, D>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op1), Op(op2), ModRm) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        if let Some(rex) = Rex::rex(ptr.clone(), reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        Args::write(&mut buffer, ptr, reg.rm())?;
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

impl Encode<M, (Reg64, Reg8)> for (RexW, Op, ModRmIndex) {
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

impl<B, X, D> Encode<RM, (Reg64, BytePtr<B, X, D>)> for (RexW, Op, Op, ModRm)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<Reg64>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg64, BytePtr<B, X, D>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (RexW, Op(op1), Op(op2), ModRm) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        buffer.write_u8(Rex::rexw(ptr.clone(), reg)?);
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<B, X, D> Encode<RM, (Reg64, WordPtr<B, X, D>)> for (RexW, Op, Op, ModRm)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<Reg64>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg64, WordPtr<B, X, D>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (RexW, Op(op1), Op(op2), ModRm) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        buffer.write_u8(Rex::rexw(ptr.clone(), reg)?);
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<B, X, D> Encode<RM, (Reg64, QWordPtr<B, X, D>)> for (RexW, Op, ModRm)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<Reg64>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg64, QWordPtr<B, X, D>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (RexW, Op(op), ModRm) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        buffer.write_u8(Rex::rexw(ptr.clone(), reg)?);
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<B, X, D> Encode<RM, (Reg64, QWordPtr<B, X, D>)> for (RexW, Op, Op, ModRm)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<Reg64>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, (reg, ptr): (Reg64, QWordPtr<B, X, D>), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (RexW, Op(op1), Op(op2), ModRm) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        buffer.write_u8(Rex::rexw(ptr.clone(), reg)?);
        buffer.write_u8(op1);
        buffer.write_u8(op2);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<B, X, D> Encode<MI, (BytePtr<B, X, D>, u8)> for (Op, ModRmIndex, Imm8)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<()>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, (ptr, imm): (BytePtr<B, X, D>, u8), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRmIndex(modrm_index), Imm8) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        if let Some(rex) = Rex::rex(ptr.clone(), ())? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        buffer.write_u8(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<B, X, D> Encode<MR, (BytePtr<B, X, D>, Reg8)> for (Op, ModRm)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<Reg8>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, (ptr, reg): (BytePtr<B, X, D>, Reg8), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRm) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        if let Some(rex) = Rex::rex(ptr.clone(), reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<B, X, D> Encode<MI, (WordPtr<B, X, D>, u16)> for (Prefix, Op, ModRmIndex, Imm16)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<()>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, (ptr, imm): (WordPtr<B, X, D>, u16), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Prefix(prefix), Op(op), ModRmIndex(modrm_index), Imm16) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = Rex::rex(ptr.clone(), ())? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        buffer.write_u16(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<B, X, D> Encode<MR, (WordPtr<B, X, D>, Reg16)> for (Prefix, Op, ModRm)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<Reg16>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, (ptr, reg): (WordPtr<B, X, D>, Reg16), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Prefix(prefix), Op(op), ModRm) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        buffer.write_u8(prefix);
        if let Some(rex) = Rex::rex(ptr.clone(), reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<B, X, D> Encode<MI, (DWordPtr<B, X, D>, u32)> for (Op, ModRmIndex, Imm32)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<()>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, (ptr, imm): (DWordPtr<B, X, D>, u32), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRmIndex(modrm_index), Imm32) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        if let Some(rex) = Rex::rex(ptr.clone(), ())? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        buffer.write_u32(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<B, X, D> Encode<MR, (DWordPtr<B, X, D>, Reg32)> for (Op, ModRm)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<Reg32>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, (ptr, reg): (DWordPtr<B, X, D>, Reg32), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (Op(op), ModRm) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        if let Some(rex) = Rex::rex(ptr.clone(), reg)? {
            buffer.write_u8(rex);
        }
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<B, X, D> Encode<MI, (QWordPtr<B, X, D>, u32)> for (RexW, Op, ModRmIndex, Imm32)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<()>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, (ptr, imm): (QWordPtr<B, X, D>, u32), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (RexW, Op(op), ModRmIndex(modrm_index), Imm32) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        buffer.write_u8(Rex::rexw(ptr.clone(), ())?);
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, modrm_index)?;
        buffer.write_u32(imm);
        emitter.write(&buffer)?;
        Ok(())
    }
}

impl<B, X, D> Encode<MR, (QWordPtr<B, X, D>, Reg64)> for (RexW, Op, ModRm)
    where Ptr<B, X, D>: Clone,
          Ptr<B, X, D>: Rex<Reg64>,
          Ptr<B, X, D>: Args<u8>
{
    fn encode<E>(emitter: &mut E, (ptr, reg): (QWordPtr<B, X, D>, Reg64), this: Self)
        -> Result<(), Error<E::Error>>
        where E: EmitBytes
    {
        let (RexW, Op(op), ModRm) = this;
        let ptr = ptr.ptr;
        let mut buffer = Buffer::new();
        buffer.write_u8(Rex::rexw(ptr.clone(), reg)?);
        buffer.write_u8(op);
        Args::write(&mut buffer, ptr, reg.rm())?;
        emitter.write(&buffer)?;
        Ok(())
    }
}
