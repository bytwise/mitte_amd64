extern crate byteorder;

use std::io::{Write, Cursor};
use byteorder::{WriteBytesExt, LittleEndian};
use amd64::*;

mod buffer;
mod ptr;
mod common;
#[macro_use]
mod macros;

pub mod reg;
pub mod operand;
pub mod error;
pub mod fixup;
pub mod label;

pub mod amd64;

pub use ptr::{byte_ptr, word_ptr, dword_ptr, qword_ptr};
pub use ptr::{Ptr, BytePtr, WordPtr, DWordPtr, QWordPtr};
pub use ptr::{byte_pointer, word_pointer, dword_pointer, qword_pointer};
pub use ptr::{Pointer, BytePointer, WordPointer, DWordPointer, QWordPointer};
pub use operand::Operand;
pub use error::Error;
pub use fixup::Fixup;


pub trait EmitBytes {
    type Error: std::error::Error;
    fn pos(&self) -> u64;
    fn write(&mut self, buf: &[u8]) -> Result<(), Self::Error>;
    fn fixup(&mut self, fixup: Fixup) -> Result<(), Self::Error>;
}

impl<'a, W> EmitBytes for &'a mut W where W: EmitBytes {
    type Error = W::Error;

    fn pos(&self) -> u64 {
        EmitBytes::pos(*self)
    }

    fn write(&mut self, buf: &[u8]) -> std::result::Result<(), Self::Error> {
        EmitBytes::write(*self, buf)
    }

    fn fixup(&mut self, fixup: Fixup) -> std::result::Result<(), Self::Error> {
        EmitBytes::fixup(*self, fixup)
    }
}

impl<W> EmitBytes for Cursor<W> where Cursor<W>: Write, W: AsRef<[u8]> {
    type Error = std::io::Error;

    fn pos(&self) -> u64 {
        self.position()
    }

    fn write(&mut self, buf: &[u8]) -> std::result::Result<(), Self::Error> {
        self.write_all(buf)
    }

    fn fixup(&mut self, fixup: Fixup) -> std::result::Result<(), Self::Error> {
        let end = self.position();
        match fixup {
            Fixup::Rel8(addr, offset) => {
                self.set_position(addr);
                try!(self.write_u8(offset as u8));
                self.set_position(end);
            }
            Fixup::Rel32(addr, offset) => {
                self.set_position(addr);
                try!(self.write_u32::<LittleEndian>(offset as u32));
                self.set_position(end);
            }
        }
        Ok(())
    }
}

impl EmitBytes for Vec<u8> {
    type Error = std::io::Error;

    #[inline]
    fn pos(&self) -> u64 {
        self.len() as u64
    }

    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.extend_from_slice(buf);
        Ok(())
    }

    #[inline]
    fn fixup(&mut self, fixup: Fixup) -> Result<(), Self::Error> {
        match fixup {
            Fixup::Rel8(addr, offset) => {
                let mut slice = &mut self[addr as usize..];
                slice.write_u8(offset as u8)
            }
            Fixup::Rel32(addr, offset) => {
                let mut slice = &mut self[addr as usize..];
                slice.write_u32::<LittleEndian>(offset as u32)
            }
        }
    }
}


pub trait Emit: EmitBytes {
    fn add<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Add<D, S>
    {
        Add::write(self, dst, src)
    }

    fn or<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Or<D, S>
    {
        Or::write(self, dst, src)
    }

    fn adc<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Adc<D, S>
    {
        Adc::write(self, dst, src)
    }

    fn sbb<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Sbb<D, S>
    {
        Sbb::write(self, dst, src)
    }

    fn and<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: And<D, S>
    {
        And::write(self, dst, src)
    }

    fn sub<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Sub<D, S>
    {
        Sub::write(self, dst, src)
    }

    fn xor<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Xor<D, S>
    {
        Xor::write(self, dst, src)
    }

    fn cmp<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Cmp<D, S>
    {
        Cmp::write(self, dst, src)
    }

    fn shl<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Shl<D, S>
    {
        Shl::write(self, dst, src)
    }

    fn shr<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Shr<D, S>
    {
        Shr::write(self, dst, src)
    }

    fn sar<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Sar<D, S>
    {
        Sar::write(self, dst, src)
    }

    fn not<T>(&mut self, arg: T) -> Result<(), Error<Self::Error>> where Self: Not<T> {
        Not::write(self, arg)
    }

    fn neg<T>(&mut self, arg: T) -> Result<(), Error<Self::Error>> where Self: Neg<T> {
        Neg::write(self, arg)
    }

    fn mul<T>(&mut self, arg: T) -> Result<(), Error<Self::Error>> where Self: Mul<T> {
        Mul::write(self, arg)
    }

    fn imul<T>(&mut self, arg: T) -> Result<(), Error<Self::Error>> where Self: Imul<T> {
        Imul::write(self, arg)
    }

    fn div<T>(&mut self, arg: T) -> Result<(), Error<Self::Error>> where Self: Div<T> {
        Div::write(self, arg)
    }

    fn idiv<T>(&mut self, arg: T) -> Result<(), Error<Self::Error>> where Self: Idiv<T> {
        Idiv::write(self, arg)
    }

    fn inc<T>(&mut self, arg: T) -> Result<(), Error<Self::Error>> where Self: Inc<T> {
        Inc::write(self, arg)
    }

    fn dec<T>(&mut self, arg: T) -> Result<(), Error<Self::Error>> where Self: Dec<T> {
        Dec::write(self, arg)
    }

    fn test<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Test<D, S>
    {
        Test::write(self, dst, src)
    }

    fn mov<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Mov<D, S>
    {
        Mov::write(self, dst, src)
    }

    fn push<S>(&mut self, src: S) -> Result<(), Error<Self::Error>> where Self: Push<S> {
        Push::write(self, src)
    }

    fn pop<D>(&mut self, dst: D) -> Result<(), Error<Self::Error>> where Self: Pop<D> {
        Pop::write(self, dst)
    }

    fn call<T>(&mut self, arg: T) -> Result<(), Error<Self::Error>> where Self: Call<T> {
        Call::write(self, arg)
    }

    fn jmp<T, R>(&mut self, arg: T) -> Result<R, Error<Self::Error>>
        where Self: Jmp<T, Return=R>
    {
        Jmp::write(self, arg)
    }

    fn ret(&mut self) -> Result<(), Error<Self::Error>> where Self: Ret {
        Ret::write(self)
    }

    fn cmove<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Cmove<D, S>
    {
        Cmove::write(self, dst, src)
    }

    fn cmovz<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Cmovz<D, S>
    {
        Cmovz::write(self, dst, src)
    }

    fn cmovne<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Cmovne<D, S>
    {
        Cmovne::write(self, dst, src)
    }

    fn cmovnz<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Cmovnz<D, S>
    {
        Cmovnz::write(self, dst, src)
    }

    fn cmova<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Cmova<D, S>
    {
        Cmova::write(self, dst, src)
    }

    fn cmovl<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Cmovl<D, S>
    {
        Cmovl::write(self, dst, src)
    }

    fn cmovge<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Cmovge<D, S>
    {
        Cmovge::write(self, dst, src)
    }

    fn cmovle<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Cmovle<D, S>
    {
        Cmovle::write(self, dst, src)
    }

    fn cmovg<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Cmovg<D, S>
    {
        Cmovg::write(self, dst, src)
    }

    fn je<T, R>(&mut self, arg: T) -> Result<R, Error<Self::Error>> where Self: Je<T, Return=R> {
        Je::write(self, arg)
    }

    fn jz<T, R>(&mut self, arg: T) -> Result<R, Error<Self::Error>> where Self: Jz<T, Return=R> {
        Jz::write(self, arg)
    }

    fn jne<T, R>(&mut self, arg: T) -> Result<R, Error<Self::Error>>
        where Self: Jne<T, Return=R>
    {
        Jne::write(self, arg)
    }

    fn jnz<T, R>(&mut self, arg: T) -> Result<R, Error<Self::Error>>
        where Self: Jnz<T, Return=R>
    {
        Jnz::write(self, arg)
    }

    fn ja<T, R>(&mut self, arg: T) -> Result<R, Error<Self::Error>> where Self: Ja<T, Return=R> {
        Ja::write(self, arg)
    }

    fn jl<T, R>(&mut self, arg: T) -> Result<R, Error<Self::Error>> where Self: Jl<T, Return=R> {
        Jl::write(self, arg)
    }

    fn jge<T, R>(&mut self, arg: T) -> Result<R, Error<Self::Error>>
        where Self: Jge<T, Return=R>
    {
        Jge::write(self, arg)
    }

    fn jle<T, R>(&mut self, arg: T) -> Result<R, Error<Self::Error>>
        where Self: Jle<T, Return=R>
    {
        Jle::write(self, arg)
    }

    fn jg<T, R>(&mut self, arg: T) -> Result<R, Error<Self::Error>> where Self: Jg<T, Return=R> {
        Jg::write(self, arg)
    }

    fn sete<D>(&mut self, dst: D) -> Result<(), Error<Self::Error>> where Self: Sete<D> {
        Sete::write(self, dst)
    }

    fn setz<D>(&mut self, dst: D) -> Result<(), Error<Self::Error>> where Self: Setz<D> {
        Setz::write(self, dst)
    }

    fn setne<D>(&mut self, dst: D) -> Result<(), Error<Self::Error>> where Self: Setne<D> {
        Setne::write(self, dst)
    }

    fn setnz<D>(&mut self, dst: D) -> Result<(), Error<Self::Error>> where Self: Setnz<D> {
        Setnz::write(self, dst)
    }

    fn seta<D>(&mut self, dst: D) -> Result<(), Error<Self::Error>> where Self: Seta<D> {
        Seta::write(self, dst)
    }

    fn setl<D>(&mut self, dst: D) -> Result<(), Error<Self::Error>> where Self: Setl<D> {
        Setl::write(self, dst)
    }

    fn setge<D>(&mut self, dst: D) -> Result<(), Error<Self::Error>> where Self: Setge<D> {
        Setge::write(self, dst)
    }

    fn setle<D>(&mut self, dst: D) -> Result<(), Error<Self::Error>> where Self: Setle<D> {
        Setle::write(self, dst)
    }

    fn setg<D>(&mut self, dst: D) -> Result<(), Error<Self::Error>> where Self: Setg<D> {
        Setg::write(self, dst)
    }

    fn lea<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Lea<D, S>
    {
        Lea::write(self, dst, src)
    }

    fn movzx<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Movzx<D, S>
    {
        Movzx::write(self, dst, src)
    }

    fn movsx<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Movsx<D, S>
    {
        Movsx::write(self, dst, src)
    }

    fn cdq(&mut self) -> Result<(), Error<Self::Error>> where Self: Cdq {
        Cdq::write(self)
    }

    fn xchg<D, S>(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>
        where Self: Xchg<D, S>
    {
        Xchg::write(self, dst, src)
    }
}

impl<W> Emit for W where W: EmitBytes {}
