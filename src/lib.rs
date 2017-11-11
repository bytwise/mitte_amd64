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


macro_rules! forward1 {
    ($f:ident ($($arg:ident : $T:ident),*) => $Trait:ident) => {
        fn $f<$($T),*>(&mut self $(, $arg: $T)*) -> Result<(), Error<Self::Error>>
            where Self: $Trait<$($T),*>
        {
            $Trait::write(self $(, $arg)*)
        }
    };
    ($f:ident ($($arg:ident : $T:ident),*) -> $R:ident => $Trait:ident) => {
        fn $f<$($T,)* $R>(&mut self $(, $arg: $T)*) -> Result<$R, Error<Self::Error>>
            where Self: $Trait<$($T,)* Return=$R>
        {
            $Trait::write(self $(, $arg)*)
        }
    };
}

macro_rules! forward {
    ($( $f:ident ($($arg:ident : $T:ident),*) $(-> $R:ident)* => $Trait:ident; )*) => {
        $(
            forward1!($f($($arg: $T),*) $(-> $R)* => $Trait);
        )*
    }
}

pub trait Emit: EmitBytes {
    forward! {
        add(dst: D, src: S) => Add;
        or(dst: D, src: S) => Or;
        adc(dst: D, src: S) => Adc;
        sbb(dst: D, src: S) => Sbb;
        and(dst: D, src: S) => And;
        sub(dst: D, src: S) => Sub;
        xor(dst: D, src: S) => Xor;
        cmp(dst: D, src: S) => Cmp;
        shl(dst: D, src: S) => Shl;
        shr(dst: D, src: S) => Shr;
        sar(dst: D, src: S) => Sar;
        not(arg: T) => Not;
        neg(arg: T) => Neg;
        mul(arg: T) => Mul;
        imul(arg: T) => Imul;
        div(arg: T) => Div;
        idiv(arg: T) => Idiv;
        inc(arg: T) => Inc;
        dec(arg: T) => Dec;
        test(arg1: D, arg2: S) => Test;
        mov(dst: D, src: S) => Mov;
        push(src: S) => Push;
        pop(dst: D) => Pop;
        call(arg: T) => Call;
        jmp(arg: T) -> R => Jmp;
        ret() => Ret;

        cmova(dst: D, src: S) => Cmova;
        cmove(dst: D, src: S) => Cmove;
        cmovg(dst: D, src: S) => Cmovg;
        cmovge(dst: D, src: S) => Cmovge;
        cmovl(dst: D, src: S) => Cmovl;
        cmovle(dst: D, src: S) => Cmovle;
        cmovne(dst: D, src: S) => Cmovne;
        cmovnz(dst: D, src: S) => Cmovnz;
        cmovz(dst: D, src: S) => Cmovz;

        ja(arg: T) -> R => Ja;
        je(arg: T) -> R => Je;
        jg(arg: T) -> R => Jg;
        jge(arg: T) -> R => Jge;
        jl(arg: T) -> R => Jl;
        jle(arg: T) -> R => Jle;
        jne(arg: T) -> R => Jne;
        jnz(arg: T) -> R => Jnz;
        jz(arg: T) -> R => Jz;

        seta(dst: D) => Seta;
        sete(dst: D) => Sete;
        setg(dst: D) => Setg;
        setge(dst: D) => Setge;
        setl(dst: D) => Setl;
        setle(dst: D) => Setle;
        setne(dst: D) => Setne;
        setnz(dst: D) => Setnz;
        setz(dst: D) => Setz;

        lea(dst: D, src: S) => Lea;
        movzx(dst: D, src: S) => Movzx;
        movsx(dst: D, src: S) => Movsx;
        cdq() => Cdq;
        xchg(dst: D, src: S) => Xchg;
    }
}

impl<W> Emit for W where W: EmitBytes {}
