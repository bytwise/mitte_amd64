extern crate byteorder;

use std::io::{Write, Cursor};
use byteorder::{WriteBytesExt, LittleEndian};
use amd64::*;

mod buffer;
mod ptr;
mod common;
#[macro_use]
mod macros;
mod encode;

pub mod reg;
pub mod operand;
pub mod error;
pub mod fixup;
pub mod label;

pub mod amd64;

pub use ptr::{Mem, Byte, Word, DWord, QWord};
pub use ptr::{byte_ptr, word_ptr, dword_ptr, qword_ptr};
pub use ptr::{byte_pointer, word_pointer, dword_pointer, qword_pointer};
pub use ptr::{Ptr, Pointer};
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

pub trait Emit: EmitBytes + Sized {
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
        cmovae(dst: D, src: S) => Cmovae;
        cmovb(dst: D, src: S) => Cmovb;
        cmovbe(dst: D, src: S) => Cmovbe;
        cmovc(dst: D, src: S) => Cmovc;
        cmove(dst: D, src: S) => Cmove;
        cmovg(dst: D, src: S) => Cmovg;
        cmovge(dst: D, src: S) => Cmovge;
        cmovl(dst: D, src: S) => Cmovl;
        cmovle(dst: D, src: S) => Cmovle;
        cmovna(dst: D, src: S) => Cmovna;
        cmovnae(dst: D, src: S) => Cmovnae;
        cmovnb(dst: D, src: S) => Cmovnb;
        cmovnbe(dst: D, src: S) => Cmovnbe;
        cmovnc(dst: D, src: S) => Cmovnc;
        cmovne(dst: D, src: S) => Cmovne;
        cmovng(dst: D, src: S) => Cmovng;
        cmovnge(dst: D, src: S) => Cmovnge;
        cmovnl(dst: D, src: S) => Cmovnl;
        cmovnle(dst: D, src: S) => Cmovnle;
        cmovno(dst: D, src: S) => Cmovno;
        cmovnp(dst: D, src: S) => Cmovnp;
        cmovns(dst: D, src: S) => Cmovns;
        cmovnz(dst: D, src: S) => Cmovnz;
        cmovo(dst: D, src: S) => Cmovo;
        cmovp(dst: D, src: S) => Cmovp;
        cmovpe(dst: D, src: S) => Cmovpe;
        cmovpo(dst: D, src: S) => Cmovpo;
        cmovs(dst: D, src: S) => Cmovs;
        cmovz(dst: D, src: S) => Cmovz;

        ja(arg: T) -> R => Ja;
        jae(arg: T) -> R => Jae;
        jb(arg: T) -> R => Jb;
        jbe(arg: T) -> R => Jbe;
        jc(arg: T) -> R => Jc;
        je(arg: T) -> R => Je;
        jg(arg: T) -> R => Jg;
        jge(arg: T) -> R => Jge;
        jl(arg: T) -> R => Jl;
        jle(arg: T) -> R => Jle;
        jna(arg: T) -> R => Jna;
        jnae(arg: T) -> R => Jnae;
        jnb(arg: T) -> R => Jnb;
        jnbe(arg: T) -> R => Jnbe;
        jnc(arg: T) -> R => Jnc;
        jne(arg: T) -> R => Jne;
        jng(arg: T) -> R => Jng;
        jnge(arg: T) -> R => Jnge;
        jnl(arg: T) -> R => Jnl;
        jnle(arg: T) -> R => Jnle;
        jno(arg: T) -> R => Jno;
        jnp(arg: T) -> R => Jnp;
        jns(arg: T) -> R => Jns;
        jnz(arg: T) -> R => Jnz;
        jo(arg: T) -> R => Jo;
        jp(arg: T) -> R => Jp;
        jpe(arg: T) -> R => Jpe;
        jpo(arg: T) -> R => Jpo;
        js(arg: T) -> R => Js;
        jz(arg: T) -> R => Jz;

        seta(dst: D) => Seta;
        setae(dst: D) => Setae;
        setb(dst: D) => Setb;
        setbe(dst: D) => Setbe;
        setc(dst: D) => Setc;
        sete(dst: D) => Sete;
        setg(dst: D) => Setg;
        setge(dst: D) => Setge;
        setl(dst: D) => Setl;
        setle(dst: D) => Setle;
        setna(dst: D) => Setna;
        setnae(dst: D) => Setnae;
        setnb(dst: D) => Setnb;
        setnbe(dst: D) => Setnbe;
        setnc(dst: D) => Setnc;
        setne(dst: D) => Setne;
        setng(dst: D) => Setng;
        setnge(dst: D) => Setnge;
        setnl(dst: D) => Setnl;
        setnle(dst: D) => Setnle;
        setno(dst: D) => Setno;
        setnp(dst: D) => Setnp;
        setns(dst: D) => Setns;
        setnz(dst: D) => Setnz;
        seto(dst: D) => Seto;
        setp(dst: D) => Setp;
        setpe(dst: D) => Setpe;
        setpo(dst: D) => Setpo;
        sets(dst: D) => Sets;
        setz(dst: D) => Setz;

        lea(dst: D, src: S) => Lea;
        movzx(dst: D, src: S) => Movzx;
        movsx(dst: D, src: S) => Movsx;

        cdq() => Cdq;
        xchg(dst: D, src: S) => Xchg;
    }
}

impl<W> Emit for W where W: EmitBytes {}
