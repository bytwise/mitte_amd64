extern crate arrayvec;
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
                self.write_u8(offset as u8)?;
                self.set_position(end);
            }
            Fixup::Rel32(addr, offset) => {
                self.set_position(addr);
                self.write_u32::<LittleEndian>(offset as u32)?;
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
            $Trait::emit(self $(, $arg)*)
        }
    };
    ($f:ident ($($arg:ident : $T:ident),*) -> $R:ident => $Trait:ident) => {
        fn $f<$($T,)* $R>(&mut self $(, $arg: $T)*) -> Result<$R, Error<Self::Error>>
            where Self: $Trait<$($T,)* Return=$R>
        {
            $Trait::emit(self $(, $arg)*)
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
        emit_add(dst: D, src: S) => Add;
        emit_or(dst: D, src: S) => Or;
        emit_adc(dst: D, src: S) => Adc;
        emit_sbb(dst: D, src: S) => Sbb;
        emit_and(dst: D, src: S) => And;
        emit_sub(dst: D, src: S) => Sub;
        emit_xor(dst: D, src: S) => Xor;
        emit_cmp(dst: D, src: S) => Cmp;
        emit_shl(dst: D, src: S) => Shl;
        emit_shr(dst: D, src: S) => Shr;
        emit_sar(dst: D, src: S) => Sar;
        emit_not(arg: T) => Not;
        emit_neg(arg: T) => Neg;
        emit_mul(arg: T) => Mul;
        emit_imul(arg: T) => Imul;
        emit_div(arg: T) => Div;
        emit_idiv(arg: T) => Idiv;
        emit_inc(arg: T) => Inc;
        emit_dec(arg: T) => Dec;
        emit_test(arg1: D, arg2: S) => Test;
        emit_mov(dst: D, src: S) => Mov;
        emit_push(src: S) => Push;
        emit_pop(dst: D) => Pop;
        emit_call(arg: T) => Call;
        emit_jmp(arg: T) -> R => Jmp;
        emit_ret() => Ret;

        emit_cmova(dst: D, src: S) => Cmova;
        emit_cmovae(dst: D, src: S) => Cmovae;
        emit_cmovb(dst: D, src: S) => Cmovb;
        emit_cmovbe(dst: D, src: S) => Cmovbe;
        emit_cmovc(dst: D, src: S) => Cmovc;
        emit_cmove(dst: D, src: S) => Cmove;
        emit_cmovg(dst: D, src: S) => Cmovg;
        emit_cmovge(dst: D, src: S) => Cmovge;
        emit_cmovl(dst: D, src: S) => Cmovl;
        emit_cmovle(dst: D, src: S) => Cmovle;
        emit_cmovna(dst: D, src: S) => Cmovna;
        emit_cmovnae(dst: D, src: S) => Cmovnae;
        emit_cmovnb(dst: D, src: S) => Cmovnb;
        emit_cmovnbe(dst: D, src: S) => Cmovnbe;
        emit_cmovnc(dst: D, src: S) => Cmovnc;
        emit_cmovne(dst: D, src: S) => Cmovne;
        emit_cmovng(dst: D, src: S) => Cmovng;
        emit_cmovnge(dst: D, src: S) => Cmovnge;
        emit_cmovnl(dst: D, src: S) => Cmovnl;
        emit_cmovnle(dst: D, src: S) => Cmovnle;
        emit_cmovno(dst: D, src: S) => Cmovno;
        emit_cmovnp(dst: D, src: S) => Cmovnp;
        emit_cmovns(dst: D, src: S) => Cmovns;
        emit_cmovnz(dst: D, src: S) => Cmovnz;
        emit_cmovo(dst: D, src: S) => Cmovo;
        emit_cmovp(dst: D, src: S) => Cmovp;
        emit_cmovpe(dst: D, src: S) => Cmovpe;
        emit_cmovpo(dst: D, src: S) => Cmovpo;
        emit_cmovs(dst: D, src: S) => Cmovs;
        emit_cmovz(dst: D, src: S) => Cmovz;

        emit_ja(arg: T) -> R => Ja;
        emit_jae(arg: T) -> R => Jae;
        emit_jb(arg: T) -> R => Jb;
        emit_jbe(arg: T) -> R => Jbe;
        emit_jc(arg: T) -> R => Jc;
        emit_je(arg: T) -> R => Je;
        emit_jg(arg: T) -> R => Jg;
        emit_jge(arg: T) -> R => Jge;
        emit_jl(arg: T) -> R => Jl;
        emit_jle(arg: T) -> R => Jle;
        emit_jna(arg: T) -> R => Jna;
        emit_jnae(arg: T) -> R => Jnae;
        emit_jnb(arg: T) -> R => Jnb;
        emit_jnbe(arg: T) -> R => Jnbe;
        emit_jnc(arg: T) -> R => Jnc;
        emit_jne(arg: T) -> R => Jne;
        emit_jng(arg: T) -> R => Jng;
        emit_jnge(arg: T) -> R => Jnge;
        emit_jnl(arg: T) -> R => Jnl;
        emit_jnle(arg: T) -> R => Jnle;
        emit_jno(arg: T) -> R => Jno;
        emit_jnp(arg: T) -> R => Jnp;
        emit_jns(arg: T) -> R => Jns;
        emit_jnz(arg: T) -> R => Jnz;
        emit_jo(arg: T) -> R => Jo;
        emit_jp(arg: T) -> R => Jp;
        emit_jpe(arg: T) -> R => Jpe;
        emit_jpo(arg: T) -> R => Jpo;
        emit_js(arg: T) -> R => Js;
        emit_jz(arg: T) -> R => Jz;

        emit_seta(dst: D) => Seta;
        emit_setae(dst: D) => Setae;
        emit_setb(dst: D) => Setb;
        emit_setbe(dst: D) => Setbe;
        emit_setc(dst: D) => Setc;
        emit_sete(dst: D) => Sete;
        emit_setg(dst: D) => Setg;
        emit_setge(dst: D) => Setge;
        emit_setl(dst: D) => Setl;
        emit_setle(dst: D) => Setle;
        emit_setna(dst: D) => Setna;
        emit_setnae(dst: D) => Setnae;
        emit_setnb(dst: D) => Setnb;
        emit_setnbe(dst: D) => Setnbe;
        emit_setnc(dst: D) => Setnc;
        emit_setne(dst: D) => Setne;
        emit_setng(dst: D) => Setng;
        emit_setnge(dst: D) => Setnge;
        emit_setnl(dst: D) => Setnl;
        emit_setnle(dst: D) => Setnle;
        emit_setno(dst: D) => Setno;
        emit_setnp(dst: D) => Setnp;
        emit_setns(dst: D) => Setns;
        emit_setnz(dst: D) => Setnz;
        emit_seto(dst: D) => Seto;
        emit_setp(dst: D) => Setp;
        emit_setpe(dst: D) => Setpe;
        emit_setpo(dst: D) => Setpo;
        emit_sets(dst: D) => Sets;
        emit_setz(dst: D) => Setz;

        emit_lea(dst: D, src: S) => Lea;
        emit_movzx(dst: D, src: S) => Movzx;
        emit_movsx(dst: D, src: S) => Movsx;

        emit_cdq() => Cdq;
        emit_xchg(dst: D, src: S) => Xchg;

        emit_ud2() => Ud2;
    }
}

impl<W> Emit for W where W: EmitBytes {}
