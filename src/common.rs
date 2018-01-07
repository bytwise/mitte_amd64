use std::fmt;

use buffer::{self, Buffer};
use reg::Reg64;
use ptr::{Scale, Scaled};
use ptr::Ptr;
use error::Error;


/// This function helps the compiler infer the right lifetimes
/// for the closures used in this crate
pub fn closure<F, R>(f: F) -> F where F: FnOnce(&mut Buffer) -> R { f }


pub enum NoError {}

impl<E> From<Error<NoError>> for Error<E>
    where E: ::std::error::Error
{
    fn from(error: Error<NoError>) -> Error<E> {
        match error {
            Error::InvalidOperands => Error::InvalidOperands,
            Error::RexIncompatibleRegister(reg) => Error::RexIncompatibleRegister(reg),
            Error::InvalidIndexRegister(reg) => Error::InvalidIndexRegister(reg),
            Error::RedefinedLabel => Error::RedefinedLabel,
            Error::LabelTooFarAway => Error::LabelTooFarAway,
            Error::Custom(e) => match e {},
        }
    }
}


pub trait Register: Copy + 'static + fmt::Debug {
    /// Returns the register size in bytes.
    fn size(&self) -> usize;
    fn is_64bit(&self) -> bool;
    fn has_extended_index(&self) -> bool;
    fn is_encodable_with_rex(&self) -> bool;
    fn needs_rex(&self) -> bool;
    fn rm(&self) -> u8;
    fn check_is_rex_compatible(&self) -> Result<(), Error<NoError>>;
}


pub fn rex_r<R>(r: R) -> Result<Option<u8>, Error<NoError>>
    where R: Register
{
    if !r.needs_rex() {
        return Ok(None);
    }

    let rex = 0x40
        | (r.is_64bit() as u8) << 3
        | (r.has_extended_index() as u8) << 2;

    Ok(Some(rex))
}

pub fn rex_x<X>(x: X) -> Result<Option<u8>, Error<NoError>>
    where X: Register
{
    if !x.needs_rex() {
        return Ok(None);
    }

    let rex = 0x40
        | (x.is_64bit() as u8) << 3
        | (x.has_extended_index() as u8) << 1;

    Ok(Some(rex))
}

pub fn rex_b<B>(b: B) -> Result<Option<u8>, Error<NoError>>
    where B: Register
{
    if !b.needs_rex() {
        return Ok(None);
    }

    let rex = 0x40
        | (b.is_64bit() as u8) << 3
        | b.has_extended_index() as u8;

    Ok(Some(rex))
}

pub fn rex_rx<R, X>(r: R, x: X) -> Result<Option<u8>, Error<NoError>>
    where R: Register, X: Register
{
    if !r.needs_rex() && !x.needs_rex() {
        return Ok(None);
    }

    try!(r.check_is_rex_compatible());
    try!(x.check_is_rex_compatible());

    let rex = 0x40
        | ((r.is_64bit() | x.is_64bit()) as u8) << 3
        | (r.has_extended_index() as u8) << 2
        | (x.has_extended_index() as u8) << 1;

    Ok(Some(rex))
}

pub fn rex_rb<R, B>(r: R, b: B) -> Result<Option<u8>, Error<NoError>>
    where R: Register, B: Register
{
    if !r.needs_rex() && !b.needs_rex() {
        return Ok(None);
    }

    try!(r.check_is_rex_compatible());
    try!(b.check_is_rex_compatible());

    let rex = 0x40
        | ((r.is_64bit() | b.is_64bit()) as u8) << 3
        | (r.has_extended_index() as u8) << 2
        | b.has_extended_index() as u8;

    Ok(Some(rex))
}

pub fn rex_xb<X, B>(x: X, b: B) -> Result<Option<u8>, Error<NoError>>
    where X: Register, B: Register
{
    if !x.needs_rex() && !b.needs_rex() {
        return Ok(None);
    }

    try!(x.check_is_rex_compatible());
    try!(b.check_is_rex_compatible());

    let rex = 0x40
        | ((x.is_64bit() | b.is_64bit()) as u8) << 3
        | (x.has_extended_index() as u8) << 1
        | b.has_extended_index() as u8;

    Ok(Some(rex))
}

pub fn rex_rxb<R, X, B>(r: R, x: X, b: B) -> Result<Option<u8>, Error<NoError>>
    where R: Register, X: Register, B: Register
{
    if !r.needs_rex() && !x.needs_rex() && !b.needs_rex() {
        return Ok(None);
    }

    try!(r.check_is_rex_compatible());
    try!(x.check_is_rex_compatible());
    try!(b.check_is_rex_compatible());

    let rex = 0x40
        | ((r.is_64bit() | x.is_64bit() | b.is_64bit()) as u8) << 3
        | (r.has_extended_index() as u8) << 2
        | (x.has_extended_index() as u8) << 1
        | b.has_extended_index() as u8;

    Ok(Some(rex))
}


#[inline]
pub fn modrm(mode: u8, reg: u8, rm: u8) -> u8 {
    debug_assert!(mode < 4);
    debug_assert!(reg < 8);
    debug_assert!(rm < 8);
    (mode << 6) | ((reg & 7) << 3) | (rm & 7)
}


#[inline]
pub fn sib(scale: u8, index: u8, base: u8) -> u8 {
    debug_assert!(scale < 4);
    debug_assert!(index < 8);
    debug_assert!(base < 8);
    (scale << 6) | ((index & 7) << 3) | (base & 7)
}


#[inline]
pub fn write_reg_disp(buffer: &mut Buffer, reg: u8, disp: i32) -> Result<(), Error<NoError>> {
    buffer.write_u8(modrm(0, reg, 4));
    buffer.write_u8(sib(0, 4, 5));
    buffer.write_u32(disp as u32);
    Ok(())
}

#[inline]
pub fn write_reg_base(buffer: &mut Buffer, reg: u8, base: Reg64) -> Result<(), Error<NoError>> {
    if base.rm() == 5 { // rbp, r13
        buffer.write_u8(modrm(1, reg, base.rm()));
        buffer.write_u8(0);
    } else {
        buffer.write_u8(modrm(0, reg, base.rm()));
        if base.rm() == 4 { // rsp, r12
            buffer.write_u8(sib(0, 4, 4));
        }
    }
    Ok(())
}

#[inline]
pub fn write_reg_base_disp8(buffer: &mut Buffer, reg: u8, base: Reg64, disp: i8) -> Result<(), Error<NoError>> {
    buffer.write_u8(modrm(1, reg, base.rm()));
    if base.rm() == 4 { // rsp, r12
        buffer.write_u8(sib(0, 4, 4));
    }
    buffer.write_u8(disp as u8);
    Ok(())
}

#[inline]
pub fn write_reg_base_disp32(buffer: &mut Buffer, reg: u8, base: Reg64, disp: i32) -> Result<(), Error<NoError>> {
    buffer.write_u8(modrm(2, reg, base.rm()));
    if base.rm() == 4 { // rsp, r12
        buffer.write_u8(sib(0, 4, 4));
    }
    buffer.write_u32(disp as u32);
    Ok(())
}

#[inline]
pub fn write_reg_index(buffer: &mut Buffer, reg: u8, index: Reg64, scale: Scale) -> Result<(), Error<NoError>> {
    if index.rm() == 4 { // rsp, r12
        return Err(Error::InvalidIndexRegister(index));
    }
    buffer.write_u8(modrm(0, reg, 4));
    buffer.write_u8(sib(scale as u8, index.rm(), 5));
    buffer.write_u32(0);
    Ok(())
}

#[inline]
pub fn write_reg_index_disp(buffer: &mut Buffer, reg: u8, index: Reg64, scale: Scale, disp: i32) -> Result<(), Error<NoError>> {
    if index.rm() == 4 { // rsp, r12
        return Err(Error::InvalidIndexRegister(index));
    }
    buffer.write_u8(modrm(0, reg, 4));
    buffer.write_u8(sib(scale as u8, index.rm(), 5));
    buffer.write_u32(disp as u32);
    Ok(())
}

#[inline]
pub fn write_reg_base_index(buffer: &mut Buffer, reg: u8, base: Reg64, index: Reg64, scale: Scale) -> Result<(), Error<NoError>> {
    if index.rm() == 4 { // rsp, r12
        return Err(Error::InvalidIndexRegister(index));
    }
    if base.rm() == 5 { // rbp, r13
        buffer.write_u8(modrm(1, reg, 4));
        buffer.write_u8(sib(scale as u8, index.rm(), base.rm()));
        buffer.write_u8(0);
    } else {
        buffer.write_u8(modrm(0, reg, 4));
        buffer.write_u8(sib(scale as u8, index.rm(), base.rm()));
    }
    Ok(())
}

#[inline]
pub fn write_reg_base_index_disp8(buffer: &mut Buffer, reg: u8, base: Reg64, index: Reg64, scale: Scale, disp: i8) -> Result<(), Error<NoError>> {
    if index.rm() == 4 { // rsp, r12
        return Err(Error::InvalidIndexRegister(index));
    }
    buffer.write_u8(modrm(1, reg, 4));
    buffer.write_u8(sib(scale as u8, index.rm(), base.rm()));
    buffer.write_u8(disp as u8);
    Ok(())
}

#[inline]
pub fn write_reg_base_index_disp32(buffer: &mut Buffer, reg: u8, base: Reg64, index: Reg64, scale: Scale, disp: i32) -> Result<(), Error<NoError>> {
    if index.rm() == 4 { // rsp, r12
        return Err(Error::InvalidIndexRegister(index));
    }
    buffer.write_u8(modrm(2, reg, 4));
    buffer.write_u8(sib(scale as u8, index.rm(), base.rm()));
    buffer.write_u32(disp as u32);
    Ok(())
}


pub trait Rex<T> {
    fn rex(ptr: Self, arg: T) -> Result<Option<u8>, Error<NoError>>;

    fn rexw(ptr: Self, arg: T) -> Result<u8, Error<NoError>>
        where Self: Sized
    {
        Rex::rex(ptr, arg).map(|rex| 0x48 | rex.unwrap_or(0))
    }
}

macro_rules! rex {
    () => {};

    (
        <$($A:ident : $bound:ident),*>
        $p:ident : Ptr<$B:ty, $X:ty, _>,
        $arg:ident : $T:ty => $e:expr;
        $($rest:tt)*
    ) => {
        impl<D, $($A : $bound),*> Rex<$T> for Ptr<$B, $X, D> {
            fn rex($p: Ptr<$B, $X, D>, $arg: $T) -> Result<Option<u8>, Error<NoError>> {
                $e
            }
        }
        rex! { $($rest)* }
    };

    (
        $p:ident : Ptr<$B:ty, $X:ty, _>,
        $arg:ident : $T:ty => $e:expr;
        $($rest:tt)*
    ) => {
        impl<D> Rex<$T> for Ptr<$B, $X, D> {
            fn rex($p: Ptr<$B, $X, D>, $arg: $T) -> Result<Option<u8>, Error<NoError>> {
                $e
            }
        }
        rex! { $($rest)* }
    };
}

rex! {
    _p: Ptr<(), (), _>,              _a: () => Ok(None);
    p: Ptr<Reg64, (), _>,            _a: () => rex_b(p.base.to_reg32());
    p: Ptr<(), Scaled<Reg64>, _>,    _a: () => rex_x(p.index.0.to_reg32());
    p: Ptr<Reg64, Scaled<Reg64>, _>, _a: () => rex_xb(p.index.0.to_reg32(), p.base.to_reg32());

    <R: Register>
    _p: Ptr<(), (), _>,              reg: R => rex_r(reg);
    <R: Register>
    p: Ptr<Reg64, (), _>,            reg: R => rex_rb(reg, p.base.to_reg32());
    <R: Register>
    p: Ptr<(), Scaled<Reg64>, _>,    reg: R => rex_rx(reg, p.index.0.to_reg32());
    <R: Register>
    p: Ptr<Reg64, Scaled<Reg64>, _>, reg: R => rex_rxb(reg, p.index.0.to_reg32(), p.base.to_reg32());
}


pub trait Args<T> {
    fn write(buffer: &mut Buffer, ptr: Self, arg: T) -> Result<(), Error<NoError>>;
}

macro_rules! args {
    () => {};

    (
        $p:ident : Ptr<$B:ty, $X:ty, $D:ty>,
        $arg:ident : $T:ty => $($e:expr),*;
        $($rest:tt)*
    ) => {
        impl Args<$T> for Ptr<$B, $X, $D> {
            #[inline]
            fn write(buffer: &mut Buffer, $p: Ptr<$B, $X, $D>, $arg: $T) -> Result<(), Error<NoError>> {
                $(
                    try!(buffer::Write::write(buffer, $e));
                )*
                Ok(())
            }
        }
        args! { $($rest)* }
    };
}

args! {
    p: Ptr<(), (), i8>, reg: u8 =>
        closure(|buffer| write_reg_disp(buffer, reg, p.disp as i32));

    p: Ptr<(), (), i32>, reg: u8 =>
        closure(|buffer| write_reg_disp(buffer, reg, p.disp));

    p: Ptr<Reg64, (), ()>, reg: u8 =>
        closure(|buffer| write_reg_base(buffer, reg, p.base));

    p: Ptr<Reg64, (), i8>, reg: u8 =>
        closure(|buffer| write_reg_base_disp8(buffer, reg, p.base, p.disp));

    p: Ptr<Reg64, (), i32>, reg: u8 =>
        closure(|buffer| write_reg_base_disp32(buffer, reg, p.base, p.disp));

    p: Ptr<(), Scaled<Reg64>, ()>, reg: u8 =>
        closure(|buffer| write_reg_index(buffer, reg, p.index.0, p.index.1));

    p: Ptr<(), Scaled<Reg64>, i8>, reg: u8 =>
        closure(|buffer| write_reg_index_disp(buffer, reg, p.index.0, p.index.1, p.disp as i32));

    p: Ptr<(), Scaled<Reg64>, i32>, reg: u8 =>
        closure(|buffer| write_reg_index_disp(buffer, reg, p.index.0, p.index.1, p.disp));

    p: Ptr<Reg64, Scaled<Reg64>, ()>, reg: u8 =>
        closure(|buffer| write_reg_base_index(buffer, reg, p.base, p.index.0, p.index.1));

    p: Ptr<Reg64, Scaled<Reg64>, i8>, reg: u8 =>
        closure(|buffer| {
            write_reg_base_index_disp8(buffer, reg, p.base, p.index.0, p.index.1, p.disp)
        });

    p: Ptr<Reg64, Scaled<Reg64>, i32>, reg: u8 =>
        closure(|buffer| {
            write_reg_base_index_disp32(buffer, reg, p.base, p.index.0, p.index.1, p.disp)
        });
}
