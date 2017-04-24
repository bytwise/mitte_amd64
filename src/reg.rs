use common::Register;
use error::{Error, Result};
pub use self::Reg8::*;
pub use self::Reg16::*;
pub use self::Reg32::*;
pub use self::Reg64::*;


#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reg8 {
    Al = 0,
    Cl = 1,
    Dl = 2,
    Bl = 3,
    Ah = 4,
    Ch = 5,
    Dh = 6,
    Bh = 7,
    R8b = 8,
    R9b = 9,
    R10b = 0xa,
    R11b = 0xb,
    R12b = 0xc,
    R13b = 0xd,
    R14b = 0xe,
    R15b = 0xf,
    Spl = 0x14,
    Bpl = 0x15,
    Sil = 0x16,
    Dil = 0x17,
}

impl Default for Reg8 {
    fn default() -> Reg8 {
        Reg8::Al
    }
}

impl Register for Reg8 {
    #[inline]
    fn size(&self) -> usize {
        1
    }

    #[inline]
    fn is_64bit(&self) -> bool {
        false
    }

    #[inline]
    fn has_extended_index(&self) -> bool {
        *self as u8 & 0x8 != 0
    }

    #[inline]
    fn is_encodable_with_rex(&self) -> bool {
        (*self as u8) < 4 || *self as u8 >= 8
    }

    #[inline]
    fn needs_rex(&self) -> bool {
        *self as u8 >= 8
    }

    #[inline]
    fn rm(&self) -> u8 {
        *self as u8 & 7
    }

    #[inline]
    fn check_is_rex_compatible(&self) -> Result<()> {
        if self.is_encodable_with_rex() {
            Ok(())
        } else {
            Err(Error::RexIncompatibleRegister(*self))
        }
    }
}


#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reg16 {
    Ax = 0,
    Cx = 1,
    Dx = 2,
    Bx = 3,
    Sp = 4,
    Bp = 5,
    Si = 6,
    Di = 7,
    R8w = 8,
    R9w = 9,
    R10w = 10,
    R11w = 11,
    R12w = 12,
    R13w = 13,
    R14w = 14,
    R15w = 15,
}

impl Default for Reg16 {
    fn default() -> Reg16 {
        Reg16::Ax
    }
}

impl Register for Reg16 {
    #[inline]
    fn size(&self) -> usize {
        2
    }

    #[inline]
    fn is_64bit(&self) -> bool {
        false
    }

    #[inline]
    fn has_extended_index(&self) -> bool {
        *self as u8 & 0x8 != 0
    }

    #[inline]
    fn is_encodable_with_rex(&self) -> bool {
        true
    }

    #[inline]
    fn needs_rex(&self) -> bool {
        self.has_extended_index()
    }

    #[inline]
    fn rm(&self) -> u8 {
        *self as u8 & 7
    }

    #[inline]
    fn check_is_rex_compatible(&self) -> Result<()> {
        Ok(())
    }
}


#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reg32 {
    Eax = 0,
    Ecx = 1,
    Edx = 2,
    Ebx = 3,
    Esp = 4,
    Ebp = 5,
    Esi = 6,
    Edi = 7,
    R8d = 8,
    R9d = 9,
    R10d = 10,
    R11d = 11,
    R12d = 12,
    R13d = 13,
    R14d = 14,
    R15d = 15,
}

impl Default for Reg32 {
    fn default() -> Reg32 {
        Reg32::Eax
    }
}

impl Register for Reg32 {
    #[inline]
    fn size(&self) -> usize {
        4
    }

    #[inline]
    fn is_64bit(&self) -> bool {
        false
    }

    #[inline]
    fn has_extended_index(&self) -> bool {
        *self as u8 & 0x8 != 0
    }

    #[inline]
    fn is_encodable_with_rex(&self) -> bool {
        true
    }

    #[inline]
    fn needs_rex(&self) -> bool {
        self.has_extended_index()
    }

    #[inline]
    fn rm(&self) -> u8 {
        *self as u8 & 7
    }

    #[inline]
    fn check_is_rex_compatible(&self) -> Result<()> {
        Ok(())
    }
}


#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reg64 {
    Rax = 0,
    Rcx = 1,
    Rdx = 2,
    Rbx = 3,
    Rsp = 4,
    Rbp = 5,
    Rsi = 6,
    Rdi = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
}

impl Default for Reg64 {
    fn default() -> Reg64 {
        Reg64::Rax
    }
}

impl Reg64 {
    #[inline]
    pub fn to_reg32(&self) -> Reg32 {
        match *self {
            Reg64::Rax => Reg32::Eax,
            Reg64::Rcx => Reg32::Ecx,
            Reg64::Rdx => Reg32::Edx,
            Reg64::Rbx => Reg32::Ebx,
            Reg64::Rsp => Reg32::Esp,
            Reg64::Rbp => Reg32::Ebp,
            Reg64::Rsi => Reg32::Esi,
            Reg64::Rdi => Reg32::Edi,
            Reg64::R8 => Reg32::R8d,
            Reg64::R9 => Reg32::R9d,
            Reg64::R10 => Reg32::R10d,
            Reg64::R11 => Reg32::R11d,
            Reg64::R12 => Reg32::R12d,
            Reg64::R13 => Reg32::R13d,
            Reg64::R14 => Reg32::R14d,
            Reg64::R15 => Reg32::R15d,
        }
    }
}

impl Register for Reg64 {
    #[inline]
    fn size(&self) -> usize {
        8
    }

    #[inline]
    fn is_64bit(&self) -> bool {
        true
    }

    #[inline]
    fn has_extended_index(&self) -> bool {
        *self as u8 & 0x8 != 0
    }

    #[inline]
    fn is_encodable_with_rex(&self) -> bool {
        true
    }

    #[inline]
    fn needs_rex(&self) -> bool {
        true
    }

    #[inline]
    fn rm(&self) -> u8 {
        *self as u8 & 7
    }

    #[inline]
    fn check_is_rex_compatible(&self) -> Result<()> {
        Ok(())
    }
}
