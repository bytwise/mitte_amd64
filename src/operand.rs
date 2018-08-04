use reg::{Reg8, Reg16, Reg32, Reg64};
use ptr::{Byte, Word, DWord, QWord};
use ptr::Pointer;


#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Operand {
    Imm8(u8),
    Imm16(u16),
    Imm32(u32),
    Imm64(u64),
    Reg8(Reg8),
    Reg16(Reg16),
    Reg32(Reg32),
    Reg64(Reg64),
    Offset8(i8),
    Offset16(i16),
    Offset32(i32),
    Offset64(i64),
    BytePointer(Byte<Pointer>),
    WordPointer(Word<Pointer>),
    DWordPointer(DWord<Pointer>),
    QWordPointer(QWord<Pointer>),
}


pub fn byte_pointer<M>(m: M) -> Operand where M: Into<Pointer> {
    Operand::BytePointer(Byte(m.into()))
}

pub fn word_pointer<M>(m: M) -> Operand where M: Into<Pointer> {
    Operand::WordPointer(Word(m.into()))
}

pub fn dword_pointer<M>(m: M) -> Operand where M: Into<Pointer> {
    Operand::DWordPointer(DWord(m.into()))
}

pub fn qword_pointer<M>(m: M) -> Operand where M: Into<Pointer> {
    Operand::QWordPointer(QWord(m.into()))
}
