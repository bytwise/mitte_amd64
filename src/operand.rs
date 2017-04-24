use reg::{Reg8, Reg16, Reg32, Reg64};
use ptr::{BytePointer, WordPointer, DWordPointer, QWordPointer};


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
    BytePointer(BytePointer),
    WordPointer(WordPointer),
    DWordPointer(DWordPointer),
    QWordPointer(QWordPointer),
}


pub fn byte_pointer<M>(m: M) -> Operand where M: Into<BytePointer> {
    Operand::BytePointer(m.into())
}

pub fn word_pointer<M>(m: M) -> Operand where M: Into<WordPointer> {
    Operand::WordPointer(m.into())
}

pub fn dword_pointer<M>(m: M) -> Operand where M: Into<DWordPointer> {
    Operand::DWordPointer(m.into())
}

pub fn qword_pointer<M>(m: M) -> Operand where M: Into<QWordPointer> {
    Operand::QWordPointer(m.into())
}
