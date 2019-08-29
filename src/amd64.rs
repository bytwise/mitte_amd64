use EmitBytes;
use reg::{Reg8, Reg16, Reg32, Reg64};
use ptr::{Mem, Byte, Word, DWord, QWord};
use operand::Operand;
use error::Error;
use fixup::{HoleKind, Hole};
use encode::{None, D, I, M, O, M1, MI, MC, MR, RM, OI, XchgSrc, XchgDst};
use encode::{Prefix, RexW, Op, OpPlusReg, ModRm, ModRmIndex, Imm8, Imm16, Imm32, Imm64};


struct ArithOpcodes {
    index: u8,
    reg8: u8,
    reg32: u8,
    mem8: u8,
    mem32: u8,
    al: u8,
    eax: u8,
    imm8: u8,
    imm32: u8,
    sext_imm8: u8,
}

const ADD: ArithOpcodes = ArithOpcodes {
    index: 0,
    reg8: 0x00,
    reg32: 0x01,
    mem8: 0x02,
    mem32: 0x03,
    al: 0x04,
    eax: 0x05,
    imm8: 0x80,
    imm32: 0x81,
    sext_imm8: 0x83,
};

const OR: ArithOpcodes = ArithOpcodes {
    index: 1,
    reg8: 0x08,
    reg32: 0x09,
    mem8: 0x0a,
    mem32: 0x0b,
    al: 0x0c,
    eax: 0x0d,
    imm8: 0x80,
    imm32: 0x81,
    sext_imm8: 0x83,
};

const ADC: ArithOpcodes = ArithOpcodes {
    index: 2,
    reg8: 0x10,
    reg32: 0x11,
    mem8: 0x12,
    mem32: 0x13,
    al: 0x14,
    eax: 0x15,
    imm8: 0x80,
    imm32: 0x81,
    sext_imm8: 0x83,
};

const SBB: ArithOpcodes = ArithOpcodes {
    index: 3,
    reg8: 0x18,
    reg32: 0x19,
    mem8: 0x1a,
    mem32: 0x1b,
    al: 0x1c,
    eax: 0x1d,
    imm8: 0x80,
    imm32: 0x81,
    sext_imm8: 0x83,
};

const AND: ArithOpcodes = ArithOpcodes {
    index: 4,
    reg8: 0x20,
    reg32: 0x21,
    mem8: 0x22,
    mem32: 0x23,
    al: 0x24,
    eax: 0x25,
    imm8: 0x80,
    imm32: 0x81,
    sext_imm8: 0x83,
};

const SUB: ArithOpcodes = ArithOpcodes {
    index: 5,
    reg8: 0x28,
    reg32: 0x29,
    mem8: 0x2a,
    mem32: 0x2b,
    al: 0x2c,
    eax: 0x2d,
    imm8: 0x80,
    imm32: 0x81,
    sext_imm8: 0x83,
};

const XOR: ArithOpcodes = ArithOpcodes {
    index: 6,
    reg8: 0x30,
    reg32: 0x31,
    mem8: 0x32,
    mem32: 0x33,
    al: 0x34,
    eax: 0x35,
    imm8: 0x80,
    imm32: 0x81,
    sext_imm8: 0x83,
};

const CMP: ArithOpcodes = ArithOpcodes {
    index: 7,
    reg8: 0x38,
    reg32: 0x39,
    mem8: 0x3a,
    mem32: 0x3b,
    al: 0x3c,
    eax: 0x3d,
    imm8: 0x80,
    imm32: 0x81,
    sext_imm8: 0x83,
};


struct ShiftOpcodes {
    index: u8,
}

const SHL: ShiftOpcodes = ShiftOpcodes {
    index: 4,
};

const SHR: ShiftOpcodes = ShiftOpcodes {
    index: 5,
};

const SAR: ShiftOpcodes = ShiftOpcodes {
    index: 7,
};


mod cond {
    pub struct Cond(pub u8);

    pub const A: Cond = Cond(0x7);
    pub const AE: Cond = Cond(0x3);
    pub const B: Cond = Cond(0x2);
    pub const BE: Cond = Cond(0x6);
    pub const C: Cond = Cond(0x2);
    pub const E: Cond = Cond(0x4);
    pub const G: Cond = Cond(0xf);
    pub const GE: Cond = Cond(0xd);
    pub const L: Cond = Cond(0xc);
    pub const LE: Cond = Cond(0xe);
    pub const NA: Cond = Cond(0x6);
    pub const NAE: Cond = Cond(0x2);
    pub const NB: Cond = Cond(0x3);
    pub const NBE: Cond = Cond(0x7);
    pub const NC: Cond = Cond(0x3);
    pub const NE: Cond = Cond(0x5);
    pub const NG: Cond = Cond(0xe);
    pub const NGE: Cond = Cond(0xc);
    pub const NL: Cond = Cond(0xd);
    pub const NLE: Cond = Cond(0xf);
    pub const NO: Cond = Cond(0x1);
    pub const NP: Cond = Cond(0xb);
    pub const NS: Cond = Cond(0x9);
    pub const NZ: Cond = Cond(0x5);
    pub const O: Cond = Cond(0x0);
    pub const P: Cond = Cond(0xa);
    pub const PE: Cond = Cond(0xa);
    pub const PO: Cond = Cond(0xb);
    pub const S: Cond = Cond(0x8);
    pub const Z: Cond = Cond(0x4);
}


macro_rules! binary_arith_op {
    ($(($Op:ident, $op:ident)),*) => {
        $(
        pub trait $Op<D, S>: EmitBytes {
            fn emit(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>;
        }

        impl<W> $Op<Operand, Operand> for W where W: EmitBytes {
            fn emit(&mut self, dst: Operand, src: Operand) -> Result<(), Error<Self::Error>> {
                use operand::Operand::*;
                match (dst, src) {
                    (Reg8(d), Imm8(s)) => $Op::emit(self, d, s),
                    (Reg16(d), Imm8(s)) => $Op::emit(self, d, s),
                    (Reg32(d), Imm8(s)) => $Op::emit(self, d, s),
                    (Reg64(d), Imm8(s)) => $Op::emit(self, d, s),
                    (Reg16(d), Imm16(s)) => $Op::emit(self, d, s),
                    (Reg32(d), Imm32(s)) => $Op::emit(self, d, s),
                    (Reg64(d), Imm32(s)) => $Op::emit(self, d, s),
                    (Reg8(d), Reg8(s)) => $Op::emit(self, d, s),
                    (Reg16(d), Reg16(s)) => $Op::emit(self, d, s),
                    (Reg32(d), Reg32(s)) => $Op::emit(self, d, s),
                    (Reg64(d), Reg64(s)) => $Op::emit(self, d, s),
                    (Reg8(d), BytePointer(s)) => $Op::emit(self, d, s),
                    (Reg16(d), WordPointer(s)) => $Op::emit(self, d, s),
                    (Reg32(d), DWordPointer(s)) => $Op::emit(self, d, s),
                    (Reg64(d), QWordPointer(s)) => $Op::emit(self, d, s),
                    (BytePointer(d), Imm8(s)) => $Op::emit(self, d, s),
                    (WordPointer(d), Imm16(s)) => $Op::emit(self, d, s),
                    (DWordPointer(d), Imm32(s)) => $Op::emit(self, d, s),
                    (QWordPointer(d), Imm32(s)) => $Op::emit(self, d, s),
                    (BytePointer(d), Reg8(s)) => $Op::emit(self, d, s),
                    (WordPointer(d), Reg16(s)) => $Op::emit(self, d, s),
                    (DWordPointer(d), Reg32(s)) => $Op::emit(self, d, s),
                    (QWordPointer(d), Reg64(s)) => $Op::emit(self, d, s),
                    _ => Err(Error::InvalidOperands),
                }
            }
        }

        op! { $Op {
            dst: Reg8, src: u8 =>
                if (dst == Reg8::Al) {
                    (I) Op($op.al), Imm8
                } else {
                    (MI) Op($op.imm8), ModRmIndex($op.index), Imm8
                };
            dst: Reg16, src: u16 =>
                if (dst == Reg16::Ax) {
                    (I) Prefix(0x66), Op($op.eax), Imm16
                } else {
                    (MI) Prefix(0x66), Op($op.imm32), ModRmIndex($op.index), Imm16
                };
            dst: Reg32, src: u32 =>
                if (dst == Reg32::Eax) {
                    (I) Op($op.eax), Imm32
                } else {
                    (MI) Op($op.imm32), ModRmIndex($op.index), Imm32
                };
            dst: Reg64, src: u32 =>
                if (dst == Reg64::Rax) {
                    (I) RexW, Op($op.eax), Imm32
                } else {
                    (MI) RexW, Op($op.imm32), ModRmIndex($op.index), Imm32
                };

            dst: Reg16, src: u8 =>
                (MI) Prefix(0x66), Op($op.sext_imm8), ModRmIndex($op.index), Imm8;
            dst: Reg32, src: u8 =>
                (MI)               Op($op.sext_imm8), ModRmIndex($op.index), Imm8;
            dst: Reg64, src: u8 =>
                (MI) RexW,         Op($op.sext_imm8), ModRmIndex($op.index), Imm8;

            dst: Reg8,  src: Reg8  => (MR)               Op($op.reg8),  ModRm;
            dst: Reg16, src: Reg16 => (MR) Prefix(0x66), Op($op.reg32), ModRm;
            dst: Reg32, src: Reg32 => (MR)               Op($op.reg32), ModRm;
            dst: Reg64, src: Reg64 => (MR) RexW,         Op($op.reg32), ModRm;

            <P: Mem> dst: Reg8,  src: Byte<P>  => (RM)               Op($op.mem8),  ModRm;
            <P: Mem> dst: Reg16, src: Word<P>  => (RM) Prefix(0x66), Op($op.mem32), ModRm;
            <P: Mem> dst: Reg32, src: DWord<P> => (RM)               Op($op.mem32), ModRm;
            <P: Mem> dst: Reg64, src: QWord<P> => (RM) RexW,         Op($op.mem32), ModRm;

            <P: Mem> dst: Byte<P>, src: u8 =>
                (MI) Op($op.imm8), ModRmIndex($op.index), Imm8;
            <P: Mem> dst: Word<P>, src: u16 =>
                (MI) Prefix(0x66), Op($op.imm32), ModRmIndex($op.index), Imm16;
            <P: Mem> dst: DWord<P>, src: u32 =>
                (MI) Op($op.imm32), ModRmIndex($op.index), Imm32;
            <P: Mem> dst: QWord<P>, src: u32 =>
                (MI) RexW, Op($op.imm32), ModRmIndex($op.index), Imm32;

            <P: Mem> dst: Byte<P>,  src: Reg8  => (MR)               Op($op.reg8),  ModRm;
            <P: Mem> dst: Word<P>,  src: Reg16 => (MR) Prefix(0x66), Op($op.reg32), ModRm;
            <P: Mem> dst: DWord<P>, src: Reg32 => (MR)               Op($op.reg32), ModRm;
            <P: Mem> dst: QWord<P>, src: Reg64 => (MR) RexW,         Op($op.reg32), ModRm;
        }}
        )*
    };
}

binary_arith_op! {
    (Add, ADD), (Or, OR), (Adc, ADC), (Sbb, SBB),
    (And, AND), (Sub, SUB), (Xor, XOR), (Cmp, CMP)
}


macro_rules! shift_op {
    ($(($Op:ident, $op:ident)),*) => {
        $(
        pub trait $Op<D, S>: EmitBytes {
            fn emit(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>;
        }

        impl<W> $Op<Operand, Operand> for W where W: EmitBytes {
            fn emit(&mut self, dst: Operand, src: Operand) -> Result<(), Error<Self::Error>> {
                use operand::Operand::*;
                match (dst, src) {
                    (Reg8(d), Imm8(s)) => $Op::emit(self, d, s),
                    (Reg16(d), Imm8(s)) => $Op::emit(self, d, s),
                    (Reg32(d), Imm8(s)) => $Op::emit(self, d, s),
                    (Reg64(d), Imm8(s)) => $Op::emit(self, d, s),
                    (Reg8(d), Reg8(s)) => $Op::emit(self, d, s),
                    (Reg16(d), Reg8(s)) => $Op::emit(self, d, s),
                    (Reg32(d), Reg8(s)) => $Op::emit(self, d, s),
                    (Reg64(d), Reg8(s)) => $Op::emit(self, d, s),
                    (BytePointer(d), Imm8(s)) => $Op::emit(self, d, s),
                    (WordPointer(d), Imm8(s)) => $Op::emit(self, d, s),
                    (DWordPointer(d), Imm8(s)) => $Op::emit(self, d, s),
                    (QWordPointer(d), Imm8(s)) => $Op::emit(self, d, s),
                    (BytePointer(d), Reg8(s)) => $Op::emit(self, d, s),
                    (WordPointer(d), Reg8(s)) => $Op::emit(self, d, s),
                    (DWordPointer(d), Reg8(s)) => $Op::emit(self, d, s),
                    (QWordPointer(d), Reg8(s)) => $Op::emit(self, d, s),
                    _ => Err(Error::InvalidOperands),
                }
            }
        }

        op! { $Op {
            r: Reg8,  shift: u8 =>
                if (shift == 1) {
                    (M1) Op(0xd0), ModRmIndex($op.index)
                } else {
                    (MI) Op(0xc0), ModRmIndex($op.index), Imm8
                };
            r: Reg16, shift: u8 =>
                if (shift == 1) {
                    (M1) Prefix(0x66u8), Op(0xd1), ModRmIndex($op.index)
                } else {
                    (MI) Prefix(0x66u8), Op(0xc1), ModRmIndex($op.index), Imm8
                };
            r: Reg32, shift: u8 =>
                if (shift == 1) {
                    (M1) Op(0xd1), ModRmIndex($op.index)
                } else {
                    (MI) Op(0xc1), ModRmIndex($op.index), Imm8
                };
            r: Reg64, shift: u8 =>
                if (shift == 1) {
                    (M1) RexW, Op(0xd1), ModRmIndex($op.index)
                } else {
                    (MI) RexW, Op(0xc1), ModRmIndex($op.index), Imm8
                };

            r: Reg8,  shift: Reg8; assert_eq!(shift, Reg8::Cl)
                => (MC) Op(0xd2), ModRmIndex($op.index);

            r: Reg16, shift: Reg8; assert_eq!(shift, Reg8::Cl)
                => (MC) Prefix(0x66), Op(0xd3), ModRmIndex($op.index);

            r: Reg32, shift: Reg8; assert_eq!(shift, Reg8::Cl)
                => (MC) Op(0xd3), ModRmIndex($op.index);

            r: Reg64, shift: Reg8; assert_eq!(shift, Reg8::Cl)
                => (MC) RexW, Op(0xd3), ModRmIndex($op.index);

            <P: Mem> p: Byte<P>,  shift: u8 =>
                if (shift == 1) {
                    (M1) Op(0xd0), ModRmIndex($op.index)
                } else {
                    (MI) Op(0xc0), ModRmIndex($op.index), Imm8
                };
            <P: Mem> p: Word<P>, shift: u8 =>
                if (shift == 1) {
                    (M1) Prefix(0x66u8), Op(0xd1), ModRmIndex($op.index)
                } else {
                    (MI) Prefix(0x66u8), Op(0xc1), ModRmIndex($op.index), Imm8
                };
            <P: Mem> p: DWord<P>, shift: u8 =>
                if (shift == 1) {
                    (M1) Op(0xd1), ModRmIndex($op.index)
                } else {
                    (MI) Op(0xc1), ModRmIndex($op.index), Imm8
                };
            <P: Mem> p: QWord<P>, shift: u8 =>
                if (shift == 1) {
                    (M1) RexW, Op(0xd1), ModRmIndex($op.index)
                } else {
                    (MI) RexW, Op(0xc1), ModRmIndex($op.index), Imm8
                };

            <P: Mem> p: Byte<P>,  shift: Reg8; assert_eq!(shift, Reg8::Cl)
                => (MC) Op(0xd2), ModRmIndex($op.index);

            <P: Mem> p: Word<P>,  shift: Reg8; assert_eq!(shift, Reg8::Cl)
                => (MC) Prefix(0x66), Op(0xd3), ModRmIndex($op.index);

            <P: Mem> p: DWord<P>, shift: Reg8; assert_eq!(shift, Reg8::Cl)
                => (MC) Op(0xd3), ModRmIndex($op.index);

            <P: Mem> p: QWord<P>, shift: Reg8; assert_eq!(shift, Reg8::Cl)
                => (MC) RexW, Op(0xd3), ModRmIndex($op.index);
        }}
        )*
    };
}

shift_op! {
    (Shl, SHL), (Shr, SHR), (Sar, SAR)
}


macro_rules! unary_arith_op {
    ($( ($Op:ident, $index:expr) ),*) => {
        $(
            pub trait $Op<T>: EmitBytes {
                fn emit(&mut self, arg: T) -> Result<(), Error<Self::Error>>;
            }

            impl<W> $Op<Operand> for W where W: EmitBytes {
                fn emit(&mut self, arg: Operand) -> Result<(), Error<Self::Error>> {
                    use operand::Operand::*;
                    match arg {
                        Reg8(a) => $Op::emit(self, a),
                        Reg16(a) => $Op::emit(self, a),
                        Reg32(a) => $Op::emit(self, a),
                        Reg64(a) => $Op::emit(self, a),
                        BytePointer(a) => $Op::emit(self, a),
                        WordPointer(a) => $Op::emit(self, a),
                        DWordPointer(a) => $Op::emit(self, a),
                        QWordPointer(a) => $Op::emit(self, a),
                        _ => Err(Error::InvalidOperands),
                    }
                }
            }

            op! { $Op {
                r: Reg8  => (M)               Op(0xf6), ModRmIndex($index);
                r: Reg16 => (M) Prefix(0x66), Op(0xf7), ModRmIndex($index);
                r: Reg32 => (M)               Op(0xf7), ModRmIndex($index);
                r: Reg64 => (M) RexW,         Op(0xf7), ModRmIndex($index);

                <P: Mem> p: Byte<P>  => (M)               Op(0xf6), ModRmIndex($index);
                <P: Mem> p: Word<P>  => (M) Prefix(0x66), Op(0xf7), ModRmIndex($index);
                <P: Mem> p: DWord<P> => (M)               Op(0xf7), ModRmIndex($index);
                <P: Mem> p: QWord<P> => (M) RexW,         Op(0xf7), ModRmIndex($index);
            }}
        )*
    };
}

unary_arith_op! {
    (Not, 2), (Neg, 3), (Mul, 4), (Imul, 5), (Div, 6), (Idiv, 7)
}


pub trait Inc<T>: EmitBytes {
    fn emit(&mut self, arg: T) -> Result<(), Error<Self::Error>>;
}

impl<W> Inc<Operand> for W where W: EmitBytes {
    fn emit(&mut self, arg: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match arg {
            Reg8(a) => Inc::emit(self, a),
            Reg16(a) => Inc::emit(self, a),
            Reg32(a) => Inc::emit(self, a),
            Reg64(a) => Inc::emit(self, a),
            BytePointer(a) => Inc::emit(self, a),
            WordPointer(a) => Inc::emit(self, a),
            DWordPointer(a) => Inc::emit(self, a),
            QWordPointer(a) => Inc::emit(self, a),
            _ => Err(Error::InvalidOperands),
        }
    }
}

op! { Inc {
    r: Reg8  => (M)               Op(0xfe), ModRmIndex(0);
    r: Reg16 => (M) Prefix(0x66), Op(0xff), ModRmIndex(0);
    r: Reg32 => (M)               Op(0xff), ModRmIndex(0);
    r: Reg64 => (M) RexW,         Op(0xff), ModRmIndex(0);

    <P: Mem> p: Byte<P>  => (M)               Op(0xfe), ModRmIndex(0);
    <P: Mem> p: Word<P>  => (M) Prefix(0x66), Op(0xff), ModRmIndex(0);
    <P: Mem> p: DWord<P> => (M)               Op(0xff), ModRmIndex(0);
    <P: Mem> p: QWord<P> => (M) RexW,         Op(0xff), ModRmIndex(0);
}}


pub trait Dec<T>: EmitBytes {
    fn emit(&mut self, arg: T) -> Result<(), Error<Self::Error>>;
}

impl<W> Dec<Operand> for W where W: EmitBytes {
    fn emit(&mut self, arg: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match arg {
            Reg8(a) => Dec::emit(self, a),
            Reg16(a) => Dec::emit(self, a),
            Reg32(a) => Dec::emit(self, a),
            Reg64(a) => Dec::emit(self, a),
            BytePointer(a) => Dec::emit(self, a),
            WordPointer(a) => Dec::emit(self, a),
            DWordPointer(a) => Dec::emit(self, a),
            QWordPointer(a) => Dec::emit(self, a),
            _ => Err(Error::InvalidOperands),
        }
    }
}

op! { Dec {
    r: Reg8  => (M)               Op(0xfe), ModRmIndex(1);
    r: Reg16 => (M) Prefix(0x66), Op(0xff), ModRmIndex(1);
    r: Reg32 => (M)               Op(0xff), ModRmIndex(1);
    r: Reg64 => (M) RexW,         Op(0xff), ModRmIndex(1);

    <P: Mem> p: Byte<P>  => (M)               Op(0xfe), ModRmIndex(1);
    <P: Mem> p: Word<P>  => (M) Prefix(0x66), Op(0xff), ModRmIndex(1);
    <P: Mem> p: DWord<P> => (M)               Op(0xff), ModRmIndex(1);
    <P: Mem> p: QWord<P> => (M) RexW,         Op(0xff), ModRmIndex(1);
}}


pub trait Test<D, S>: EmitBytes {
    fn emit(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>;
}

impl<W> Test<Operand, Operand> for W where W: EmitBytes {
    fn emit(&mut self, dst: Operand, src: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match (dst, src) {
            (Reg8(d), Imm8(s)) => Test::emit(self, d, s),
            (Reg16(d), Imm16(s)) => Test::emit(self, d, s),
            (Reg32(d), Imm32(s)) => Test::emit(self, d, s),
            (Reg64(d), Imm32(s)) => Test::emit(self, d, s),
            (Reg8(d), Reg8(s)) => Test::emit(self, d, s),
            (Reg16(d), Reg16(s)) => Test::emit(self, d, s),
            (Reg32(d), Reg32(s)) => Test::emit(self, d, s),
            (Reg64(d), Reg64(s)) => Test::emit(self, d, s),
            (BytePointer(d), Imm8(s)) => Test::emit(self, d, s),
            (WordPointer(d), Imm16(s)) => Test::emit(self, d, s),
            (DWordPointer(d), Imm32(s)) => Test::emit(self, d, s),
            (QWordPointer(d), Imm32(s)) => Test::emit(self, d, s),
            (BytePointer(d), Reg8(s)) => Test::emit(self, d, s),
            (WordPointer(d), Reg16(s)) => Test::emit(self, d, s),
            (DWordPointer(d), Reg32(s)) => Test::emit(self, d, s),
            (QWordPointer(d), Reg64(s)) => Test::emit(self, d, s),
            _ => Err(Error::InvalidOperands),
        }
    }
}

op! { Test {
    r: Reg8, imm: u8 =>
        if (r == Reg8::Al) {
            (I) Op(0xa8), Imm8
        } else {
            (MI) Op(0xf6), ModRmIndex(0), Imm8
        };
    r: Reg16, imm: u16 =>
        if (r == Reg16::Ax) {
            (I) Prefix(0x66), Op(0xa9), Imm16
        } else {
            (MI) Prefix(0x66), Op(0xf7), ModRmIndex(0), Imm16
        };
    r: Reg32, imm: u32 =>
        if (r == Reg32::Eax) {
            (I) Op(0xa9), Imm32
        } else {
            (MI) Op(0xf7), ModRmIndex(0), Imm32
        };
    r: Reg64, imm: u32 =>
        if (r == Reg64::Rax) {
            (I) RexW, Op(0xa9), Imm32
        } else {
            (MI) RexW, Op(0xf7), ModRmIndex(0), Imm32
        };

    r1: Reg8,  r2: Reg8  => (MR)               Op(0x84), ModRm;
    r1: Reg16, r2: Reg16 => (MR) Prefix(0x66), Op(0x85), ModRm;
    r1: Reg32, r2: Reg32 => (MR)               Op(0x85), ModRm;
    r1: Reg64, r2: Reg64 => (MR) RexW,         Op(0x85), ModRm;

    <P: Mem> p: Byte<P>,  imm: u8  => (MI)               Op(0xf6), ModRmIndex(0), Imm8;
    <P: Mem> p: Word<P>,  imm: u16 => (MI) Prefix(0x66), Op(0xf7), ModRmIndex(0), Imm16;
    <P: Mem> p: DWord<P>, imm: u32 => (MI)               Op(0xf7), ModRmIndex(0), Imm32;
    <P: Mem> p: QWord<P>, imm: u32 => (MI) RexW,         Op(0xf7), ModRmIndex(0), Imm32;

    <P: Mem> p: Byte<P>,  r: Reg8  => (MR)               Op(0x84), ModRm;
    <P: Mem> p: Word<P>,  r: Reg16 => (MR) Prefix(0x66), Op(0x85), ModRm;
    <P: Mem> p: DWord<P>, r: Reg32 => (MR)               Op(0x85), ModRm;
    <P: Mem> p: QWord<P>, r: Reg64 => (MR) RexW,         Op(0x85), ModRm;
}}


pub trait Mov<D, S>: EmitBytes {
    fn emit(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>;
}

impl<W> Mov<Operand, Operand> for W where W: EmitBytes {
    fn emit(&mut self, dst: Operand, src: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match (dst, src) {
            (Reg8(d), Imm8(s)) => Mov::emit(self, d, s),
            (Reg16(d), Imm16(s)) => Mov::emit(self, d, s),
            (Reg32(d), Imm32(s)) => Mov::emit(self, d, s),
            (Reg64(d), Imm64(s)) => Mov::emit(self, d, s),
            (Reg64(d), Imm32(s)) => Mov::emit(self, d, s),
            (Reg8(d), Reg8(s)) => Mov::emit(self, d, s),
            (Reg16(d), Reg16(s)) => Mov::emit(self, d, s),
            (Reg32(d), Reg32(s)) => Mov::emit(self, d, s),
            (Reg64(d), Reg64(s)) => Mov::emit(self, d, s),
            (Reg8(d), BytePointer(s)) => Mov::emit(self, d, s),
            (Reg16(d), WordPointer(s)) => Mov::emit(self, d, s),
            (Reg32(d), DWordPointer(s)) => Mov::emit(self, d, s),
            (Reg64(d), QWordPointer(s)) => Mov::emit(self, d, s),
            (BytePointer(d), Imm8(s)) => Mov::emit(self, d, s),
            (WordPointer(d), Imm16(s)) => Mov::emit(self, d, s),
            (DWordPointer(d), Imm32(s)) => Mov::emit(self, d, s),
            (QWordPointer(d), Imm32(s)) => Mov::emit(self, d, s),
            (BytePointer(d), Reg8(s)) => Mov::emit(self, d, s),
            (WordPointer(d), Reg16(s)) => Mov::emit(self, d, s),
            (DWordPointer(d), Reg32(s)) => Mov::emit(self, d, s),
            (QWordPointer(d), Reg64(s)) => Mov::emit(self, d, s),
            _ => Err(Error::InvalidOperands),
        }
    }
}

op! { Mov {
    dst: Reg8,  src: u8  => (OI)               OpPlusReg(0xb0), Imm8;
    dst: Reg16, src: u16 => (OI) Prefix(0x66), OpPlusReg(0xb8), Imm16;
    dst: Reg32, src: u32 => (OI)               OpPlusReg(0xb8), Imm32;
    dst: Reg64, src: u64 => (OI) RexW,         OpPlusReg(0xb8), Imm64;
    dst: Reg64, src: u32 => (MI) RexW, Op(0xc7), ModRmIndex(0), Imm32;

    dst: Reg8,  src: Reg8  => (MR)               Op(0x88), ModRm;
    dst: Reg16, src: Reg16 => (MR) Prefix(0x66), Op(0x89), ModRm;
    dst: Reg32, src: Reg32 => (MR)               Op(0x89), ModRm;
    dst: Reg64, src: Reg64 => (MR) RexW,         Op(0x89), ModRm;

    <P: Mem> r: Reg8,  p: Byte<P>  => (RM)               Op(0x8a), ModRm;
    <P: Mem> r: Reg16, p: Word<P>  => (RM) Prefix(0x66), Op(0x8b), ModRm;
    <P: Mem> r: Reg32, p: DWord<P> => (RM)               Op(0x8b), ModRm;
    <P: Mem> r: Reg64, p: QWord<P> => (RM) RexW,         Op(0x8b), ModRm;

    <P: Mem> p: Byte<P>,  imm: u8  => (MI)               Op(0xc6), ModRmIndex(0), Imm8;
    <P: Mem> p: Word<P>,  imm: u16 => (MI) Prefix(0x66), Op(0xc7), ModRmIndex(0), Imm16;
    <P: Mem> p: DWord<P>, imm: u32 => (MI)               Op(0xc7), ModRmIndex(0), Imm32;
    <P: Mem> p: QWord<P>, imm: u32 => (MI) RexW,         Op(0xc7), ModRmIndex(0), Imm32;

    <P: Mem> p: Byte<P>,  r: Reg8  => (MR)               Op(0x88), ModRm;
    <P: Mem> p: Word<P>,  r: Reg16 => (MR) Prefix(0x66), Op(0x89), ModRm;
    <P: Mem> p: DWord<P>, r: Reg32 => (MR)               Op(0x89), ModRm;
    <P: Mem> p: QWord<P>, r: Reg64 => (MR) RexW,         Op(0x89), ModRm;
}}


pub trait Push<S>: EmitBytes {
    fn emit(&mut self, src: S) -> Result<(), Error<Self::Error>>;
}

impl<W> Push<Operand> for W where W: EmitBytes {
    fn emit(&mut self, arg: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match arg {
            Imm8(a) => Push::emit(self, a),
            Imm16(a) => Push::emit(self, a),
            Imm32(a) => Push::emit(self, a),
            Reg16(a) => Push::emit(self, a),
            Reg64(a) => Push::emit(self, a),
            WordPointer(a) => Push::emit(self, a),
            QWordPointer(a) => Push::emit(self, a),
            _ => Err(Error::InvalidOperands),
        }
    }
}

op! { Push {
    imm: u8  => (I)               Op(0x6a), Imm8;
    imm: u16 => (I) Prefix(0x66), Op(0x68), Imm16;
    imm: u32 => (I)               Op(0x68), Imm32;
    reg: Reg16 => (O) Prefix(0x66), OpPlusReg(0x50);
    reg: Reg64 => (O)               OpPlusReg(0x50);

    <P: Mem> p: Word<P>  => (M) Prefix(0x66), Op(0xff), ModRmIndex(6);
    <P: Mem> p: QWord<P> => (M)               Op(0xff), ModRmIndex(6);
}}


pub trait Pop<D>: EmitBytes {
    fn emit(&mut self, dst: D) -> Result<(), Error<Self::Error>>;
}

impl<W> Pop<Operand> for W where W: EmitBytes {
    fn emit(&mut self, arg: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match arg {
            Reg16(a) => Pop::emit(self, a),
            Reg64(a) => Pop::emit(self, a),
            WordPointer(a) => Pop::emit(self, a),
            QWordPointer(a) => Pop::emit(self, a),
            _ => Err(Error::InvalidOperands),
        }
    }
}

op! { Pop {
    reg: Reg16 => (O) Prefix(0x66), OpPlusReg(0x58);
    reg: Reg64 => (O)               OpPlusReg(0x58);

    <P: Mem> p: Word<P>  => (M) Prefix(0x66), Op(0x8f), ModRmIndex(0);
    <P: Mem> p: QWord<P> => (M)               Op(0x8f), ModRmIndex(0);
}}


pub trait Call<T>: EmitBytes {
    fn emit(&mut self, arg: T) -> Result<(), Error<Self::Error>>;
}

impl<W> Call<Operand> for W where W: EmitBytes {
    fn emit(&mut self, arg: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match arg {
            Offset32(a) => Call::emit(self, a),
            Reg64(a) => Call::emit(self, a),
            _ => Err(Error::InvalidOperands),
        }
    }
}

op! { Call {
    r: i32 => (D) Op(0xe8), Imm32;
    r: Reg64 => (M) Op(0xff), ModRmIndex(2);
}}


pub trait Jmp<T>: EmitBytes {
    type Return;
    fn emit(&mut self, arg: T) -> Result<Self::Return, Error<Self::Error>>;
}

impl<W> Jmp<Operand> for W where W: EmitBytes {
    type Return = ();
    fn emit(&mut self, arg: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match arg {
            Offset8(a) => Jmp::emit(self, a),
            Offset32(a) => Jmp::emit(self, a),
            Reg64(a) => Jmp::emit(self, a),
            _ => Err(Error::InvalidOperands),
        }
    }
}

impl<W> Jmp<HoleKind> for W where W: EmitBytes {
    type Return = Hole;
    fn emit(&mut self, arg: HoleKind) -> Result<Hole, Error<Self::Error>> {
        use fixup::HoleKind::*;
        match arg {
            Rel8 => {
                try!(self.write(&[0xebu8, -2i8 as u8]));
                Ok(Hole::rel8(self.pos() - 1))
            }
            Rel32 => {
                try!(self.write(&[0xe9u8, -5i8 as u8, 0u8, 0u8, 0u8]));
                Ok(Hole::rel32(self.pos() - 4))
            }
        }
    }
}

op! { Jmp => () {
    imm: i8  => (D) Op(0xeb), Imm8;
    imm: i32 => (D) Op(0xe9), Imm32;
    r: Reg64 => (M) Op(0xff), ModRmIndex(4);
}}


pub trait Ret: EmitBytes {
    fn emit(&mut self) -> Result<(), Error<Self::Error>>;
}

op! { Ret {
    => (None) Op(0xc3);
}}


macro_rules! cc_op {
    ($( ($cond:ident, $Cmov:ident, $J:ident, $Set:ident) ),*) => {
        $(
        pub trait $Cmov<D, S>: EmitBytes {
            fn emit(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>;
        }

        impl<W> $Cmov<Operand, Operand> for W where W: EmitBytes {
            fn emit(&mut self, dst: Operand, src: Operand) -> Result<(), Error<Self::Error>> {
                use operand::Operand::*;
                match (dst, src) {
                    (Reg16(d), Reg16(s)) => $Cmov::emit(self, d, s),
                    (Reg32(d), Reg32(s)) => $Cmov::emit(self, d, s),
                    (Reg64(d), Reg64(s)) => $Cmov::emit(self, d, s),
                    (Reg16(d), WordPointer(s)) => $Cmov::emit(self, d, s),
                    (Reg32(d), DWordPointer(s)) => $Cmov::emit(self, d, s),
                    (Reg64(d), QWordPointer(s)) => $Cmov::emit(self, d, s),
                    _ => Err(Error::InvalidOperands),
                }
            }
        }

        op! { $Cmov {
            dst: Reg16, src: Reg16 => (RM) Prefix(0x66), Op(0x0f), Op(0x40 | cond::$cond.0), ModRm;
            dst: Reg32, src: Reg32 => (RM)               Op(0x0f), Op(0x40 | cond::$cond.0), ModRm;
            dst: Reg64, src: Reg64 => (RM) RexW,         Op(0x0f), Op(0x40 | cond::$cond.0), ModRm;

            <P: Mem> dst: Reg16, src: Word<P> =>
                (RM) Prefix(0x66), Op(0x0f), Op(0x40 | cond::$cond.0), ModRm;
            <P: Mem> dst: Reg32, src: DWord<P> =>
                (RM) Op(0x0f), Op(0x40 | cond::$cond.0), ModRm;
            <P: Mem> dst: Reg64, src: QWord<P> =>
                (RM) RexW, Op(0x0f), Op(0x40 | cond::$cond.0), ModRm;
        }}


        pub trait $J<T>: EmitBytes {
            type Return;
            fn emit(&mut self, arg: T) -> Result<Self::Return, Error<Self::Error>>;
        }

        impl<W> $J<Operand> for W where W: EmitBytes {
            type Return = ();
            fn emit(&mut self, arg: Operand) -> Result<(), Error<Self::Error>> {
                use operand::Operand::*;
                match arg {
                    Offset8(a) => $J::emit(self, a),
                    Offset32(a) => $J::emit(self, a),
                    _ => Err(Error::InvalidOperands),
                }
            }
        }

        impl<W> $J<HoleKind> for W where W: EmitBytes {
            type Return = Hole;
            fn emit(&mut self, arg: HoleKind) -> Result<Hole, Error<Self::Error>> {
                use fixup::HoleKind::*;
                match arg {
                    Rel8 => {
                        try!(self.write(&[0x70u8 | cond::$cond.0, -2i8 as u8]));
                        Ok(Hole::rel8(self.pos() - 1))
                    }
                    Rel32 => {
                        try!(self.write(&[0x0fu8, 0x80u8 | cond::$cond.0,
                                          -6i8 as u8, 0u8, 0u8, 0u8]));
                        Ok(Hole::rel32(self.pos() - 4))
                    }
                }
            }
        }

        op! { $J => () {
            off: i8  => (D)           Op(0x70 | cond::$cond.0), Imm8;
            off: i32 => (D) Op(0x0f), Op(0x80 | cond::$cond.0), Imm32;
        }}


        pub trait $Set<D>: EmitBytes {
            fn emit(&mut self, dst: D) -> Result<(), Error<Self::Error>>;
        }

        impl<W> $Set<Operand> for W where W: EmitBytes {
            fn emit(&mut self, arg: Operand) -> Result<(), Error<Self::Error>> {
                use operand::Operand::*;
                match arg {
                    Reg8(a) => $Set::emit(self, a),
                    BytePointer(a) => $Set::emit(self, a),
                    _ => Err(Error::InvalidOperands),
                }
            }
        }

        op! { $Set {
            r: Reg8 => (M) Op(0x0f), Op(0x90 | cond::$cond.0), ModRmIndex(0);
            <P: Mem> p: Byte<P> => (M) Op(0x0f), Op(0x90 | cond::$cond.0), ModRmIndex(0);
        }}
        )*
    };
}

cc_op! {
    (A,   Cmova,   Ja,   Seta),
    (AE,  Cmovae,  Jae,  Setae),
    (B,   Cmovb,   Jb,   Setb),
    (BE,  Cmovbe,  Jbe,  Setbe),
    (C,   Cmovc,   Jc,   Setc),
    (E,   Cmove,   Je,   Sete),
    (G,   Cmovg,   Jg,   Setg),
    (GE,  Cmovge,  Jge,  Setge),
    (L,   Cmovl,   Jl,   Setl),
    (LE,  Cmovle,  Jle,  Setle),
    (NA,  Cmovna,  Jna,  Setna),
    (NAE, Cmovnae, Jnae, Setnae),
    (NB,  Cmovnb,  Jnb,  Setnb),
    (NBE, Cmovnbe, Jnbe, Setnbe),
    (NC,  Cmovnc,  Jnc,  Setnc),
    (NE,  Cmovne,  Jne,  Setne),
    (NG,  Cmovng,  Jng,  Setng),
    (NGE, Cmovnge, Jnge, Setnge),
    (NL,  Cmovnl,  Jnl,  Setnl),
    (NLE, Cmovnle, Jnle, Setnle),
    (NO,  Cmovno,  Jno,  Setno),
    (NP,  Cmovnp,  Jnp,  Setnp),
    (NS,  Cmovns,  Jns,  Setns),
    (NZ,  Cmovnz,  Jnz,  Setnz),
    (O,   Cmovo,   Jo,   Seto),
    (P,   Cmovp,   Jp,   Setp),
    (PE,  Cmovpe,  Jpe,  Setpe),
    (PO,  Cmovpo,  Jpo,  Setpo),
    (S,   Cmovs,   Js,   Sets),
    (Z,   Cmovz,   Jz,   Setz)
}


pub trait Lea<D, S>: EmitBytes {
    fn emit(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>;
}

impl<W> Lea<Operand, Operand> for W where W: EmitBytes {
    fn emit(&mut self, dst: Operand, src: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match (dst, src) {
            (Reg16(d), WordPointer(s)) => Lea::emit(self, d, s),
            (Reg32(d), DWordPointer(s)) => Lea::emit(self, d, s),
            (Reg64(d), QWordPointer(s)) => Lea::emit(self, d, s),
            _ => Err(Error::InvalidOperands),
        }
    }
}

op! { Lea {
    <P: Mem> dst: Reg16, p: Word<P>  => (RM) Prefix(0x66), Op(0x8d), ModRm;
    <P: Mem> dst: Reg32, p: DWord<P> => (RM)               Op(0x8d), ModRm;
    <P: Mem> dst: Reg64, p: QWord<P> => (RM) RexW,         Op(0x8d), ModRm;
}}


pub trait Movzx<D, S>: EmitBytes {
    fn emit(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>;
}

impl<W> Movzx<Operand, Operand> for W where W: EmitBytes {
    fn emit(&mut self, dst: Operand, src: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match (dst, src) {
            (Reg16(d), Reg8(s)) => Movzx::emit(self, d, s),
            (Reg32(d), Reg8(s)) => Movzx::emit(self, d, s),
            (Reg64(d), Reg8(s)) => Movzx::emit(self, d, s),
            (Reg32(d), Reg16(s)) => Movzx::emit(self, d, s),
            (Reg64(d), Reg16(s)) => Movzx::emit(self, d, s),
            (Reg16(d), BytePointer(s)) => Movzx::emit(self, d, s),
            (Reg32(d), BytePointer(s)) => Movzx::emit(self, d, s),
            (Reg64(d), BytePointer(s)) => Movzx::emit(self, d, s),
            (Reg32(d), WordPointer(s)) => Movzx::emit(self, d, s),
            (Reg64(d), WordPointer(s)) => Movzx::emit(self, d, s),
            _ => Err(Error::InvalidOperands),
        }
    }
}

op! { Movzx {
    dst: Reg16, src: Reg8 => (RM) Prefix(0x66), Op(0x0f), Op(0xb6), ModRm;
    dst: Reg32, src: Reg8 => (RM)               Op(0x0f), Op(0xb6), ModRm;
    dst: Reg64, src: Reg8 => (RM) RexW,         Op(0x0f), Op(0xb6), ModRm;
    dst: Reg32, src: Reg16 => (RM)       Op(0x0f), Op(0xb7), ModRm;
    dst: Reg64, src: Reg16 => (RM) RexW, Op(0x0f), Op(0xb7), ModRm;

    <P: Mem> dst: Reg16, src: Byte<P> => (RM) Prefix(0x66), Op(0x0f), Op(0xb6), ModRm;
    <P: Mem> dst: Reg32, src: Byte<P> => (RM)               Op(0x0f), Op(0xb6), ModRm;
    <P: Mem> dst: Reg64, src: Byte<P> => (RM) RexW,         Op(0x0f), Op(0xb6), ModRm;
    <P: Mem> dst: Reg32, src: Word<P> => (RM)       Op(0x0f), Op(0xb7), ModRm;
    <P: Mem> dst: Reg64, src: Word<P> => (RM) RexW, Op(0x0f), Op(0xb7), ModRm;
}}


pub trait Movsx<D, S>: EmitBytes {
    fn emit(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>;
}

impl<W> Movsx<Operand, Operand> for W where W: EmitBytes {
    fn emit(&mut self, dst: Operand, src: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match (dst, src) {
            (Reg16(d), Reg8(s)) => Movsx::emit(self, d, s),
            (Reg32(d), Reg8(s)) => Movsx::emit(self, d, s),
            (Reg64(d), Reg8(s)) => Movsx::emit(self, d, s),
            (Reg32(d), Reg16(s)) => Movsx::emit(self, d, s),
            (Reg64(d), Reg16(s)) => Movsx::emit(self, d, s),
            (Reg16(d), BytePointer(s)) => Movsx::emit(self, d, s),
            (Reg32(d), BytePointer(s)) => Movsx::emit(self, d, s),
            (Reg64(d), BytePointer(s)) => Movsx::emit(self, d, s),
            (Reg32(d), WordPointer(s)) => Movsx::emit(self, d, s),
            (Reg64(d), WordPointer(s)) => Movsx::emit(self, d, s),
            _ => Err(Error::InvalidOperands),
        }
    }
}

op! { Movsx {
    dst: Reg16, src: Reg8 => (RM) Prefix(0x66), Op(0x0f), Op(0xbe), ModRm;
    dst: Reg32, src: Reg8 => (RM)               Op(0x0f), Op(0xbe), ModRm;
    dst: Reg64, src: Reg8 => (RM) RexW,         Op(0x0f), Op(0xbe), ModRm;
    dst: Reg32, src: Reg16 => (RM)       Op(0x0f), Op(0xbf), ModRm;
    dst: Reg64, src: Reg16 => (RM) RexW, Op(0x0f), Op(0xbf), ModRm;

    <P: Mem> dst: Reg16, src: Byte<P> => (RM) Prefix(0x66), Op(0x0f), Op(0xbe), ModRm;
    <P: Mem> dst: Reg32, src: Byte<P> => (RM)               Op(0x0f), Op(0xbe), ModRm;
    <P: Mem> dst: Reg64, src: Byte<P> => (RM) RexW,         Op(0x0f), Op(0xbe), ModRm;
    <P: Mem> dst: Reg32, src: Word<P> => (RM)       Op(0x0f), Op(0xbf), ModRm;
    <P: Mem> dst: Reg64, src: Word<P> => (RM) RexW, Op(0x0f), Op(0xbf), ModRm;
}}


pub trait Cdq: EmitBytes {
    fn emit(&mut self) -> Result<(), Error<Self::Error>>;
}

op! { Cdq {
    => (None) Op(0x99);
}}


pub trait Xchg<D, S>: EmitBytes {
    fn emit(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>;
}

impl<W> Xchg<Operand, Operand> for W where W: EmitBytes {
    fn emit(&mut self, dst: Operand, src: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match (dst, src) {
            (Reg8(d), Reg8(s)) => Xchg::emit(self, d, s),
            (Reg16(d), Reg16(s)) => Xchg::emit(self, d, s),
            (Reg32(d), Reg32(s)) => Xchg::emit(self, d, s),
            (Reg64(d), Reg64(s)) => Xchg::emit(self, d, s),
            (Reg8(d), BytePointer(s)) => Xchg::emit(self, d, s),
            (Reg16(d), WordPointer(s)) => Xchg::emit(self, d, s),
            (Reg32(d), DWordPointer(s)) => Xchg::emit(self, d, s),
            (Reg64(d), QWordPointer(s)) => Xchg::emit(self, d, s),
            (BytePointer(d), Reg8(s)) => Xchg::emit(self, d, s),
            (WordPointer(d), Reg16(s)) => Xchg::emit(self, d, s),
            (DWordPointer(d), Reg32(s)) => Xchg::emit(self, d, s),
            (QWordPointer(d), Reg64(s)) => Xchg::emit(self, d, s),
            _ => Err(Error::InvalidOperands),
        }
    }
}

op! { Xchg {
    dst: Reg8, src: Reg8 => (MR) Op(0x86), ModRm;
    dst: Reg16, src: Reg16 =>
        if (dst == Reg16::Ax) {
            (XchgSrc) Prefix(0x66), OpPlusReg(0x90)
        } else if (src == Reg16::Ax) {
            (XchgDst) Prefix(0x66), OpPlusReg(0x90)
        } else {
            (MR) Prefix(0x66), Op(0x87), ModRm
        };
    dst: Reg32, src: Reg32 =>
        if (dst == Reg32::Eax) {
            (XchgSrc) OpPlusReg(0x90)
        } else if (src == Reg32::Eax) {
            (XchgDst) OpPlusReg(0x90)
        } else {
            (MR) Op(0x87), ModRm
        };
    dst: Reg64, src: Reg64 =>
        if (dst == Reg64::Rax) {
            (XchgSrc) RexW, OpPlusReg(0x90)
        } else if (src == Reg64::Rax) {
            (XchgDst) RexW, OpPlusReg(0x90)
        } else {
            (MR) RexW, Op(0x87), ModRm
        };

    <P: Mem> r: Reg8,  p: Byte<P>  => (RM)               Op(0x86), ModRm;
    <P: Mem> r: Reg16, p: Word<P>  => (RM) Prefix(0x66), Op(0x87), ModRm;
    <P: Mem> r: Reg32, p: DWord<P> => (RM)               Op(0x87), ModRm;
    <P: Mem> r: Reg64, p: QWord<P> => (RM) RexW,         Op(0x87), ModRm;

    <P: Mem> p: Byte<P>,  r: Reg8  => (MR)               Op(0x86), ModRm;
    <P: Mem> p: Word<P>, r: Reg16  => (MR) Prefix(0x66), Op(0x87), ModRm;
    <P: Mem> p: DWord<P>, r: Reg32 => (MR)               Op(0x87), ModRm;
    <P: Mem> p: QWord<P>, r: Reg64 => (MR) RexW,         Op(0x87), ModRm;
}}


pub trait Ud2: EmitBytes {
    fn emit(&mut self) -> Result<(), Error<Self::Error>>;
}

op! { Ud2 {
    => (None) Op(0x0f), Op(0x0b);
}}
