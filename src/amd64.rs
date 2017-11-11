use EmitBytes;
use common::*;
use reg::{Reg8, Reg16, Reg32, Reg64};
use ptr::Scaled;
use ptr::{Ptr, BytePtr, WordPtr, DWordPtr, QWordPtr};
use ptr::{BytePointer, WordPointer, DWordPointer, QWordPointer};
use operand::Operand;
use error::Error;
use fixup::{HoleKind, Hole};

// used in several instructions to force REX.W
use reg::Rax;


fn size<R>(r: R) -> Option<u8>
    where R: Register
{
    if r.size() == 2 {
        Some(0x66u8)
    } else {
        None
    }
}


trait Op1<T>: EmitBytes {
    fn write(&mut self, opcode: &[u8], op_index: u8, arg: T) -> Result<(), Error<Self::Error>>;
}

op! { Op1 {
    <R: Register>
    reg: R; op: &[u8], op_index: u8 =>
        size(reg), try!(rex_b(reg)), op, modrm(3, op_index, reg.rm());
}}


trait Op2<D, S>: EmitBytes {
    fn write(&mut self, opcode: &[u8], reg: D, rm: S) -> Result<(), Error<Self::Error>>;
}

op! { Op2 {
    <R1: Register, R2: Register>
    dst: R1, src: R2; opcode: &[u8] =>
        size(dst), try!(rex_rb(dst, src)), opcode, modrm(3, dst.rm(), src.rm());
}}


macro_rules! forward1 {
    ($Trait:ident { $($T:ty $(, $a:ident : $A:ty)* => $opcode:expr, $op_index:expr;)* }) => {
        $(
            impl<W> $Trait<$T> for W where W: EmitBytes {
                fn write(&mut self, $($a: $A ,)* arg: $T) -> Result<(), Error<Self::Error>> {
                    Op1::write(self, $opcode, $op_index, arg)
                }
            }
        )*
    };
}

macro_rules! forward2 {
    ($Trait:ident { $($D:ty, $S:ty $(, $a:ident : $A:ty)* => $opcode:expr;)* }) => {
        $(
            impl<W> $Trait<$D, $S> for W where W: EmitBytes {
                fn write(&mut self, $($a: $A ,)* dst: $D, src: $S) -> Result<(), Error<Self::Error>> {
                    Op2::write(self, $opcode, dst, src)
                }
            }
        )*
    };
}


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
            fn write(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>;
        }

        impl<W> $Op<Operand, Operand> for W where W: EmitBytes {
            fn write(&mut self, dst: Operand, src: Operand) -> Result<(), Error<Self::Error>> {
                use operand::Operand::*;
                match (dst, src) {
                    (Reg8(d), Imm8(s)) => $Op::write(self, d, s),
                    (Reg16(d), Imm8(s)) => $Op::write(self, d, s),
                    (Reg32(d), Imm8(s)) => $Op::write(self, d, s),
                    (Reg64(d), Imm8(s)) => $Op::write(self, d, s),
                    (Reg16(d), Imm16(s)) => $Op::write(self, d, s),
                    (Reg32(d), Imm32(s)) => $Op::write(self, d, s),
                    (Reg64(d), Imm32(s)) => $Op::write(self, d, s),
                    (Reg8(d), Reg8(s)) => $Op::write(self, d, s),
                    (Reg16(d), Reg16(s)) => $Op::write(self, d, s),
                    (Reg32(d), Reg32(s)) => $Op::write(self, d, s),
                    (Reg64(d), Reg64(s)) => $Op::write(self, d, s),
                    (Reg8(d), BytePointer(s)) => $Op::write(self, d, s),
                    (Reg16(d), WordPointer(s)) => $Op::write(self, d, s),
                    (Reg32(d), DWordPointer(s)) => $Op::write(self, d, s),
                    (Reg64(d), QWordPointer(s)) => $Op::write(self, d, s),
                    (BytePointer(d), Imm8(s)) => $Op::write(self, d, s),
                    (WordPointer(d), Imm16(s)) => $Op::write(self, d, s),
                    (DWordPointer(d), Imm32(s)) => $Op::write(self, d, s),
                    (QWordPointer(d), Imm32(s)) => $Op::write(self, d, s),
                    (BytePointer(d), Reg8(s)) => $Op::write(self, d, s),
                    (WordPointer(d), Reg16(s)) => $Op::write(self, d, s),
                    (DWordPointer(d), Reg32(s)) => $Op::write(self, d, s),
                    (QWordPointer(d), Reg64(s)) => $Op::write(self, d, s),
                    _ => Err(Error::InvalidOperands),
                }
            }
        }

        forward2! { $Op {
            Reg8, Reg8 => &[$op.mem8];
            Reg16, Reg16 => &[$op.mem32];
            Reg32, Reg32 => &[$op.mem32];
            Reg64, Reg64 => &[$op.mem32];
        }}

        op! { $Op {
            dst: Reg16, src: u8 =>
                0x66u8, try!(rex_b(dst)), $op.sext_imm8, modrm(3, $op.index, dst.rm()), src;
            dst: Reg32, src: u8 =>
                try!(rex_b(dst)), $op.sext_imm8, modrm(3, $op.index, dst.rm()), src;
            dst: Reg64, src: u8 =>
                try!(rex_b(dst)), $op.sext_imm8, modrm(3, $op.index, dst.rm()), src;

            dst: Reg8, src: u8 =>
                closure(|buffer| {
                    if dst == Reg8::Al {
                        buffer.write_u8($op.al);
                    } else {
                        try!(write_rex_b(buffer, dst));
                        buffer.write_u8($op.imm8);
                        buffer.write_u8(modrm(3, $op.index, dst.rm()));
                    }
                    Ok(())
                }),
                src;
            dst: Reg16, src: u16 =>
                0x66u8,
                closure(|buffer| {
                    if dst == Reg16::Ax {
                        buffer.write_u8($op.eax);
                    } else {
                        try!(write_rex_b(buffer, dst));
                        buffer.write_u8($op.imm32);
                        buffer.write_u8(modrm(3, $op.index, dst.rm()));
                    }
                    Ok(())
                }),
                src;
            dst: Reg32, src: u32 =>
                closure(|buffer| {
                    if dst == Reg32::Eax {
                        buffer.write_u8($op.eax);
                    } else {
                        try!(write_rex_b(buffer, dst));
                        buffer.write_u8($op.imm32);
                        buffer.write_u8(modrm(3, $op.index, dst.rm()));
                    }
                    Ok(())
                }),
                src;
            dst: Reg64, src: u32 =>
                try!(rex_b(dst)),
                closure(|buffer| {
                    if dst == Rax {
                        buffer.write_u8($op.eax);
                    } else {
                        buffer.write_u8($op.imm32);
                        buffer.write_u8(modrm(3, $op.index, dst.rm()));
                    }
                    Ok(())
                }),
                src;
        }}

        dispatch_ptr! { $Op {
            Reg8, @BytePointer => BytePtr;
            Reg16, @WordPointer => WordPtr;
            Reg32, @DWordPointer => DWordPtr;
            Reg64, @QWordPointer => QWordPtr;
            @BytePointer, u8 => BytePtr;
            @WordPointer, u16 => WordPtr;
            @DWordPointer, u32 => DWordPtr;
            @QWordPointer, u32 => QWordPtr;
            @BytePointer, Reg8 => BytePtr;
            @WordPointer, Reg16 => WordPtr;
            @DWordPointer, Reg32 => DWordPtr;
            @QWordPointer, Reg64 => QWordPtr;
        }}

        op_ptr! { $Op {
            r: Reg8, p: BytePtr<..> =>
                try!(Rex::rex(p.ptr, r)),
                $op.mem8,
                closure(|b| Args::write(b, p.ptr, r.rm()));
            r: Reg16, p: WordPtr<..> =>
                0x66u8,
                try!(Rex::rex(p.ptr, r)),
                $op.mem32,
                closure(|b| Args::write(b, p.ptr, r.rm()));
            r: Reg32, p: DWordPtr<..> =>
                try!(Rex::rex(p.ptr, r)),
                $op.mem32,
                closure(|b| Args::write(b, p.ptr, r.rm()));
            r: Reg64, p: QWordPtr<..> =>
                try!(Rex::rex(p.ptr, r)),
                $op.mem32,
                closure(|b| Args::write(b, p.ptr, r.rm()));

            p: BytePtr<..>, imm: u8 =>
                try!(Rex::rex(p.ptr, ())),
                $op.imm8,
                closure(|b| Args::write(b, p.ptr, $op.index)),
                imm;
            p: WordPtr<..>, imm: u16 =>
                0x66u8,
                try!(Rex::rex(p.ptr, ())),
                $op.imm32,
                closure(|b| Args::write(b, p.ptr, $op.index)),
                imm;
            p: DWordPtr<..>, imm: u32 =>
                try!(Rex::rex(p.ptr, ())),
                $op.imm32,
                closure(|b| Args::write(b, p.ptr, $op.index)),
                imm;
            p: QWordPtr<..>, imm: u32 =>
                try!(Rex::rex(p.ptr, Rax)),
                $op.imm32,
                closure(|b| Args::write(b, p.ptr, $op.index)),
                imm;

            p: BytePtr<..>, r: Reg8 =>
                try!(Rex::rex(p.ptr, r)),
                $op.reg8,
                closure(|b| Args::write(b, p.ptr, r.rm()));
            p: WordPtr<..>, r: Reg16 =>
                0x66u8,
                try!(Rex::rex(p.ptr, r)),
                $op.reg32,
                closure(|b| Args::write(b, p.ptr, r.rm()));
            p: DWordPtr<..>, r: Reg32 =>
                try!(Rex::rex(p.ptr, r)),
                $op.reg32,
                closure(|b| Args::write(b, p.ptr, r.rm()));
            p: QWordPtr<..>, r: Reg64 =>
                try!(Rex::rex(p.ptr, r)),
                $op.reg32,
                closure(|b| Args::write(b, p.ptr, r.rm()));
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
            fn write(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>;
        }

        impl<W> $Op<Operand, Operand> for W where W: EmitBytes {
            fn write(&mut self, dst: Operand, src: Operand) -> Result<(), Error<Self::Error>> {
                use operand::Operand::*;
                match (dst, src) {
                    (Reg8(d), Imm8(s)) => $Op::write(self, d, s),
                    (Reg16(d), Imm8(s)) => $Op::write(self, d, s),
                    (Reg32(d), Imm8(s)) => $Op::write(self, d, s),
                    (Reg64(d), Imm8(s)) => $Op::write(self, d, s),
                    (Reg8(d), Reg8(s)) => $Op::write(self, d, s),
                    (Reg16(d), Reg8(s)) => $Op::write(self, d, s),
                    (Reg32(d), Reg8(s)) => $Op::write(self, d, s),
                    (Reg64(d), Reg8(s)) => $Op::write(self, d, s),
                    _ => Err(Error::InvalidOperands),
                }
            }
        }

        op! { $Op {
            r: Reg8, shift: u8 =>  try!(rex_b(r)), 0xc0u8, modrm(3, $op.index, r.rm()), shift;
            r: Reg16, shift: u8 =>
                0x66u8, try!(rex_b(r)), 0xc1u8, modrm(3, $op.index, r.rm()), shift;
            r: Reg32, shift: u8 => try!(rex_b(r)), 0xc1u8, modrm(3, $op.index, r.rm()), shift;
            r: Reg64, shift: u8 => try!(rex_b(r)), 0xc1u8, modrm(3, $op.index, r.rm()), shift;

            r: Reg8, shift: Reg8 =>
                assert_eq!(shift, Reg8::Cl),
                try!(rex_b(r)), 0xd2u8, modrm(3, $op.index, r.rm());
            r: Reg16, shift: Reg8 =>
                assert_eq!(shift, Reg8::Cl),
                0x66u8, try!(rex_b(r)), 0xd3u8, modrm(3, $op.index, r.rm());
            r: Reg32, shift: Reg8 =>
                assert_eq!(shift, Reg8::Cl),
                try!(rex_b(r)), 0xd3u8, modrm(3, $op.index, r.rm());
            r: Reg64, shift: Reg8 =>
                assert_eq!(shift, Reg8::Cl),
                try!(rex_b(r)), 0xd3u8, modrm(3, $op.index, r.rm());
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
                fn write(&mut self, arg: T) -> Result<(), Error<Self::Error>>;
            }

            impl<W> $Op<Operand> for W where W: EmitBytes {
                fn write(&mut self, arg: Operand) -> Result<(), Error<Self::Error>> {
                    use operand::Operand::*;
                    match arg {
                        Reg8(a) => $Op::write(self, a),
                        Reg16(a) => $Op::write(self, a),
                        Reg32(a) => $Op::write(self, a),
                        Reg64(a) => $Op::write(self, a),
                        BytePointer(a) => $Op::write(self, a),
                        WordPointer(a) => $Op::write(self, a),
                        DWordPointer(a) => $Op::write(self, a),
                        QWordPointer(a) => $Op::write(self, a),
                        _ => Err(Error::InvalidOperands),
                    }
                }
            }

            forward1! { $Op {
                Reg8 => &[0xf6], $index;
                Reg16 => &[0xf7], $index;
                Reg32 => &[0xf7], $index;
                Reg64 => &[0xf7], $index;
            }}

            dispatch_ptr! { $Op {
                @BytePointer => BytePtr;
                @WordPointer => WordPtr;
                @DWordPointer => DWordPtr;
                @QWordPointer => QWordPtr;
            }}

            op_ptr! { $Op {
                p: BytePtr<..> =>
                    try!(Rex::rex(p.ptr, ())),
                    0xf6u8,
                    closure(|b| Args::write(b, p.ptr, $index));
                p: WordPtr<..> =>
                    0x66u8, try!(Rex::rex(p.ptr, ())),
                    0xf7u8,
                    closure(|b| Args::write(b, p.ptr, $index));
                p: DWordPtr<..> =>
                    try!(Rex::rex(p.ptr, ())),
                    0xf7u8,
                    closure(|b| Args::write(b, p.ptr, $index));
                p: QWordPtr<..> =>
                    try!(Rex::rex(p.ptr, Rax)),
                    0xf7u8,
                    closure(|b| Args::write(b, p.ptr, $index));
            }}
        )*
    };
}

unary_arith_op! {
    (Not, 2), (Neg, 3), (Mul, 4), (Imul, 5), (Div, 6), (Idiv, 7)
}


pub trait Inc<T>: EmitBytes {
    fn write(&mut self, arg: T) -> Result<(), Error<Self::Error>>;
}

impl<W> Inc<Operand> for W where W: EmitBytes {
    fn write(&mut self, arg: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match arg {
            Reg8(a) => Inc::write(self, a),
            Reg16(a) => Inc::write(self, a),
            Reg32(a) => Inc::write(self, a),
            Reg64(a) => Inc::write(self, a),
            BytePointer(a) => Inc::write(self, a),
            WordPointer(a) => Inc::write(self, a),
            DWordPointer(a) => Inc::write(self, a),
            QWordPointer(a) => Inc::write(self, a),
            _ => Err(Error::InvalidOperands),
        }
    }
}

forward1! { Inc {
    Reg8 => &[0xfe], 0;
    Reg16 => &[0xff], 0;
    Reg32 => &[0xff], 0;
    Reg64 => &[0xff], 0;
}}

dispatch_ptr! { Inc {
    @BytePointer => BytePtr;
    @WordPointer => WordPtr;
    @DWordPointer => DWordPtr;
    @QWordPointer => QWordPtr;
}}

op_ptr! { Inc {
    p: BytePtr<..> =>         try!(Rex::rex(p.ptr, ())),  0xfeu8, closure(|b| Args::write(b, p.ptr, 0));
    p: WordPtr<..> => 0x66u8, try!(Rex::rex(p.ptr, ())),  0xffu8, closure(|b| Args::write(b, p.ptr, 0));
    p: DWordPtr<..> =>        try!(Rex::rex(p.ptr, ())),  0xffu8, closure(|b| Args::write(b, p.ptr, 0));
    p: QWordPtr<..> =>        try!(Rex::rex(p.ptr, Rax)), 0xffu8, closure(|b| Args::write(b, p.ptr, 0));
}}


pub trait Dec<T>: EmitBytes {
    fn write(&mut self, arg: T) -> Result<(), Error<Self::Error>>;
}

impl<W> Dec<Operand> for W where W: EmitBytes {
    fn write(&mut self, arg: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match arg {
            Reg8(a) => Dec::write(self, a),
            Reg16(a) => Dec::write(self, a),
            Reg32(a) => Dec::write(self, a),
            Reg64(a) => Dec::write(self, a),
            BytePointer(a) => Dec::write(self, a),
            WordPointer(a) => Dec::write(self, a),
            DWordPointer(a) => Dec::write(self, a),
            QWordPointer(a) => Dec::write(self, a),
            _ => Err(Error::InvalidOperands),
        }
    }
}

forward1! { Dec {
    Reg8 => &[0xfe], 1;
    Reg16 => &[0xff], 1;
    Reg32 => &[0xff], 1;
    Reg64 => &[0xff], 1;
}}

dispatch_ptr! { Dec {
    @BytePointer => BytePtr;
    @WordPointer => WordPtr;
    @DWordPointer => DWordPtr;
    @QWordPointer => QWordPtr;
}}

op_ptr! { Dec {
    p: BytePtr<..> =>         try!(Rex::rex(p.ptr, ())),  0xfeu8, closure(|b| Args::write(b, p.ptr, 1));
    p: WordPtr<..> => 0x66u8, try!(Rex::rex(p.ptr, ())),  0xffu8, closure(|b| Args::write(b, p.ptr, 1));
    p: DWordPtr<..> =>        try!(Rex::rex(p.ptr, ())),  0xffu8, closure(|b| Args::write(b, p.ptr, 1));
    p: QWordPtr<..> =>        try!(Rex::rex(p.ptr, Rax)), 0xffu8, closure(|b| Args::write(b, p.ptr, 1));
}}


pub trait Test<D, S>: EmitBytes {
    fn write(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>;
}

impl<W> Test<Operand, Operand> for W where W: EmitBytes {
    fn write(&mut self, dst: Operand, src: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match (dst, src) {
            (Reg8(d), Imm8(s)) => Test::write(self, d, s),
            (Reg16(d), Imm16(s)) => Test::write(self, d, s),
            (Reg32(d), Imm32(s)) => Test::write(self, d, s),
            (Reg64(d), Imm32(s)) => Test::write(self, d, s),
            (Reg8(d), Reg8(s)) => Test::write(self, d, s),
            (Reg16(d), Reg16(s)) => Test::write(self, d, s),
            (Reg32(d), Reg32(s)) => Test::write(self, d, s),
            (Reg64(d), Reg64(s)) => Test::write(self, d, s),
            (Reg8(d), BytePointer(s)) => Test::write(self, d, s),
            (Reg16(d), WordPointer(s)) => Test::write(self, d, s),
            (Reg32(d), DWordPointer(s)) => Test::write(self, d, s),
            (Reg64(d), QWordPointer(s)) => Test::write(self, d, s),
            (BytePointer(d), Imm8(s)) => Test::write(self, d, s),
            (WordPointer(d), Imm16(s)) => Test::write(self, d, s),
            (DWordPointer(d), Imm32(s)) => Test::write(self, d, s),
            (QWordPointer(d), Imm32(s)) => Test::write(self, d, s),
            (BytePointer(d), Reg8(s)) => Test::write(self, d, s),
            (WordPointer(d), Reg16(s)) => Test::write(self, d, s),
            (DWordPointer(d), Reg32(s)) => Test::write(self, d, s),
            (QWordPointer(d), Reg64(s)) => Test::write(self, d, s),
            _ => Err(Error::InvalidOperands),
        }
    }
}

forward2! { Test {
    Reg8, Reg8 => &[0x84];
    Reg16, Reg16 => &[0x85];
    Reg32, Reg32 => &[0x85];
    Reg64, Reg64 => &[0x85];
}}

forward! { Test {
    r: Reg8, p: BytePointer => (Test::write)(p, r);
    r: Reg16, p: WordPointer => (Test::write)(p, r);
    r: Reg32, p: DWordPointer => (Test::write)(p, r);
    r: Reg64, p: QWordPointer => (Test::write)(p, r);
}}

forward_ptr! { Test {
    r: Reg8, p: BytePtr<..> => (Test::write)(p, r);
    r: Reg16, p: WordPtr<..> => (Test::write)(p, r);
    r: Reg32, p: DWordPtr<..> => (Test::write)(p, r);
    r: Reg64, p: QWordPtr<..> => (Test::write)(p, r);
}}

op! { Test {
    r: Reg8, imm: u8 =>
        closure(|buffer| {
            if r == Reg8::Al {
                buffer.write_u8(0xa8);
            } else {
                try!(write_rex_b(buffer, r));
                buffer.write_u8(0xf6);
                buffer.write_u8(modrm(3, 0, r.rm()));
            }
            Ok(())
        }),
        imm;
    r: Reg16, imm: u16 =>
        0x66u8,
        closure(|buffer| {
            if r == Reg16::Ax {
                buffer.write_u8(0xa9);
            } else {
                try!(write_rex_b(buffer, r));
                buffer.write_u8(0xf7);
                buffer.write_u8(modrm(3, 0, r.rm()));
            }
            Ok(())
        }),
        imm;
    r: Reg32, imm: u32 =>
        closure(|buffer| {
            if r == Reg32::Eax {
                buffer.write_u8(0xa9);
            } else {
                try!(write_rex_b(buffer, r));
                buffer.write_u8(0xf7);
                buffer.write_u8(modrm(3, 0, r.rm()));
            }
            Ok(())
        }),
        imm;
    r: Reg64, imm: u32 =>
        try!(rex_b(r)),
        closure(|buffer| {
            if r == Rax {
                buffer.write_u8(0xa9);
            } else {
                buffer.write_u8(0xf7);
                buffer.write_u8(modrm(3, 0, r.rm()));
            }
            Ok(())
        }),
        imm;
}}

dispatch_ptr! { Test {
    @BytePointer, u8 => BytePtr;
    @WordPointer, u16 => WordPtr;
    @DWordPointer, u32 => DWordPtr;
    @QWordPointer, u32 => QWordPtr;
    @BytePointer, Reg8 => BytePtr;
    @WordPointer, Reg16 => WordPtr;
    @DWordPointer, Reg32 => DWordPtr;
    @QWordPointer, Reg64 => QWordPtr;
}}

op_ptr! { Test {
    p: BytePtr<..>, imm: u8 =>
        try!(Rex::rex(p.ptr, ())),
        0xf6u8,
        closure(|b| Args::write(b, p.ptr, 0)),
        imm;
    p: WordPtr<..>, imm: u16 =>
        0x66u8,
        try!(Rex::rex(p.ptr, ())),
        0xf7u8,
        closure(|b| Args::write(b, p.ptr, 0)),
        imm;
    p: DWordPtr<..>, imm: u32 =>
        try!(Rex::rex(p.ptr, ())),
        0xf7u8,
        closure(|b| Args::write(b, p.ptr, 0)),
        imm;
    p: QWordPtr<..>, imm: u32 =>
        try!(Rex::rex(p.ptr, Rax)),
        0xf7u8,
        closure(|b| Args::write(b, p.ptr, 0)),
        imm;

    p: BytePtr<..>, r: Reg8 =>
        try!(Rex::rex(p.ptr, r)),
        0x84u8,
        closure(|b| Args::write(b, p.ptr, r.rm()));
    p: WordPtr<..>, r: Reg16 =>
        0x66u8,
        try!(Rex::rex(p.ptr, r)),
        0x85u8,
        closure(|b| Args::write(b, p.ptr, r.rm()));
    p: DWordPtr<..>, r: Reg32 =>
        try!(Rex::rex(p.ptr, r)),
        0x85u8,
        closure(|b| Args::write(b, p.ptr, r.rm()));
    p: QWordPtr<..>, r: Reg64 =>
        try!(Rex::rex(p.ptr, r)),
        0x85u8,
        closure(|b| Args::write(b, p.ptr, r.rm()));
}}


pub trait Mov<D, S>: EmitBytes {
    fn write(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>;
}

impl<W> Mov<Operand, Operand> for W where W: EmitBytes {
    fn write(&mut self, dst: Operand, src: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match (dst, src) {
            (Reg8(d), Imm8(s)) => Mov::write(self, d, s),
            (Reg16(d), Imm16(s)) => Mov::write(self, d, s),
            (Reg32(d), Imm32(s)) => Mov::write(self, d, s),
            (Reg64(d), Imm64(s)) => Mov::write(self, d, s),
            (Reg64(d), Imm32(s)) => Mov::write(self, d, s),
            (Reg8(d), Reg8(s)) => Mov::write(self, d, s),
            (Reg16(d), Reg16(s)) => Mov::write(self, d, s),
            (Reg32(d), Reg32(s)) => Mov::write(self, d, s),
            (Reg64(d), Reg64(s)) => Mov::write(self, d, s),
            (Reg8(d), BytePointer(s)) => Mov::write(self, d, s),
            (Reg16(d), WordPointer(s)) => Mov::write(self, d, s),
            (Reg32(d), DWordPointer(s)) => Mov::write(self, d, s),
            (Reg64(d), QWordPointer(s)) => Mov::write(self, d, s),
            (BytePointer(d), Imm8(s)) => Mov::write(self, d, s),
            (WordPointer(d), Imm16(s)) => Mov::write(self, d, s),
            (DWordPointer(d), Imm32(s)) => Mov::write(self, d, s),
            (QWordPointer(d), Imm32(s)) => Mov::write(self, d, s),
            (BytePointer(d), Reg8(s)) => Mov::write(self, d, s),
            (WordPointer(d), Reg16(s)) => Mov::write(self, d, s),
            (DWordPointer(d), Reg32(s)) => Mov::write(self, d, s),
            (QWordPointer(d), Reg64(s)) => Mov::write(self, d, s),
            _ => Err(Error::InvalidOperands),
        }
    }
}

op! { Mov {
    dst: Reg8,  src: u8  =>         try!(rex_b(dst)), 0xb0 | dst.rm(), src;
    dst: Reg16, src: u16 => 0x66u8, try!(rex_b(dst)), 0xb8 | dst.rm(), src;
    dst: Reg32, src: u32 =>         try!(rex_b(dst)), 0xb8 | dst.rm(), src;
    dst: Reg64, src: u64 =>         try!(rex_b(dst)), 0xb8 | dst.rm(), src;
    dst: Reg64, src: u32 => try!(rex_b(dst)), 0xc7u8, modrm(3, 0, dst.rm()), src;

    dst: Reg8, src: Reg8 =>           try!(rex_rb(dst, src)), 0x8au8, modrm(3, dst.rm(), src.rm());
    dst: Reg16, src: Reg16 => 0x66u8, try!(rex_rb(dst, src)), 0x8bu8, modrm(3, dst.rm(), src.rm());
    dst: Reg32, src: Reg32 =>         try!(rex_rb(dst, src)), 0x8bu8, modrm(3, dst.rm(), src.rm());
    dst: Reg64, src: Reg64 =>         try!(rex_rb(dst, src)), 0x8bu8, modrm(3, dst.rm(), src.rm());
}}

dispatch_ptr! { Mov {
    Reg8, @BytePointer => BytePtr;
    Reg16, @WordPointer => WordPtr;
    Reg32, @DWordPointer => DWordPtr;
    Reg64, @QWordPointer => QWordPtr;
    @BytePointer, u8 => BytePtr;
    @WordPointer, u16 => WordPtr;
    @DWordPointer, u32 => DWordPtr;
    @QWordPointer, u32 => QWordPtr;
    @BytePointer, Reg8 => BytePtr;
    @WordPointer, Reg16 => WordPtr;
    @DWordPointer, Reg32 => DWordPtr;
    @QWordPointer, Reg64 => QWordPtr;
}}

op_ptr! { Mov {
    r: Reg8, p: BytePtr<..> =>
        try!(Rex::rex(p.ptr, r)),
        0x8au8,
        closure(|b| Args::write(b, p.ptr, r.rm()));
    r: Reg16, p: WordPtr<..> =>
        0x66u8,
        try!(Rex::rex(p.ptr, r)),
        0x8bu8,
        closure(|b| Args::write(b, p.ptr, r.rm()));
    r: Reg32, p: DWordPtr<..> =>
        try!(Rex::rex(p.ptr, r)),
        0x8bu8,
        closure(|b| Args::write(b, p.ptr, r.rm()));
    r: Reg64, p: QWordPtr<..> =>
        try!(Rex::rex(p.ptr, r)),
        0x8bu8,
        closure(|b| Args::write(b, p.ptr, r.rm()));

    p: BytePtr<..>, imm: u8 =>
        try!(Rex::rex(p.ptr, ())), 0xc6u8,
        closure(|b| Args::write(b, p.ptr, 0)),
        imm;
    p: WordPtr<..>, imm: u16 =>
        0x66u8,
        try!(Rex::rex(p.ptr, ())), 0xc7u8,
        closure(|b| Args::write(b, p.ptr, 0)),
        imm;
    p: DWordPtr<..>, imm: u32 =>
        try!(Rex::rex(p.ptr, ())), 0xc7u8,
        closure(|b| Args::write(b, p.ptr, 0)),
        imm;
    p: QWordPtr<..>, imm: u32 =>
        try!(Rex::rex(p.ptr, Rax)), 0xc7u8,
        closure(|b| Args::write(b, p.ptr, 0)),
        imm;

    p: BytePtr<..>, r: Reg8 =>
        try!(Rex::rex(p.ptr, r)),
        0x88u8,
        closure(|b| Args::write(b, p.ptr, r.rm()));
    p: WordPtr<..>, r: Reg16 =>
        0x66u8,
        try!(Rex::rex(p.ptr, r)),
        0x89u8,
        closure(|b| Args::write(b, p.ptr, r.rm()));
    p: DWordPtr<..>, r: Reg32 =>
        try!(Rex::rex(p.ptr, r)),
        0x89u8,
        closure(|b| Args::write(b, p.ptr, r.rm()));
    p: QWordPtr<..>, r: Reg64 =>
        try!(Rex::rex(p.ptr, r)),
        0x89u8,
        closure(|b| Args::write(b, p.ptr, r.rm()));
}}


pub trait Push<S>: EmitBytes {
    fn write(&mut self, src: S) -> Result<(), Error<Self::Error>>;
}

impl<W> Push<Operand> for W where W: EmitBytes {
    fn write(&mut self, arg: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match arg {
            Imm8(a) => Push::write(self, a),
            Imm16(a) => Push::write(self, a),
            Imm32(a) => Push::write(self, a),
            Reg16(a) => Push::write(self, a),
            Reg64(a) => Push::write(self, a),
            WordPointer(a) => Push::write(self, a),
            QWordPointer(a) => Push::write(self, a),
            _ => Err(Error::InvalidOperands),
        }
    }
}

op! { Push {
    imm: u8 =>          0x6au8, imm;
    imm: u16 => 0x66u8, 0x68u8, imm;
    imm: u32 =>         0x68u8, imm;
    reg: Reg16 => 0x66u8, try!(rex_b(reg)), 0x50 | reg.rm();
    reg: Reg64 => try!(rex_b(reg.to_reg32())), 0x50 | reg.rm();
}}

dispatch_ptr! { Push {
    @WordPointer => WordPtr;
    @QWordPointer => QWordPtr;
}}

op_ptr! { Push {
    p: WordPtr<..> => 0x66u8, try!(Rex::rex(p.ptr, ())), 0xffu8, closure(|b| Args::write(b, p.ptr, 6));
    p: QWordPtr<..> =>        try!(Rex::rex(p.ptr, ())), 0xffu8, closure(|b| Args::write(b, p.ptr, 6));
}}


pub trait Pop<D>: EmitBytes {
    fn write(&mut self, dst: D) -> Result<(), Error<Self::Error>>;
}

impl<W> Pop<Operand> for W where W: EmitBytes {
    fn write(&mut self, arg: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match arg {
            Reg16(a) => Pop::write(self, a),
            Reg64(a) => Pop::write(self, a),
            WordPointer(a) => Pop::write(self, a),
            QWordPointer(a) => Pop::write(self, a),
            _ => Err(Error::InvalidOperands),
        }
    }
}

op! { Pop {
    reg: Reg16 => 0x66u8, try!(rex_b(reg)), 0x58 | reg.rm();
    reg: Reg64 => try!(rex_b(reg.to_reg32())), 0x58 | reg.rm();
}}

dispatch_ptr! { Pop {
    @WordPointer => WordPtr;
    @QWordPointer => QWordPtr;
}}

op_ptr! { Pop {
    p: WordPtr<..> => 0x66u8, try!(Rex::rex(p.ptr, ())), 0x8fu8, closure(|b| Args::write(b, p.ptr, 0));
    p: QWordPtr<..> =>        try!(Rex::rex(p.ptr, ())), 0x8fu8, closure(|b| Args::write(b, p.ptr, 0));
}}


pub trait Call<T>: EmitBytes {
    fn write(&mut self, arg: T) -> Result<(), Error<Self::Error>>;
}

impl<W> Call<Operand> for W where W: EmitBytes {
    fn write(&mut self, arg: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match arg {
            Reg64(a) => Call::write(self, a),
            _ => Err(Error::InvalidOperands),
        }
    }
}

op! { Call {
    r: Reg64 => try!(rex_b(r.to_reg32())), 0xffu8, modrm(3, 2, r.rm());
}}


pub trait Jmp<T>: EmitBytes {
    type Return;
    fn write(&mut self, arg: T) -> Result<Self::Return, Error<Self::Error>>;
}

impl<W> Jmp<Operand> for W where W: EmitBytes {
    type Return = ();
    fn write(&mut self, arg: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match arg {
            Offset8(a) => Jmp::write(self, a),
            Offset32(a) => Jmp::write(self, a),
            _ => Err(Error::InvalidOperands),
        }
    }
}

impl<W> Jmp<HoleKind> for W where W: EmitBytes {
    type Return = Hole;
    fn write(&mut self, arg: HoleKind) -> Result<Hole, Error<Self::Error>> {
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
    imm: i8 => 0xebu8, imm;
    imm: i32 => 0xe9u8, imm;
}}


pub trait Ret: EmitBytes {
    fn write(&mut self) -> Result<(), Error<Self::Error>>;
}

impl<W> Ret for W where W: EmitBytes {
    fn write(&mut self) -> Result<(), Error<Self::Error>> {
        try!(self.write(&[0xc3]));
        Ok(())
    }
}


macro_rules! cc_op {
    ($( ($cond:ident, $Cmov:ident, $J:ident, $Set:ident) ),*) => {
        $(
        pub trait $Cmov<D, S>: EmitBytes {
            fn write(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>;
        }

        impl<W> $Cmov<Operand, Operand> for W where W: EmitBytes {
            fn write(&mut self, dst: Operand, src: Operand) -> Result<(), Error<Self::Error>> {
                use operand::Operand::*;
                match (dst, src) {
                    (Reg16(d), Reg16(s)) => $Cmov::write(self, d, s),
                    (Reg32(d), Reg32(s)) => $Cmov::write(self, d, s),
                    (Reg64(d), Reg64(s)) => $Cmov::write(self, d, s),
                    (Reg16(d), WordPointer(s)) => $Cmov::write(self, d, s),
                    (Reg32(d), DWordPointer(s)) => $Cmov::write(self, d, s),
                    (Reg64(d), QWordPointer(s)) => $Cmov::write(self, d, s),
                    _ => Err(Error::InvalidOperands),
                }
            }
        }

        forward2! { $Cmov {
            Reg16, Reg16 => &[0x0f, 0x40 | cond::$cond.0];
            Reg32, Reg32 => &[0x0f, 0x40 | cond::$cond.0];
            Reg64, Reg64 => &[0x0f, 0x40 | cond::$cond.0];
        }}

        dispatch_ptr! { $Cmov {
            Reg16, @WordPointer => WordPtr;
            Reg32, @DWordPointer => DWordPtr;
            Reg64, @QWordPointer => QWordPtr;
        }}

        op_ptr! { $Cmov {
            r: Reg16, p: WordPtr<..> =>
                0x66u8,
                try!(Rex::rex(p.ptr, r)),
                0x0fu8, 0x40 | cond::$cond.0,
                closure(|b| Args::write(b, p.ptr, r.rm()));
            r: Reg32, p: DWordPtr<..> =>
                try!(Rex::rex(p.ptr, r)),
                0x0fu8, 0x40 | cond::$cond.0,
                closure(|b| Args::write(b, p.ptr, r.rm()));
            r: Reg64, p: QWordPtr<..> =>
                try!(Rex::rex(p.ptr, r)),
                0x0fu8, 0x40 | cond::$cond.0,
                closure(|b| Args::write(b, p.ptr, r.rm()));
        }}


        pub trait $J<T>: EmitBytes {
            type Return;
            fn write(&mut self, arg: T) -> Result<Self::Return, Error<Self::Error>>;
        }

        impl<W> $J<Operand> for W where W: EmitBytes {
            type Return = ();
            fn write(&mut self, arg: Operand) -> Result<(), Error<Self::Error>> {
                use operand::Operand::*;
                match arg {
                    Offset8(a) => $J::write(self, a),
                    Offset32(a) => $J::write(self, a),
                    _ => Err(Error::InvalidOperands),
                }
            }
        }

        impl<W> $J<HoleKind> for W where W: EmitBytes {
            type Return = Hole;
            fn write(&mut self, arg: HoleKind) -> Result<Hole, Error<Self::Error>> {
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
            off: i8  =>         0x70 | cond::$cond.0, off;
            off: i32 => 0x0fu8, 0x80 | cond::$cond.0, off;
        }}


        pub trait $Set<D>: EmitBytes {
            fn write(&mut self, dst: D) -> Result<(), Error<Self::Error>>;
        }

        impl<W> $Set<Operand> for W where W: EmitBytes {
            fn write(&mut self, arg: Operand) -> Result<(), Error<Self::Error>> {
                use operand::Operand::*;
                match arg {
                    Reg8(a) => $Set::write(self, a),
                    BytePointer(a) => $Set::write(self, a),
                    _ => Err(Error::InvalidOperands),
                }
            }
        }

        op! { $Set {
            r: Reg8 => try!(rex_b(r)), 0x0fu8, 0x90 | cond::$cond.0, modrm(3, 0, r.rm());
        }}

        dispatch_ptr! { $Set {
            @BytePointer => BytePtr;
        }}

        op_ptr! { $Set {
            p: BytePtr<..> =>
                try!(Rex::rex(p.ptr, ())),
                0x0fu8, 0x90 | cond::$cond.0,
                closure(|b| Args::write(b, p.ptr, 0));
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
    fn write(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>;
}

impl<W> Lea<Operand, Operand> for W where W: EmitBytes {
    fn write(&mut self, dst: Operand, src: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match (dst, src) {
            (Reg16(d), WordPointer(s)) => Lea::write(self, d, s),
            (Reg32(d), DWordPointer(s)) => Lea::write(self, d, s),
            (Reg64(d), QWordPointer(s)) => Lea::write(self, d, s),
            _ => Err(Error::InvalidOperands),
        }
    }
}

dispatch_ptr! { Lea {
    Reg16, @WordPointer => WordPtr;
    Reg32, @DWordPointer => DWordPtr;
    Reg64, @QWordPointer => QWordPtr;
}}

op_ptr! { Lea {
    dst: Reg16, p: WordPtr<..> =>
        0x66u8,
        try!(Rex::rex(p.ptr, dst)),
        0x8du8,
        closure(|b| Args::write(b, p.ptr, dst.rm()));
    dst: Reg32, p: DWordPtr<..> =>
        try!(Rex::rex(p.ptr, dst)),
        0x8du8,
        closure(|b| Args::write(b, p.ptr, dst.rm()));
    dst: Reg64, p: QWordPtr<..> =>
        try!(Rex::rex(p.ptr, dst)),
        0x8du8,
        closure(|b| Args::write(b, p.ptr, dst.rm()));
}}


pub trait Movzx<D, S>: EmitBytes {
    fn write(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>;
}

impl<W> Movzx<Operand, Operand> for W where W: EmitBytes {
    fn write(&mut self, dst: Operand, src: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match (dst, src) {
            (Reg16(d), Reg8(s)) => Movzx::write(self, d, s),
            (Reg32(d), Reg8(s)) => Movzx::write(self, d, s),
            (Reg64(d), Reg8(s)) => Movzx::write(self, d, s),
            (Reg32(d), Reg16(s)) => Movzx::write(self, d, s),
            (Reg64(d), Reg16(s)) => Movzx::write(self, d, s),
            (Reg16(d), BytePointer(s)) => Movzx::write(self, d, s),
            (Reg32(d), BytePointer(s)) => Movzx::write(self, d, s),
            (Reg64(d), BytePointer(s)) => Movzx::write(self, d, s),
            (Reg32(d), WordPointer(s)) => Movzx::write(self, d, s),
            (Reg64(d), WordPointer(s)) => Movzx::write(self, d, s),
            _ => Err(Error::InvalidOperands),
        }
    }
}

forward2! { Movzx {
    Reg16, Reg8 => &[0x0f, 0xb6];
    Reg32, Reg8 => &[0x0f, 0xb6];
    Reg64, Reg8 => &[0x0f, 0xb6];
    Reg32, Reg16 => &[0x0f, 0xb7];
    Reg64, Reg16 => &[0x0f, 0xb7];
}}

dispatch_ptr! { Movzx {
    Reg16, @BytePointer => BytePtr;
    Reg32, @BytePointer => BytePtr;
    Reg64, @BytePointer => BytePtr;
    Reg32, @WordPointer => WordPtr;
    Reg64, @WordPointer => WordPtr;
}}

op_ptr! { Movzx {
    dst: Reg16, p: BytePtr<..> =>
        0x66u8,
        try!(Rex::rex(p.ptr, dst)),
        0x0fu8, 0xb6u8,
        closure(|b| Args::write(b, p.ptr, dst.rm()));
    dst: Reg32, p: BytePtr<..> =>
        try!(Rex::rex(p.ptr, dst)),
        0x0fu8, 0xb6u8,
        closure(|b| Args::write(b, p.ptr, dst.rm()));
    dst: Reg64, p: BytePtr<..> =>
        try!(Rex::rex(p.ptr, dst)),
        0x0fu8, 0xb6u8,
        closure(|b| Args::write(b, p.ptr, dst.rm()));

    dst: Reg32, p: WordPtr<..> =>
        try!(Rex::rex(p.ptr, dst)),
        0x0fu8, 0xb7u8,
        closure(|b| Args::write(b, p.ptr, dst.rm()));
    dst: Reg64, p: WordPtr<..> =>
        try!(Rex::rex(p.ptr, dst)),
        0x0fu8, 0xb7u8,
        closure(|b| Args::write(b, p.ptr, dst.rm()));
}}


pub trait Movsx<D, S>: EmitBytes {
    fn write(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>;
}

impl<W> Movsx<Operand, Operand> for W where W: EmitBytes {
    fn write(&mut self, dst: Operand, src: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match (dst, src) {
            (Reg16(d), Reg8(s)) => Movsx::write(self, d, s),
            (Reg32(d), Reg8(s)) => Movsx::write(self, d, s),
            (Reg64(d), Reg8(s)) => Movsx::write(self, d, s),
            (Reg32(d), Reg16(s)) => Movsx::write(self, d, s),
            (Reg64(d), Reg16(s)) => Movsx::write(self, d, s),
            (Reg16(d), BytePointer(s)) => Movsx::write(self, d, s),
            (Reg32(d), BytePointer(s)) => Movsx::write(self, d, s),
            (Reg64(d), BytePointer(s)) => Movsx::write(self, d, s),
            (Reg32(d), WordPointer(s)) => Movsx::write(self, d, s),
            (Reg64(d), WordPointer(s)) => Movsx::write(self, d, s),
            _ => Err(Error::InvalidOperands),
        }
    }
}

forward2! { Movsx {
    Reg16, Reg8 => &[0x0f, 0xbe];
    Reg32, Reg8 => &[0x0f, 0xbe];
    Reg64, Reg8 => &[0x0f, 0xbe];
    Reg32, Reg16 => &[0x0f, 0xbf];
    Reg64, Reg16 => &[0x0f, 0xbf];
}}

dispatch_ptr! { Movsx {
    Reg16, @BytePointer => BytePtr;
    Reg32, @BytePointer => BytePtr;
    Reg64, @BytePointer => BytePtr;
    Reg32, @WordPointer => WordPtr;
    Reg64, @WordPointer => WordPtr;
}}

op_ptr! { Movsx {
    dst: Reg16, p: BytePtr<..> =>
        0x66u8,
        try!(Rex::rex(p.ptr, dst)),
        0x0fu8, 0xbeu8,
        closure(|b| Args::write(b, p.ptr, dst.rm()));
    dst: Reg32, p: BytePtr<..> =>
        try!(Rex::rex(p.ptr, dst)),
        0x0fu8, 0xbeu8,
        closure(|b| Args::write(b, p.ptr, dst.rm()));
    dst: Reg64, p: BytePtr<..> =>
        try!(Rex::rex(p.ptr, dst)),
        0x0fu8, 0xbeu8,
        closure(|b| Args::write(b, p.ptr, dst.rm()));

    dst: Reg32, p: WordPtr<..> =>
        try!(Rex::rex(p.ptr, dst)),
        0x0fu8, 0xbfu8,
        closure(|b| Args::write(b, p.ptr, dst.rm()));
    dst: Reg64, p: WordPtr<..> =>
        try!(Rex::rex(p.ptr, dst)),
        0x0fu8, 0xbfu8,
        closure(|b| Args::write(b, p.ptr, dst.rm()));
}}


pub trait Cdq: EmitBytes {
    fn write(&mut self) -> Result<(), Error<Self::Error>>;
}

impl<W> Cdq for W where W: EmitBytes {
    fn write(&mut self) -> Result<(), Error<Self::Error>> {
        try!(self.write(&[0x99]));
        Ok(())
    }
}


pub trait Xchg<D, S>: EmitBytes {
    fn write(&mut self, dst: D, src: S) -> Result<(), Error<Self::Error>>;
}

impl<W> Xchg<Operand, Operand> for W where W: EmitBytes {
    fn write(&mut self, dst: Operand, src: Operand) -> Result<(), Error<Self::Error>> {
        use operand::Operand::*;
        match (dst, src) {
            (Reg8(d), Reg8(s)) => Xchg::write(self, d, s),
            (Reg16(d), Reg16(s)) => Xchg::write(self, d, s),
            (Reg32(d), Reg32(s)) => Xchg::write(self, d, s),
            (Reg64(d), Reg64(s)) => Xchg::write(self, d, s),
            (Reg8(d), BytePointer(s)) => Xchg::write(self, d, s),
            (Reg16(d), WordPointer(s)) => Xchg::write(self, d, s),
            (Reg32(d), DWordPointer(s)) => Xchg::write(self, d, s),
            (Reg64(d), QWordPointer(s)) => Xchg::write(self, d, s),
            (BytePointer(d), Reg8(s)) => Xchg::write(self, d, s),
            (WordPointer(d), Reg16(s)) => Xchg::write(self, d, s),
            (DWordPointer(d), Reg32(s)) => Xchg::write(self, d, s),
            (QWordPointer(d), Reg64(s)) => Xchg::write(self, d, s),
            _ => Err(Error::InvalidOperands),
        }
    }
}

op! { Xchg {
    dst: Reg8, src: Reg8 => try!(rex_rb(src, dst)), 0x86u8, modrm(3, src.rm(), dst.rm());
    dst: Reg16, src: Reg16 =>
        0x66u8,
        closure(|buffer| {
            if dst == Reg16::Ax {
                try!(write_rex_b(buffer, src));
                buffer.write_u8(0x90 | src.rm());
            } else if src == Reg16::Ax {
                try!(write_rex_b(buffer, dst));
                buffer.write_u8(0x90 | dst.rm());
            } else {
                try!(write_rex_rb(buffer, src, dst));
                buffer.write_u8(0x87);
                buffer.write_u8(modrm(3, src.rm(), dst.rm()));
            }
            Ok(())
        });
    dst: Reg32, src: Reg32 =>
        closure(|buffer| {
            if dst == Reg32::Eax {
                try!(write_rex_b(buffer, src));
                buffer.write_u8(0x90 | src.rm());
            } else if src == Reg32::Eax {
                try!(write_rex_b(buffer, dst));
                buffer.write_u8(0x90 | dst.rm());
            } else {
                try!(write_rex_rb(buffer, src, dst));
                buffer.write_u8(0x87);
                buffer.write_u8(modrm(3, src.rm(), dst.rm()));
            }
            Ok(())
        });
    dst: Reg64, src: Reg64 =>
        closure(|buffer| {
            if dst == Rax {
                try!(write_rex_b(buffer, src));
                buffer.write_u8(0x90 | src.rm());
            } else if src == Rax {
                try!(write_rex_b(buffer, dst));
                buffer.write_u8(0x90 | dst.rm());
            } else {
                try!(write_rex_rb(buffer, src, dst));
                buffer.write_u8(0x87);
                buffer.write_u8(modrm(3, src.rm(), dst.rm()));
            }
            Ok(())
        });
}}

dispatch_ptr! { Xchg {
    Reg8, @BytePointer => BytePtr;
    Reg16, @WordPointer => WordPtr;
    Reg32, @DWordPointer => DWordPtr;
    Reg64, @QWordPointer => QWordPtr;

    @BytePointer, Reg8 => BytePtr;
    @WordPointer, Reg16 => WordPtr;
    @DWordPointer, Reg32 => DWordPtr;
    @QWordPointer, Reg64 => QWordPtr;
}}

op_ptr! { Xchg {
    r: Reg8, p: BytePtr<..> =>
        try!(Rex::rex(p.ptr, r)),
        0x86u8,
        closure(|b| Args::write(b, p.ptr, r.rm()));
    r: Reg16, p: WordPtr<..> =>
        0x66u8,
        try!(Rex::rex(p.ptr, r)),
        0x87u8,
        closure(|b| Args::write(b, p.ptr, r.rm()));
    r: Reg32, p: DWordPtr<..> =>
        try!(Rex::rex(p.ptr, r)),
        0x87u8,
        closure(|b| Args::write(b, p.ptr, r.rm()));
    r: Reg64, p: QWordPtr<..> =>
        try!(Rex::rex(p.ptr, r)),
        0x87u8,
        closure(|b| Args::write(b, p.ptr, r.rm()));

    p: BytePtr<..>, r: Reg8 =>
        try!(Rex::rex(p.ptr, r)),
        0x86u8,
        closure(|b| Args::write(b, p.ptr, r.rm()));
    p: WordPtr<..>, r: Reg16 =>
        0x66u8,
        try!(Rex::rex(p.ptr, r)),
        0x87u8,
        closure(|b| Args::write(b, p.ptr, r.rm()));
    p: DWordPtr<..>, r: Reg32 =>
        try!(Rex::rex(p.ptr, r)),
        0x87u8,
        closure(|b| Args::write(b, p.ptr, r.rm()));
    p: QWordPtr<..>, r: Reg64 =>
        try!(Rex::rex(p.ptr, r)),
        0x87u8,
        closure(|b| Args::write(b, p.ptr, r.rm()));
}}
