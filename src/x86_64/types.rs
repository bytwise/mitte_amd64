#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    O = 0,
    No = 1,
    B = 2,
    Ae = 3,
    E = 4,
    Ne = 5,
    Be = 6,
    A = 7,
    S = 8,
    Ns = 9,
    P = 0xa,
    Np = 0xb,
    L = 0xc,
    Ge = 0xd,
    Le = 0xe,
    G = 0xf,
}

#[allow(non_upper_case_globals)]
impl Condition {
    pub const C: Condition = Condition::B;
    pub const Nae: Condition = Condition::B;
    pub const Nb: Condition = Condition::Ae;
    pub const Nc: Condition = Condition::Ae;
    pub const Z: Condition = Condition::E;
    pub const Nz: Condition = Condition::Ne;
    pub const Na: Condition = Condition::Be;
    pub const Nbe: Condition = Condition::A;
    pub const Pe: Condition = Condition::P;
    pub const Po: Condition = Condition::Np;
    pub const Nge: Condition = Condition::L;
    pub const Nl: Condition = Condition::Ge;
    pub const Ng: Condition = Condition::Le;
    pub const Nle: Condition = Condition::G;
}


#[derive(Clone, Copy)]
pub struct Rel8 {
    pub(crate) offset: i8,
}

impl From<i8> for Rel8 {
    #[inline]
    fn from(offset: i8) -> Rel8 {
        Rel8 { offset }
    }
}


#[derive(Clone, Copy)]
pub struct Rel32 {
    pub(crate) offset: i32,
}

impl From<i32> for Rel32 {
    #[inline]
    fn from(offset: i32) -> Rel32 {
        Rel32 { offset }
    }
}
