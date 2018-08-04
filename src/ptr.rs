use std::ops;

use reg::Reg64;


mod private {
    use common::{Rex, Args};

    pub trait MemSealed: Clone + Rex + Args {}

    impl<M> MemSealed for M where M: Clone + Rex + Args {}
}

pub trait Mem: private::MemSealed {}

impl Mem for Pointer {}
impl Mem for Ptr<(), (), i8> { }
impl Mem for Ptr<(), (), i32> {}
impl Mem for Ptr<Reg64, (), ()> {}
impl Mem for Ptr<Reg64, (), i8> {}
impl Mem for Ptr<Reg64, (), i32> {}
impl Mem for Ptr<(), Scaled<Reg64>, ()> {}
impl Mem for Ptr<(), Scaled<Reg64>, i8> {}
impl Mem for Ptr<(), Scaled<Reg64>, i32> {}
impl Mem for Ptr<Reg64, Scaled<Reg64>, ()> {}
impl Mem for Ptr<Reg64, Scaled<Reg64>, i8> {}
impl Mem for Ptr<Reg64, Scaled<Reg64>, i32> {}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Byte<M>(pub M);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Word<M>(pub M);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DWord<M>(pub M);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct QWord<M>(pub M);


pub fn byte_ptr<M, B, X, D>(m: M) -> Byte<Ptr<B, X, D>> where M: Into<Ptr<B, X, D>> {
    Byte(m.into())
}

pub fn word_ptr<M, B, X, D>(m: M) -> Word<Ptr<B, X, D>> where M: Into<Ptr<B, X, D>> {
    Word(m.into())
}

pub fn dword_ptr<M, B, X, D>(m: M) -> DWord<Ptr<B, X, D>> where M: Into<Ptr<B, X, D>> {
    DWord(m.into())
}

pub fn qword_ptr<M, B, X, D>(m: M) -> QWord<Ptr<B, X, D>> where M: Into<Ptr<B, X, D>> {
    QWord(m.into())
}


pub fn byte_pointer<M>(m: M) -> Byte<Pointer> where M: Into<Pointer> {
    Byte(m.into())
}

pub fn word_pointer<M>(m: M) -> Word<Pointer> where M: Into<Pointer> {
    Word(m.into())
}

pub fn dword_pointer<M>(m: M) -> DWord<Pointer> where M: Into<Pointer> {
    DWord(m.into())
}

pub fn qword_pointer<M>(m: M) -> QWord<Pointer> where M: Into<Pointer> {
    QWord(m.into())
}


#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scale {
    _1 = 0,
    _2 = 1,
    _4 = 2,
    _8 = 3,
}


#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Scaled<R>(pub R, pub Scale);


#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ptr<B, X, D> {
    pub base: B,
    pub index: X,
    pub disp: D,
}

impl<B, X, D> Ptr<B, X, D> {
    pub fn new(base: B, index: X, disp: D) -> Ptr<B, X, D> {
        Ptr {
            base: base,
            index: index,
            disp: disp,
        }
    }
}


impl From<i8> for Ptr<(), (), i8> {
    #[inline]
    fn from(disp: i8) -> Ptr<(), (), i8> {
        Ptr::new((), (), disp)
    }
}

impl From<i32> for Ptr<(), (), i32> {
    #[inline]
    fn from(disp: i32) -> Ptr<(), (), i32> {
        Ptr::new((), (), disp)
    }
}

impl From<Reg64> for Ptr<Reg64, (), ()> {
    #[inline]
    fn from(base: Reg64) -> Ptr<Reg64, (), ()> {
        Ptr::new(base, (), ())
    }
}


impl ops::Add<i8> for Reg64 {
    type Output = Ptr<Reg64, (), i8>;

    #[inline]
    fn add(self, rhs: i8) -> Ptr<Reg64, (), i8> {
        Ptr::new(self, (), rhs)
    }
}

impl ops::Add<i32> for Reg64 {
    type Output = Ptr<Reg64, (), i32>;

    #[inline]
    fn add(self, rhs: i32) -> Ptr<Reg64, (), i32> {
        Ptr::new(self, (), rhs)
    }
}

impl ops::Sub<i8> for Reg64 {
    type Output = Ptr<Reg64, (), i8>;

    #[inline]
    fn sub(self, rhs: i8) -> Ptr<Reg64, (), i8> {
        Ptr::new(self, (), -rhs)
    }
}

impl ops::Sub<i32> for Reg64 {
    type Output = Ptr<Reg64, (), i32>;

    #[inline]
    fn sub(self, rhs: i32) -> Ptr<Reg64, (), i32> {
        Ptr::new(self, (), -rhs)
    }
}

impl ops::Add<Ptr<(), (), i8>> for Reg64 {
    type Output = Ptr<Reg64, (), i8>;

    #[inline]
    fn add(self, p: Ptr<(), (), i8>) -> Ptr<Reg64, (), i8> {
        Ptr::new(self, (), p.disp)
    }
}

impl ops::Add<Ptr<(), (), i32>> for Reg64 {
    type Output = Ptr<Reg64, (), i32>;

    #[inline]
    fn add(self, p: Ptr<(), (), i32>) -> Ptr<Reg64, (), i32> {
        Ptr::new(self, (), p.disp)
    }
}

impl ops::Add<Reg64> for Reg64 {
    type Output = Ptr<Reg64, Scaled<Reg64>, ()>;

    #[inline]
    fn add(self, index: Reg64) -> Ptr<Reg64, Scaled<Reg64>, ()> {
        Ptr::new(self, Scaled(index, Scale::_1), ())
    }
}

impl ops::Add<Ptr<(), Scaled<Reg64>, ()>> for Reg64 {
    type Output = Ptr<Reg64, Scaled<Reg64>, ()>;

    #[inline]
    fn add(self, p: Ptr<(), Scaled<Reg64>, ()>) -> Ptr<Reg64, Scaled<Reg64>, ()> {
        Ptr::new(self, p.index, ())
    }
}

impl ops::Add<Ptr<(), Scaled<Reg64>, i8>> for Reg64 {
    type Output = Ptr<Reg64, Scaled<Reg64>, i8>;

    #[inline]
    fn add(self, p: Ptr<(), Scaled<Reg64>, i8>) -> Ptr<Reg64, Scaled<Reg64>, i8> {
        Ptr::new(self, p.index, p.disp)
    }
}

impl ops::Add<Ptr<(), Scaled<Reg64>, i32>> for Reg64 {
    type Output = Ptr<Reg64, Scaled<Reg64>, i32>;

    #[inline]
    fn add(self, p: Ptr<(), Scaled<Reg64>, i32>) -> Ptr<Reg64, Scaled<Reg64>, i32> {
        Ptr::new(self, p.index, p.disp)
    }
}

impl ops::Add<i8> for Ptr<Reg64, (), ()> {
    type Output = Ptr<Reg64, (), i8>;

    #[inline]
    fn add(self, rhs: i8) -> Ptr<Reg64, (), i8> {
        Ptr::new(self.base, (), rhs)
    }
}

impl ops::Add<i32> for Ptr<Reg64, (), ()> {
    type Output = Ptr<Reg64, (), i32>;

    #[inline]
    fn add(self, rhs: i32) -> Ptr<Reg64, (), i32> {
        Ptr::new(self.base, (), rhs)
    }
}

impl ops::Add<i8> for Ptr<(), Scaled<Reg64>, ()> {
    type Output = Ptr<(), Scaled<Reg64>, i8>;

    #[inline]
    fn add(self, rhs: i8) -> Ptr<(), Scaled<Reg64>, i8> {
        Ptr::new((), self.index, rhs)
    }
}

impl ops::Add<i32> for Ptr<(), Scaled<Reg64>, ()> {
    type Output = Ptr<(), Scaled<Reg64>, i32>;

    #[inline]
    fn add(self, rhs: i32) -> Ptr<(), Scaled<Reg64>, i32> {
        Ptr::new((), self.index, rhs)
    }
}

impl ops::Add<i8> for Ptr<Reg64, Scaled<Reg64>, ()> {
    type Output = Ptr<Reg64, Scaled<Reg64>, i8>;

    #[inline]
    fn add(self, rhs: i8) -> Ptr<Reg64, Scaled<Reg64>, i8> {
        Ptr::new(self.base, self.index, rhs)
    }
}

impl ops::Add<i32> for Ptr<Reg64, Scaled<Reg64>, ()> {
    type Output = Ptr<Reg64, Scaled<Reg64>, i32>;

    #[inline]
    fn add(self, rhs: i32) -> Ptr<Reg64, Scaled<Reg64>, i32> {
        Ptr::new(self.base, self.index, rhs)
    }
}

impl ops::Sub<i8> for Ptr<Reg64, (), ()> {
    type Output = Ptr<Reg64, (), i8>;

    #[inline]
    fn sub(self, rhs: i8) -> Ptr<Reg64, (), i8> {
        Ptr::new(self.base, (), -rhs)
    }
}

impl ops::Sub<i32> for Ptr<Reg64, (), ()> {
    type Output = Ptr<Reg64, (), i32>;

    #[inline]
    fn sub(self, rhs: i32) -> Ptr<Reg64, (), i32> {
        Ptr::new(self.base, (), -rhs)
    }
}

impl ops::Sub<i8> for Ptr<(), Scaled<Reg64>, ()> {
    type Output = Ptr<(), Scaled<Reg64>, i8>;

    #[inline]
    fn sub(self, rhs: i8) -> Ptr<(), Scaled<Reg64>, i8> {
        Ptr::new((), self.index, -rhs)
    }
}

impl ops::Sub<i32> for Ptr<(), Scaled<Reg64>, ()> {
    type Output = Ptr<(), Scaled<Reg64>, i32>;

    #[inline]
    fn sub(self, rhs: i32) -> Ptr<(), Scaled<Reg64>, i32> {
        Ptr::new((), self.index, -rhs)
    }
}

impl ops::Sub<i8> for Ptr<Reg64, Scaled<Reg64>, ()> {
    type Output = Ptr<Reg64, Scaled<Reg64>, i8>;

    #[inline]
    fn sub(self, rhs: i8) -> Ptr<Reg64, Scaled<Reg64>, i8> {
        Ptr::new(self.base, self.index, -rhs)
    }
}

impl ops::Sub<i32> for Ptr<Reg64, Scaled<Reg64>, ()> {
    type Output = Ptr<Reg64, Scaled<Reg64>, i32>;

    #[inline]
    fn sub(self, rhs: i32) -> Ptr<Reg64, Scaled<Reg64>, i32> {
        Ptr::new(self.base, self.index, -rhs)
    }
}

impl ops::Mul<u8> for Reg64 {
    type Output = Ptr<(), Scaled<Reg64>, ()>;

    #[inline]
    fn mul(self, rhs: u8) -> Ptr<(), Scaled<Reg64>, ()> {
        let scale = match rhs {
            1 => Scale::_1,
            2 => Scale::_2,
            4 => Scale::_4,
            8 => Scale::_8,
            _ => panic!("Invalid scale {}. Possible values are 1, 2, 4, 8.", rhs)
        };
        Ptr::new((), Scaled(self, scale), ())
    }
}


#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pointer {
    Disp8(i8),
    Disp32(i32),
    Base(Reg64),
    BaseDisp8(Reg64, i8),
    BaseDisp32(Reg64, i32),
    Index(Scaled<Reg64>),
    IndexDisp8(Scaled<Reg64>, i8),
    IndexDisp32(Scaled<Reg64>, i32),
    BaseIndex(Reg64, Scaled<Reg64>),
    BaseIndexDisp8(Reg64, Scaled<Reg64>, i8),
    BaseIndexDisp32(Reg64, Scaled<Reg64>, i32),
}

impl From<i8> for Pointer {
    #[inline]
    fn from(disp: i8) -> Pointer {
        Pointer::Disp8(disp)
    }
}

impl From<i32> for Pointer {
    #[inline]
    fn from(disp: i32) -> Pointer {
        Pointer::Disp32(disp)
    }
}

impl From<Reg64> for Pointer {
    #[inline]
    fn from(base: Reg64) -> Pointer {
        Pointer::Base(base)
    }
}

impl From<Ptr<(), (), i8>> for Pointer {
    #[inline]
    fn from(p: Ptr<(), (), i8>) -> Pointer {
        Pointer::Disp8(p.disp)
    }
}

impl From<Ptr<(), (), i32>> for Pointer {
    #[inline]
    fn from(p: Ptr<(), (), i32>) -> Pointer {
        Pointer::Disp32(p.disp)
    }
}

impl From<Ptr<Reg64, (), ()>> for Pointer {
    #[inline]
    fn from(p: Ptr<Reg64, (), ()>) -> Pointer {
        Pointer::Base(p.base)
    }
}

impl From<Ptr<Reg64, (), i8>> for Pointer {
    #[inline]
    fn from(p: Ptr<Reg64, (), i8>) -> Pointer {
        Pointer::BaseDisp8(p.base, p.disp)
    }
}

impl From<Ptr<Reg64, (), i32>> for Pointer {
    #[inline]
    fn from(p: Ptr<Reg64, (), i32>) -> Pointer {
        Pointer::BaseDisp32(p.base, p.disp)
    }
}

impl From<Ptr<(), Scaled<Reg64>, ()>> for Pointer {
    #[inline]
    fn from(p: Ptr<(), Scaled<Reg64>, ()>) -> Pointer {
        Pointer::Index(p.index)
    }
}

impl From<Ptr<(), Scaled<Reg64>, i8>> for Pointer {
    #[inline]
    fn from(p: Ptr<(), Scaled<Reg64>, i8>) -> Pointer {
        Pointer::IndexDisp8(p.index, p.disp)
    }
}

impl From<Ptr<(), Scaled<Reg64>, i32>> for Pointer {
    #[inline]
    fn from(p: Ptr<(), Scaled<Reg64>, i32>) -> Pointer {
        Pointer::IndexDisp32(p.index, p.disp)
    }
}

impl From<Ptr<Reg64, Scaled<Reg64>, ()>> for Pointer {
    #[inline]
    fn from(p: Ptr<Reg64, Scaled<Reg64>, ()>) -> Pointer {
        Pointer::BaseIndex(p.base, p.index)
    }
}

impl From<Ptr<Reg64, Scaled<Reg64>, i8>> for Pointer {
    #[inline]
    fn from(p: Ptr<Reg64, Scaled<Reg64>, i8>) -> Pointer {
        Pointer::BaseIndexDisp8(p.base, p.index, p.disp)
    }
}

impl From<Ptr<Reg64, Scaled<Reg64>, i32>> for Pointer {
    #[inline]
    fn from(p: Ptr<Reg64, Scaled<Reg64>, i32>) -> Pointer {
        Pointer::BaseIndexDisp32(p.base, p.index, p.disp)
    }
}
