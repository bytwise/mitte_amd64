#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum HoleKind {
    Rel8,
    Rel32,
}


#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Hole {
    pub addr: u64,
    pub kind: HoleKind,
}

impl Hole {
    #[inline]
    pub fn rel8(addr: u64) -> Hole {
        Hole { addr: addr, kind: HoleKind::Rel8 }
    }

    #[inline]
    pub fn rel32(addr: u64) -> Hole {
        Hole { addr: addr, kind: HoleKind::Rel32 }
    }
}


#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Fixup {
    Rel8(u64, i8),
    Rel32(u64, i32),
}

impl Fixup {
    #[inline]
    pub fn addr(&self) -> u64 {
        match *self {
            Fixup::Rel8(addr, _) | Fixup::Rel32(addr, _) => addr,
        }
    }
}
