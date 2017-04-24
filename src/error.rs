use std::result;
use std::error;
use std::io;
use std::fmt;

use reg::{Reg8, Reg64};


pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    InvalidOperands,
    RexIncompatibleRegister(Reg8),
    InvalidIndexRegister(Reg64),
    RedefinedLabel,
    LabelTooFarAway,
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidOperands => write!(fmt, "invalid operands"),
            Error::RexIncompatibleRegister(reg) =>
                write!(fmt, "register {:?} is incompatible with REX prefix", reg),
            Error::InvalidIndexRegister(reg) =>
                write!(fmt, "register {:?} can't be used as index", reg),
            Error::RedefinedLabel => write!(fmt, "can't bind label twice"),
            Error::LabelTooFarAway => write!(fmt, "label is too far away"),
            Error::Io(ref error) => error.fmt(fmt)
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::InvalidOperands => "invalid operands",
            Error::RexIncompatibleRegister(..) => "register is incompatible with REX prefix",
            Error::InvalidIndexRegister(..) => "register can't be used as index",
            Error::RedefinedLabel => "can't bind label twice",
            Error::LabelTooFarAway => "label is too far away",
            Error::Io(ref error) => error.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Io(ref error) => Some(error),
            _ => None
        }
    }
}

impl From<io::Error> for Error {
    #[inline]
    fn from(error: io::Error) -> Error {
        Error::Io(error)
    }
}
