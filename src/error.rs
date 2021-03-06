use std::error;
use std::fmt;
use std::io;

use reg::{Reg8, Reg64};


pub type IoError = Error<io::Error>;


#[derive(Debug)]
pub enum Error<E> {
    InvalidOperands,
    RexIncompatibleRegister(Reg8),
    InvalidIndexRegister(Reg64),
    RedefinedLabel,
    LabelTooFarAway,
    Custom(E),
}

impl<E> fmt::Display for Error<E>
    where E: fmt::Display
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidOperands => write!(fmt, "invalid operands"),
            Error::RexIncompatibleRegister(reg) =>
                write!(fmt, "register {:?} is incompatible with REX prefix", reg),
            Error::InvalidIndexRegister(reg) =>
                write!(fmt, "register {:?} can't be used as index", reg),
            Error::RedefinedLabel => write!(fmt, "can't bind label twice"),
            Error::LabelTooFarAway => write!(fmt, "label is too far away"),
            Error::Custom(ref error) => error.fmt(fmt),
        }
    }
}

impl<E> error::Error for Error<E>
    where E: error::Error
{
    fn description(&self) -> &str {
        match *self {
            Error::InvalidOperands => "invalid operands",
            Error::RexIncompatibleRegister(..) => "register is incompatible with REX prefix",
            Error::InvalidIndexRegister(..) => "register can't be used as index",
            Error::RedefinedLabel => "can't bind label twice",
            Error::LabelTooFarAway => "label is too far away",
            Error::Custom(ref error) => error.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Custom(ref error) => Some(error),
            _ => None
        }
    }
}

impl<E> From<E> for Error<E>
    where E: error::Error
{
    #[inline]
    fn from(error: E) -> Error<E> {
        Error::Custom(error)
    }
}
