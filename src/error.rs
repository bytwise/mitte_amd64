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
            Error::Custom(ref error) => error.fmt(fmt),
        }
    }
}

impl<E> error::Error for Error<E>
    where E: error::Error + 'static
{
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
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
