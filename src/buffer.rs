use std::mem;
use std::slice;
use std::ops::{Range, Deref, DerefMut};

use byteorder::{ByteOrder, LittleEndian};

use common::NoError;
use error::Error;


pub struct Buffer {
    len: usize,
    buf: [u8; 32],
}

impl Buffer {
    #[inline]
    pub fn new() -> Buffer {
        unsafe {
            Buffer {
                len: 0,
                buf: mem::uninitialized(),
            }
        }
    }

    #[inline]
    pub fn write(&mut self, slice: &[u8]) {
        debug_assert!(self.len + slice.len() <= 32);
        unsafe {
            let len = self.len;
            let end = self.len + slice.len();
            self.slice_unchecked_mut(len..end).copy_from_slice(slice);
        }
        self.len += slice.len();
    }

    #[inline]
    pub fn write_u8(&mut self, value: u8) {
        debug_assert!(self.len + 1 <= 32);
        unsafe {
            *self.buf.get_unchecked_mut(self.len) = value;
        }
        self.len += 1;
    }

    #[inline]
    pub fn write_u16(&mut self, value: u16) {
        debug_assert!(self.len + 2 <= 32);
        unsafe {
            let len = self.len;
            let slice = self.slice_unchecked_mut(len..len+2);
            LittleEndian::write_u16(slice, value);
        }
        self.len += 2;
    }

    #[inline]
    pub fn write_u32(&mut self, value: u32) {
        debug_assert!(self.len + 4 <= 32);
        unsafe {
            let len = self.len;
            let slice = self.slice_unchecked_mut(len..len+4);
            LittleEndian::write_u32(slice, value);
        }
        self.len += 4;
    }

    #[inline]
    pub fn write_u64(&mut self, value: u64) {
        debug_assert!(self.len + 8 <= 32);
        unsafe {
            let len = self.len;
            let slice = self.slice_unchecked_mut(len..len+8);
            LittleEndian::write_u64(slice, value);
        }
        self.len += 8;
    }

    #[inline]
    unsafe fn slice_unchecked(&self, range: Range<usize>) -> &[u8] {
        let ptr = self.buf.as_ptr().offset(range.start as isize);
        let len = range.end - range.start;
        slice::from_raw_parts(ptr, len)
    }

    #[inline]
    unsafe fn slice_unchecked_mut(&mut self, range: Range<usize>) -> &mut [u8] {
        let ptr = self.buf.as_mut_ptr().offset(range.start as isize);
        let len = range.end - range.start;
        slice::from_raw_parts_mut(ptr, len)
    }
}


impl Deref for Buffer {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        let len = self.len;
        unsafe { self.slice_unchecked(0..len) }
    }
}

impl DerefMut for Buffer {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        let len = self.len;
        unsafe { self.slice_unchecked_mut(0..len) }
    }
}


pub trait Write<T> {
    fn write(&mut self, value: T) -> Result<(), Error<NoError>>;
}

impl Write<()> for Buffer {
    #[inline]
    fn write(&mut self, _value: ()) -> Result<(), Error<NoError>> {
        Ok(())
    }
}

impl Write<u8> for Buffer {
    #[inline]
    fn write(&mut self, value: u8) -> Result<(), Error<NoError>> {
        self.write_u8(value);
        Ok(())
    }
}

impl Write<u16> for Buffer {
    #[inline]
    fn write(&mut self, value: u16) -> Result<(), Error<NoError>> {
        self.write_u16(value);
        Ok(())
    }
}

impl Write<u32> for Buffer {
    #[inline]
    fn write(&mut self, value: u32) -> Result<(), Error<NoError>> {
        self.write_u32(value);
        Ok(())
    }
}

impl Write<u64> for Buffer {
    #[inline]
    fn write(&mut self, value: u64) -> Result<(), Error<NoError>> {
        self.write_u64(value);
        Ok(())
    }
}

impl Write<i8> for Buffer {
    #[inline]
    fn write(&mut self, value: i8) -> Result<(), Error<NoError>> {
        self.write_u8(value as u8);
        Ok(())
    }
}

impl Write<i32> for Buffer {
    #[inline]
    fn write(&mut self, value: i32) -> Result<(), Error<NoError>> {
        self.write_u32(value as u32);
        Ok(())
    }
}

impl Write<Option<u8>> for Buffer {
    #[inline]
    fn write(&mut self, value: Option<u8>) -> Result<(), Error<NoError>> {
        if let Some(value) = value {
            self.write_u8(value);
        }
        Ok(())
    }
}

impl<'a> Write<&'a [u8]> for Buffer {
    #[inline]
    fn write(&mut self, value: &[u8]) -> Result<(), Error<NoError>> {
        self.write(value);
        Ok(())
    }
}

impl<F> Write<F> for Buffer
    where F: FnOnce(&mut Buffer) -> Result<(), Error<NoError>>
{
    #[inline]
    fn write(&mut self, f: F) -> Result<(), Error<NoError>> {
        f(self)
    }
}
