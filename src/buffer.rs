use std::mem;
use std::slice;
use std::ops::{Range, Deref, DerefMut};

use byteorder::{ByteOrder, LittleEndian};


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
