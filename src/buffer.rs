use std::ops::{Deref, DerefMut};

use arrayvec::ArrayVec;


pub struct Buffer {
    buf: ArrayVec<u8, 32>,
}

impl Buffer {
    #[inline]
    pub fn new() -> Buffer {
        Buffer {
            buf: ArrayVec::new(),
        }
    }

    #[inline]
    pub fn write_u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    #[inline]
    pub fn write_u16(&mut self, value: u16) {
        self.buf.try_extend_from_slice(&value.to_le_bytes()).unwrap();
    }

    #[inline]
    pub fn write_u32(&mut self, value: u32) {
        self.buf.try_extend_from_slice(&value.to_le_bytes()).unwrap();
    }

    #[inline]
    pub fn write_u64(&mut self, value: u64) {
        self.buf.try_extend_from_slice(&value.to_le_bytes()).unwrap();
    }
}


impl Deref for Buffer {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        self.buf.deref()
    }
}

impl DerefMut for Buffer {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        self.buf.deref_mut()
    }
}
