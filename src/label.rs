use EmitBytes;
use error::{Error, Result};
use fixup::{HoleKind, Hole, Fixup};
use amd64::{Jmp, Je, Jz, Jne, Jnz, Ja, Jl, Jge, Jle, Jg};


pub trait BindLabel {
    fn bind_label(&mut self, label: &mut Label) -> Result<()>;
}

impl<W> BindLabel for W where W: EmitBytes {
    fn bind_label(&mut self, label: &mut Label) -> Result<()> {
        if label.address.is_some() {
            return Err(Error::RedefinedLabel);
        }

        let pos = self.pos();
        for hole in label.unresolved_locs.drain(..) {
            let offset = pos as i64 - (hole.addr as i64 + 4);

            try!(self.fixup(Fixup::Rel32(hole.addr, offset as i32)));
        }

        label.address = Some(pos);
        Ok(())
    }
}


#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Label {
    address: Option<u64>,
    unresolved_locs: Vec<Hole>,
}

impl Label {
    #[inline]
    pub fn new() -> Label {
        Label {
            address: None,
            unresolved_locs: Vec::new(),
        }
    }
}


impl<'a, W> Jmp<&'a mut Label> for W where W: EmitBytes {
    type Return = ();
    fn write(&mut self, label: &mut Label) -> Result<()> {
        if let Some(addr) = label.address {
            let offset = addr as isize - (self.pos() as isize + 5);

            match offset {
                -0x8000_0000...0x7fff_ffff => try!(Jmp::write(self, offset as i32)),
                _ => return Err(Error::LabelTooFarAway),
            }
            Ok(())
        } else {
            let hole = try!(Jmp::write(self, HoleKind::Rel32));
            label.unresolved_locs.push(hole);
            Ok(())
        }
    }
}


macro_rules! jcc {
    ($($J:ident),*) => {
        $(
            impl<'a, W> $J<&'a mut Label> for W where W: EmitBytes {
                type Return = ();
                fn write(&mut self, label: &mut Label) -> Result<()> {
                    if let Some(addr) = label.address {
                        let offset = addr as isize - (self.pos() as isize + 6);

                        match offset {
                            -0x8000_0000...0x7fff_ffff => {
                                try!($J::write(self, offset as i32))
                            }
                            _ => return Err(Error::LabelTooFarAway),
                        }
                        Ok(())
                    } else {
                        let hole = try!($J::write(self, HoleKind::Rel32));
                        label.unresolved_locs.push(hole);
                        Ok(())
                    }
                }
            }
        )*
    };
}

jcc! { Je, Jz, Jne, Jnz, Ja, Jl, Jge, Jle, Jg }


#[cfg(test)]
mod tests {
    use Emit;
    use reg::Reg8::*;
    use reg::Reg64::*;
    use byte_ptr;
    use super::{BindLabel, Label};


    #[test]
    fn test() {
        let mut buffer = Vec::new();

        buffer.add(byte_ptr(Rax), Al).unwrap();

        {
            let mut l1 = Label::new();
            let mut l2 = Label::new();
            buffer.jg(&mut l2).unwrap();

            buffer.bind_label(&mut l1).unwrap();
            buffer.add(byte_ptr(Rax), Al).unwrap();
            buffer.jg(&mut l1).unwrap();

            buffer.bind_label(&mut l2).unwrap();
        }

        {
            let mut l1 = Label::new();
            let mut l2 = Label::new();
            buffer.jg(&mut l2).unwrap();

            buffer.bind_label(&mut l1).unwrap();
            buffer.add(byte_ptr(Rax), Al).unwrap();
            buffer.jg(&mut l1).unwrap();

            buffer.bind_label(&mut l2).unwrap();
        }

        assert_eq!(buffer, &[
            0, 0,                                   // add [rax], al
            0x0f, 0x8f, 8, 0, 0, 0,                 // jg +8
            0, 0,                                   // add [rax], al
            0x0f, 0x8f, 0xf8, 0xff, 0xff, 0xff,     // jg -8
            0x0f, 0x8f, 8, 0, 0, 0,                 // jg +8
            0, 0,                                   // add [rax], al
            0x0f, 0x8f, 0xf8, 0xff, 0xff, 0xff      // jg -8
        ]);
    }
}
