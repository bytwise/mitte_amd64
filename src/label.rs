use mitte_core::{EmitSlice, Emit};

use error::Error;
use fixup::{HoleKind, Hole};
use amd64::Jmp;
use amd64::{
    Ja,
    Jae,
    Jb,
    Jbe,
    Jc,
    Je,
    Jg,
    Jge,
    Jl,
    Jle,
    Jna,
    Jnae,
    Jnb,
    Jnbe,
    Jnc,
    Jne,
    Jng,
    Jnge,
    Jnl,
    Jnle,
    Jno,
    Jnp,
    Jns,
    Jnz,
    Jo,
    Jp,
    Jpe,
    Jpo,
    Js,
    Jz
};


pub trait BindLabel: EmitSlice {
    fn bind_label(&mut self, label: &mut Label) -> Result<(), Error<Self::Error>>;
}

impl<W> BindLabel for W where W: Emit {
    fn bind_label(&mut self, label: &mut Label) -> Result<(), Error<Self::Error>> {
        if label.address.is_some() {
            return Err(Error::RedefinedLabel);
        }

        let pos = self.position();
        for hole in label.unresolved_locs.drain(..) {
            let offset = pos as i64 - (hole.addr as i64 + 4);

            if let Ok(buffer) = self.get_mut_array::<4>(hole.addr) {
                buffer.copy_from_slice(&(offset as u32).to_le_bytes());
            } else {
                panic!("fixup is out of bounds");
            }
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


impl<'a, W> Jmp<&'a mut Label> for W where W: Emit {
    fn emit(&mut self, label: &mut Label) -> Result<(), Error<Self::Error>> {
        if let Some(addr) = label.address {
            let offset = addr as isize - self.position() as isize;

            match offset {
                -0x8000_0000..=0x7fff_ffff => Jmp::emit(self, offset as i32),
                _ => Err(Error::LabelTooFarAway),
            }
        } else {
            Jmp::emit(self, 0i32)?;
            let hole = Hole {
                addr: self.position() - 4,
                kind: HoleKind::Rel32,
            };
            label.unresolved_locs.push(hole);
            Ok(())
        }
    }
}


macro_rules! jcc {
    ($($J:ident),*) => {
        $(
            impl<'a, W> $J<&'a mut Label> for W where W: Emit {
                fn emit(&mut self, label: &mut Label) -> Result<(), Error<Self::Error>> {
                    if let Some(addr) = label.address {
                        let offset = addr as isize - self.position() as isize;

                        match offset {
                            -0x8000_0000..=0x7fff_ffff => $J::emit(self, offset as i32),
                            _ => Err(Error::LabelTooFarAway),
                        }
                    } else {
                        $J::emit(self, 0i32)?;
                        let hole = Hole {
                            addr: self.position() - 4,
                            kind: HoleKind::Rel32,
                        };
                        label.unresolved_locs.push(hole);
                        Ok(())
                    }
                }
            }
        )*
    };
}

jcc! {
    Ja,
    Jae,
    Jb,
    Jbe,
    Jc,
    Je,
    Jg,
    Jge,
    Jl,
    Jle,
    Jna,
    Jnae,
    Jnb,
    Jnbe,
    Jnc,
    Jne,
    Jng,
    Jnge,
    Jnl,
    Jnle,
    Jno,
    Jnp,
    Jns,
    Jnz,
    Jo,
    Jp,
    Jpe,
    Jpo,
    Js,
    Jz
}


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

        buffer.emit_add(byte_ptr(Rax), Al).unwrap();

        {
            let mut l1 = Label::new();
            let mut l2 = Label::new();
            buffer.emit_jg(&mut l2).unwrap();

            buffer.bind_label(&mut l1).unwrap();
            buffer.emit_add(byte_ptr(Rax), Al).unwrap();
            buffer.emit_jg(&mut l1).unwrap();

            buffer.bind_label(&mut l2).unwrap();
        }

        {
            let mut l1 = Label::new();
            let mut l2 = Label::new();
            buffer.emit_jg(&mut l2).unwrap();

            buffer.bind_label(&mut l1).unwrap();
            buffer.emit_add(byte_ptr(Rax), Al).unwrap();
            buffer.emit_jg(&mut l1).unwrap();

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
