use std::ops::Range;

use mitte_core::Error;


pub enum FixupKind {
    PcRel8,
    PcRel32,
}

impl<Emit> mitte_core::FixupKind<Emit> for FixupKind
    where Emit: mitte_core::Emit
{
    #[inline]
    fn apply_fixup(&self, emit: &mut Emit, range: Range<u64>, offset: i64) -> Result<(), Error> {
        let offset = offset - (range.end - range.start) as i64;
        match *self {
            FixupKind::PcRel8 => {
                let buffer = emit.get_mut_array::<1>(range.end - 1)?;
                buffer.copy_from_slice(&(offset as i8).to_le_bytes());
            }
            FixupKind::PcRel32 => {
                let buffer = emit.get_mut_array::<4>(range.end - 4)?;
                buffer.copy_from_slice(&(offset as i32).to_le_bytes());
            }
        }
        Ok(())
    }
}
