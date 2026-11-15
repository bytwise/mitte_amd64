macro_rules! forward {
    (
        $(
            $method:ident $(< $( $generics:ident ),* >)* ($( $arg:ident : $arg_ty:ty ),*)
                $(where $( $T:ident : $bound:path ),+ )*
                => $( $opcode:expr ),*;
        )*
    ) => {
        $(
            #[inline]
            fn $method $(< $( $generics ),* >)* (&mut self $(, $arg : $arg_ty )*)
                -> Result<(), Error<Self::Error>>
            $(where $( $T : $bound ),+ )*
            {
                super::encoding::Encode::encode(self, ($( $arg ),*), ( $( $opcode ),* ))
            }
        )*
    }
}

pub(crate) use forward;
