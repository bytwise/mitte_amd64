macro_rules! forward {
    ($( $f:ident ($($arg:ident : $T:ident),*) => $Trait:ident; )*) => {
        $(
            fn $f<$($T),*>(&mut self $(, $arg: $T)*) -> Result<(), Error<Self::Error>>
                where Self: $Trait<$($T),*>
            {
                $Trait::emit(self $(, $arg)*)
            }
        )*
    }
}

pub(crate) use forward;


macro_rules! op {
    ($Trait:ident {}) => {};
    ($Trait:ident => $R:ty {}) => {};

    (
        $Trait:ident
        {
            $(<$($A:ident : $bound:ident),*>)*
            $($arg:ident : $T:ty),+
                ; assert_eq!($assert_e1:expr, $assert_e2:expr)
                => ($enc:ty) $($e:expr),*;
            $($rest:tt)*
        }
    ) => {
        impl<W $($(, $A)*)*> $Trait<$($T),*> for W
            where W: mitte_core::EmitSlice $($(, $A : $bound)*)*
        {
            fn emit(&mut self, $($arg: $T),*)
                -> std::result::Result<(), super::error::Error<W::Error>>
            {
                #![allow(unused_parens)]
                assert_eq!($assert_e1, $assert_e2);
                super::encoding::Encode::<$enc, _>::encode(self, ( $($arg),* ), ( $($e),* ))
            }
        }
        op! { $Trait { $($rest)* } }
    };

    (
        $Trait:ident
        {
            $(<$($A:ident : $bound:ident),*>)*
            $($arg:ident : $T:ty),* => if ($cond:expr) {
                ($enc1:ty) $($e1:expr),*
            } else {
                ($enc2:ty) $($e2:expr),*
            };
            $($rest:tt)*
        }
    ) => {
        impl<W $($(, $A)*)*> $Trait<$($T),*> for W
            where W: mitte_core::EmitSlice $($(, $A : $bound)*)*
        {
            fn emit(&mut self, $($arg: $T),*)
                -> std::result::Result<(), super::error::Error<W::Error>>
            {
                #![allow(unused_parens)]
                if $cond {
                    super::encoding::Encode::<$enc1, _>::encode(self, ( $($arg),* ), ( $($e1),* ))
                } else {
                    super::encoding::Encode::<$enc2, _>::encode(self, ( $($arg),* ), ( $($e2),* ))
                }
            }
        }
        op! { $Trait { $($rest)* } }
    };

    (
        $Trait:ident
        {
            $($arg:ident : $T:ty),* => if ($cond1:expr) {
                ($enc1:ty) $($e1:expr),*
            } else if ($cond2:expr) {
                ($enc2:ty) $($e2:expr),*
            } else {
                ($enc3:ty) $($e3:expr),*
            };
            $($rest:tt)*
        }
    ) => {
        impl<W> $Trait<$($T),*> for W where W: mitte_core::EmitSlice {
            fn emit(&mut self, $($arg: $T),*)
                -> std::result::Result<(), super::error::Error<W::Error>>
            {
                #![allow(unused_parens)]
                if $cond1 {
                    super::encoding::Encode::<$enc1, _>::encode(self, ( $($arg),* ), ( $($e1),* ))
                } else if $cond2 {
                    super::encoding::Encode::<$enc2, _>::encode(self, ( $($arg),* ), ( $($e2),* ))
                } else {
                    super::encoding::Encode::<$enc3, _>::encode(self, ( $($arg),* ), ( $($e3),* ))
                }
            }
        }
        op! { $Trait { $($rest)* } }
    };

    (
        $Trait:ident
        {
            $(<$($A:ident : $bound:ident),*>)*
            $($arg:ident : $T:ty),* => ($enc:ty) $($e:expr),*;
            $($rest:tt)*
        }
    ) => {
        impl<W $($(, $A)*)*> $Trait<$($T),*> for W
            where W: mitte_core::EmitSlice $($(, $A : $bound)*)*
        {
            fn emit(&mut self, $($arg: $T),*)
                -> std::result::Result<(), super::error::Error<W::Error>>
            {
                #![allow(unused_parens)]
                super::encoding::Encode::<$enc, _>::encode(self, ( $($arg),* ), ( $($e),* ))
            }
        }
        op! { $Trait { $($rest)* } }
    };

    (
        $Trait:ident => $R:ty
        {
            $($arg:ident : $T:ty),* => ($enc:ty) $($e:expr),*;
            $($rest:tt)*
        }
    ) => {
        impl<W> $Trait<$($T),*> for W where W: mitte_core::EmitSlice {
            type Return = $R;
            fn emit(&mut self, $($arg: $T),*)
                -> std::result::Result<$R, super::error::Error<W::Error>>
            {
                #![allow(unused_parens)]
                super::encoding::Encode::<$enc, _>::encode(self, ( $($arg),* ), ( $($e),* ))
            }
        }
        op! { $Trait => $R { $($rest)* } }
    };
}

pub(crate) use op;
