macro_rules! op {
    ($Trait:ident {}) => {};
    ($Trait:ident => $R:ty {}) => {};

    (
        $Trait:ident
        {
            $($arg:ident : $T:ty),+
                ; assert_eq!($assert_e1:expr, $assert_e2:expr)
                => ($enc:ty) $($e:expr),*;
            $($rest:tt)*
        }
    ) => {
        impl<W> $Trait<$($T),*> for W where W: ::EmitBytes {
            fn write(&mut self, $($arg: $T),*)
                -> ::std::result::Result<(), ::error::Error<W::Error>>
            {
                assert_eq!($assert_e1, $assert_e2);
                ::encode::Encode::<$enc, _>::encode(self, ( $($arg),* ), ( $($e),* ))
            }
        }
        op! { $Trait { $($rest)* } }
    };

    (
        $Trait:ident
        {
            $($arg:ident : $T:ty),* => if ($cond:expr) {
                ($enc1:ty) $($e1:expr),*
            } else {
                ($enc2:ty) $($e2:expr),*
            };
            $($rest:tt)*
        }
    ) => {
        impl<W> $Trait<$($T),*> for W where W: ::EmitBytes {
            fn write(&mut self, $($arg: $T),*)
                -> ::std::result::Result<(), ::error::Error<W::Error>>
            {
                if $cond {
                    ::encode::Encode::<$enc1, _>::encode(self, ( $($arg),* ), ( $($e1),* ))
                } else {
                    ::encode::Encode::<$enc2, _>::encode(self, ( $($arg),* ), ( $($e2),* ))
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
        impl<W> $Trait<$($T),*> for W where W: ::EmitBytes {
            fn write(&mut self, $($arg: $T),*)
                -> ::std::result::Result<(), ::error::Error<W::Error>>
            {
                if $cond1 {
                    ::encode::Encode::<$enc1, _>::encode(self, ( $($arg),* ), ( $($e1),* ))
                } else if $cond2 {
                    ::encode::Encode::<$enc2, _>::encode(self, ( $($arg),* ), ( $($e2),* ))
                } else {
                    ::encode::Encode::<$enc3, _>::encode(self, ( $($arg),* ), ( $($e3),* ))
                }
            }
        }
        op! { $Trait { $($rest)* } }
    };

    (
        $Trait:ident
        {
            $($arg:ident : $T:ty),* => ($enc:ty) $($e:expr),*;
            $($rest:tt)*
        }
    ) => {
        impl<W> $Trait<$($T),*> for W where W: ::EmitBytes {
            fn write(&mut self, $($arg: $T),*)
                -> ::std::result::Result<(), ::error::Error<W::Error>>
            {
                ::encode::Encode::<$enc, _>::encode(self, ( $($arg),* ), ( $($e),* ))
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
        impl<W> $Trait<$($T),*> for W where W: ::EmitBytes {
            type Return = $R;
            fn write(&mut self, $($arg: $T),*)
                -> ::std::result::Result<$R, ::error::Error<W::Error>>
            {
                ::encode::Encode::<$enc, _>::encode(self, ( $($arg),* ), ( $($e),* ))
            }
        }
        op! { $Trait => $R { $($rest)* } }
    };
}


macro_rules! op_ptr {
    ($Trait:ident {}) => {};

    (
        $Trait:ident {
            $ptr:ident : $Ptr:ident <..> $(, $arg:ident : $T:ident)* => ($enc:ty) $($e:expr),*;
            $($rest:tt)*
        }
    ) => {
        op! { $Trait {
            $ptr: $Ptr<(), (), i8> $(, $arg: $T)* => ($enc) $($e),*;
            $ptr: $Ptr<(), (), i32> $(, $arg: $T)* => ($enc) $($e),*;
            $ptr: $Ptr<Reg64, (), ()> $(, $arg: $T)* => ($enc) $($e),*;
            $ptr: $Ptr<Reg64, (), i8> $(, $arg: $T)* => ($enc) $($e),*;
            $ptr: $Ptr<Reg64, (), i32> $(, $arg: $T)* => ($enc) $($e),*;
            $ptr: $Ptr<(), Scaled<Reg64>, ()> $(, $arg: $T)* => ($enc) $($e),*;
            $ptr: $Ptr<(), Scaled<Reg64>, i8> $(, $arg: $T)* => ($enc) $($e),*;
            $ptr: $Ptr<(), Scaled<Reg64>, i32> $(, $arg: $T)* => ($enc) $($e),*;
            $ptr: $Ptr<Reg64, Scaled<Reg64>, ()> $(, $arg: $T)* => ($enc) $($e),*;
            $ptr: $Ptr<Reg64, Scaled<Reg64>, i8> $(, $arg: $T)* => ($enc) $($e),*;
            $ptr: $Ptr<Reg64, Scaled<Reg64>, i32> $(, $arg: $T)* => ($enc) $($e),*;
        }}
        op_ptr! { $Trait { $($rest)* } }
    };

    (
        $Trait:ident {
            $arg:ident : $T:ident, $ptr:ident : $Ptr:ident <..> => ($enc:ty) $($e:expr),*;
            $($rest:tt)*
        }
    ) => {
        op! { $Trait {
            $arg: $T, $ptr: $Ptr<(), (), i8> => ($enc) $($e),*;
            $arg: $T, $ptr: $Ptr<(), (), i32> => ($enc) $($e),*;
            $arg: $T, $ptr: $Ptr<Reg64, (), ()> => ($enc) $($e),*;
            $arg: $T, $ptr: $Ptr<Reg64, (), i8> => ($enc) $($e),*;
            $arg: $T, $ptr: $Ptr<Reg64, (), i32> => ($enc) $($e),*;
            $arg: $T, $ptr: $Ptr<(), Scaled<Reg64>, ()> => ($enc) $($e),*;
            $arg: $T, $ptr: $Ptr<(), Scaled<Reg64>, i8> => ($enc) $($e),*;
            $arg: $T, $ptr: $Ptr<(), Scaled<Reg64>, i32> => ($enc) $($e),*;
            $arg: $T, $ptr: $Ptr<Reg64, Scaled<Reg64>, ()> => ($enc) $($e),*;
            $arg: $T, $ptr: $Ptr<Reg64, Scaled<Reg64>, i8> => ($enc) $($e),*;
            $arg: $T, $ptr: $Ptr<Reg64, Scaled<Reg64>, i32> => ($enc) $($e),*;
        }}
        op_ptr! { $Trait { $($rest)* } }
    };
}


macro_rules! dispatch_ptr {
    ($Trait:ident {}) => {};

    (
        $Trait:ident {
            @$Ptr:ty $(, $T:ident)* => $ptr:ident;
            $($rest:tt)*
        }
    ) => {
        impl<W> $Trait<$Ptr $(, $T)*> for W where W: ::EmitBytes {
            #[allow(non_snake_case)]
            fn write(&mut self, ptr: $Ptr $(, $T: $T)*)
                -> ::std::result::Result<(), ::error::Error<W::Error>>
            {
                use ::ptr::Pointer;
                match ptr.ptr {
                    Pointer::Disp8(d) => {
                        $Trait::write(self, $ptr { ptr: Ptr::new((), (), d) } $(, $T)*)
                    }
                    Pointer::Disp32(d) => {
                        $Trait::write(self, $ptr { ptr: Ptr::new((), (), d) } $(, $T)*)
                    }
                    Pointer::Base(b) => {
                        $Trait::write(self, $ptr { ptr: Ptr::new(b, (), ()) } $(, $T)*)
                    }
                    Pointer::BaseDisp8(b, d) => {
                        $Trait::write(self, $ptr { ptr: Ptr::new(b, (), d) } $(, $T)*)
                    }
                    Pointer::BaseDisp32(b, d) => {
                        $Trait::write(self, $ptr { ptr: Ptr::new(b, (), d) } $(, $T)*)
                    }
                    Pointer::Index(x) => {
                        $Trait::write(self, $ptr { ptr: Ptr::new((), x, ()) } $(, $T)*)
                    }
                    Pointer::IndexDisp8(x, d) => {
                        $Trait::write(self, $ptr { ptr: Ptr::new((), x, d) } $(, $T)*)
                    }
                    Pointer::IndexDisp32(x, d) => {
                        $Trait::write(self, $ptr { ptr: Ptr::new((), x, d) } $(, $T)*)
                    }
                    Pointer::BaseIndex(b, x) => {
                        $Trait::write(self, $ptr { ptr: Ptr::new(b, x, ()) } $(, $T)*)
                    }
                    Pointer::BaseIndexDisp8(b, x, d) => {
                        $Trait::write(self, $ptr { ptr: Ptr::new(b, x, d) } $(, $T)*)
                    }
                    Pointer::BaseIndexDisp32(b, x, d) => {
                        $Trait::write(self, $ptr { ptr: Ptr::new(b, x, d) } $(, $T)*)
                    }
                }
            }
        }
        dispatch_ptr! { $Trait { $($rest)* } }
    };

    (
        $Trait:ident {
            $T:ident, @$Ptr:ty => $ptr:ident;
            $($rest:tt)*
        }
    ) => {
        impl<W> $Trait<$T, $Ptr> for W where W: ::EmitBytes {
            #[allow(non_snake_case)]
            fn write(&mut self, arg: $T, ptr: $Ptr)
                -> ::std::result::Result<(), ::error::Error<W::Error>>
            {
                use ::ptr::Pointer;
                match ptr.ptr {
                    Pointer::Disp8(d) => {
                        $Trait::write(self, arg, $ptr { ptr: Ptr::new((), (), d) })
                    }
                    Pointer::Disp32(d) => {
                        $Trait::write(self, arg, $ptr { ptr: Ptr::new((), (), d) })
                    }
                    Pointer::Base(b) => {
                        $Trait::write(self, arg, $ptr { ptr: Ptr::new(b, (), ()) })
                    }
                    Pointer::BaseDisp8(b, d) => {
                        $Trait::write(self, arg, $ptr { ptr: Ptr::new(b, (), d) })
                    }
                    Pointer::BaseDisp32(b, d) => {
                        $Trait::write(self, arg, $ptr { ptr: Ptr::new(b, (), d) })
                    }
                    Pointer::Index(x) => {
                        $Trait::write(self, arg, $ptr { ptr: Ptr::new((), x, ()) })
                    }
                    Pointer::IndexDisp8(x, d) => {
                        $Trait::write(self, arg, $ptr { ptr: Ptr::new((), x, d) })
                    }
                    Pointer::IndexDisp32(x, d) => {
                        $Trait::write(self, arg, $ptr { ptr: Ptr::new((), x, d) })
                    }
                    Pointer::BaseIndex(b, x) => {
                        $Trait::write(self, arg, $ptr { ptr: Ptr::new(b, x, ()) })
                    }
                    Pointer::BaseIndexDisp8(b, x, d) => {
                        $Trait::write(self, arg, $ptr { ptr: Ptr::new(b, x, d) })
                    }
                    Pointer::BaseIndexDisp32(b, x, d) => {
                        $Trait::write(self, arg, $ptr { ptr: Ptr::new(b, x, d) })
                    }
                }
            }
        }
        dispatch_ptr! { $Trait { $($rest)* } }
    };
}
