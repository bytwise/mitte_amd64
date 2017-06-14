macro_rules! op {
    ($Trait:ident {}) => {};
    ($Trait:ident => $R:ty {}) => {};

    (
        $Trait:ident
        {
            <$($A:ident : $bound:ident),*>
            $($arg:ident : $T:ty),* ; $($c:ident : $C:ty),* => $($e:expr),*;
            $($rest:tt)*
        }
    ) => {
        impl<W, $($A : $bound),*> $Trait<$($T),*> for W where W: ::EmitBytes {
            fn write(&mut self, $($c: $C),* $(, $arg: $T)*)
                -> ::std::result::Result<(), ::error::Error<W::Error>>
            {
                let mut buffer = ::buffer::Buffer::new();
                $(
                    try!(::buffer::Write::write(&mut buffer, $e));
                )*
                try!(self.write(&buffer));
                Ok(())
            }
        }
        op! { $Trait { $($rest)* } }
    };

    (
        $Trait:ident
        {
            $($arg:ident : $T:ty),* => $($e:expr),*;
            $($rest:tt)*
        }
    ) => {
        impl<W> $Trait<$($T),*> for W where W: ::EmitBytes {
            fn write(&mut self, $($arg: $T),*)
                -> ::std::result::Result<(), ::error::Error<W::Error>>
            {
                let mut buffer = ::buffer::Buffer::new();
                $(
                    try!(::buffer::Write::write(&mut buffer, $e));
                )*
                try!(self.write(&buffer));
                Ok(())
            }
        }
        op! { $Trait { $($rest)* } }
    };

    (
        $Trait:ident => $R:ty
        {
            $($arg:ident : $T:ty),* => $($e:expr),*;
            $($rest:tt)*
        }
    ) => {
        impl<W> $Trait<$($T),*> for W where W: ::EmitBytes {
            type Return = $R;
            fn write(&mut self, $($arg: $T),*)
                -> ::std::result::Result<$R, ::error::Error<W::Error>>
            {
                let mut buffer = ::buffer::Buffer::new();
                $(
                    try!(::buffer::Write::write(&mut buffer, $e));
                )*
                try!(self.write(&buffer));
                Ok(())
            }
        }
        op! { $Trait => $R { $($rest)* } }
    };
}


macro_rules! op_ptr {
    ($Trait:ident {}) => {};

    (
        $Trait:ident {
            <$($A:ident : $bound:ident),*>
            $ptr:ident : $Ptr:ident <..> $(, $arg:ident : $T:ident)* ; $($c:ident : $C:ty),* => $($e:expr),*;
            $($rest:tt)*
        }
    ) => {
        op! { $Trait {
            <$($A: $bound),*>
            $ptr: $Ptr<(), (), i8> $(, $arg: $T)* ; $($c: $C),* => $($e),*;
            <$($A: $bound),*>
            $ptr: $Ptr<(), (), i32> $(, $arg: $T)* ; $($c: $C),* => $($e),*;
            <$($A: $bound),*>
            $ptr: $Ptr<Reg64, (), ()> $(, $arg: $T)* ; $($c: $C),* => $($e),*;
            <$($A: $bound),*>
            $ptr: $Ptr<Reg64, (), i8> $(, $arg: $T)* ; $($c: $C),* => $($e),*;
            <$($A: $bound),*>
            $ptr: $Ptr<Reg64, (), i32> $(, $arg: $T)* ; $($c: $C),* => $($e),*;
            <$($A: $bound),*>
            $ptr: $Ptr<(), Scaled<Reg64>, ()> $(, $arg: $T)* ; $($c: $C),* => $($e),*;
            <$($A: $bound),*>
            $ptr: $Ptr<(), Scaled<Reg64>, i8> $(, $arg: $T)* ; $($c: $C),* => $($e),*;
            <$($A: $bound),*>
            $ptr: $Ptr<(), Scaled<Reg64>, i32> $(, $arg: $T)* ; $($c: $C),* => $($e),*;
            <$($A: $bound),*>
            $ptr: $Ptr<Reg64, Scaled<Reg64>, ()> $(, $arg: $T)* ; $($c: $C),* => $($e),*;
            <$($A: $bound),*>
            $ptr: $Ptr<Reg64, Scaled<Reg64>, i8> $(, $arg: $T)* ; $($c: $C),* => $($e),*;
            <$($A: $bound),*>
            $ptr: $Ptr<Reg64, Scaled<Reg64>, i32> $(, $arg: $T)* ; $($c: $C),* => $($e),*;
        }}
        op_ptr! { $Trait { $($rest)* } }
    };

    (
        $Trait:ident {
            <$($A:ident : $bound:ident),*>
            $arg:ident : $T:ident, $ptr:ident : $Ptr:ident <..> ; $($c:ident : $C:ty),* => $($e:expr),*;
            $($rest:tt)*
        }
    ) => {
        op! { $Trait {
            <$($A: $bound),*>
            $arg: $T, $ptr: $Ptr<(), (), i8> ; $($c: $C),* => $($e),*;
            <$($A: $bound),*>
            $arg: $T, $ptr: $Ptr<(), (), i32> ; $($c: $C),* => $($e),*;
            <$($A: $bound),*>
            $arg: $T, $ptr: $Ptr<Reg64, (), ()> ; $($c: $C),* => $($e),*;
            <$($A: $bound),*>
            $arg: $T, $ptr: $Ptr<Reg64, (), i8> ; $($c: $C),* => $($e),*;
            <$($A: $bound),*>
            $arg: $T, $ptr: $Ptr<Reg64, (), i32> ; $($c: $C),* => $($e),*;
            <$($A: $bound),*>
            $arg: $T, $ptr: $Ptr<(), Scaled<Reg64>, ()> ; $($c: $C),* => $($e),*;
            <$($A: $bound),*>
            $arg: $T, $ptr: $Ptr<(), Scaled<Reg64>, i8> ; $($c: $C),* => $($e),*;
            <$($A: $bound),*>
            $arg: $T, $ptr: $Ptr<(), Scaled<Reg64>, i32> ; $($c: $C),* => $($e),*;
            <$($A: $bound),*>
            $arg: $T, $ptr: $Ptr<Reg64, Scaled<Reg64>, ()> ; $($c: $C),* => $($e),*;
            <$($A: $bound),*>
            $arg: $T, $ptr: $Ptr<Reg64, Scaled<Reg64>, i8> ; $($c: $C),* => $($e),*;
            <$($A: $bound),*>
            $arg: $T, $ptr: $Ptr<Reg64, Scaled<Reg64>, i32> ; $($c: $C),* => $($e),*;
        }}
        op_ptr! { $Trait { $($rest)* } }
    };

    (
        $Trait:ident {
            $ptr:ident : $Ptr:ident <..> $(, $arg:ident : $T:ident)* => $($e:expr),*;
            $($rest:tt)*
        }
    ) => {
        op! { $Trait {
            $ptr: $Ptr<(), (), i8> $(, $arg: $T)* => $($e),*;
            $ptr: $Ptr<(), (), i32> $(, $arg: $T)* => $($e),*;
            $ptr: $Ptr<Reg64, (), ()> $(, $arg: $T)* => $($e),*;
            $ptr: $Ptr<Reg64, (), i8> $(, $arg: $T)* => $($e),*;
            $ptr: $Ptr<Reg64, (), i32> $(, $arg: $T)* => $($e),*;
            $ptr: $Ptr<(), Scaled<Reg64>, ()> $(, $arg: $T)* => $($e),*;
            $ptr: $Ptr<(), Scaled<Reg64>, i8> $(, $arg: $T)* => $($e),*;
            $ptr: $Ptr<(), Scaled<Reg64>, i32> $(, $arg: $T)* => $($e),*;
            $ptr: $Ptr<Reg64, Scaled<Reg64>, ()> $(, $arg: $T)* => $($e),*;
            $ptr: $Ptr<Reg64, Scaled<Reg64>, i8> $(, $arg: $T)* => $($e),*;
            $ptr: $Ptr<Reg64, Scaled<Reg64>, i32> $(, $arg: $T)* => $($e),*;
        }}
        op_ptr! { $Trait { $($rest)* } }
    };

    (
        $Trait:ident {
            $ptr:ident : $Ptr:ident <..> $(, $arg:ident : $T:ident)* ; $($c:ident : $C:ty),* => $($e:expr),*;
            $($rest:tt)*
        }
    ) => {
        op! { $Trait {
            $ptr: $Ptr<(), (), i8> $(, $arg: $T)* ; $($c: $C),* => $($e),*;
            $ptr: $Ptr<(), (), i32> $(, $arg: $T)* ; $($c: $C),* => $($e),*;
            $ptr: $Ptr<Reg64, (), ()> $(, $arg: $T)* ; $($c: $C),* => $($e),*;
            $ptr: $Ptr<Reg64, (), i8> $(, $arg: $T)* ; $($c: $C),* => $($e),*;
            $ptr: $Ptr<Reg64, (), i32> $(, $arg: $T)* ; $($c: $C),* => $($e),*;
            $ptr: $Ptr<(), Scaled<Reg64>, ()> $(, $arg: $T)* ; $($c: $C),* => $($e),*;
            $ptr: $Ptr<(), Scaled<Reg64>, i8> $(, $arg: $T)* ; $($c: $C),* => $($e),*;
            $ptr: $Ptr<(), Scaled<Reg64>, i32> $(, $arg: $T)* ; $($c: $C),* => $($e),*;
            $ptr: $Ptr<Reg64, Scaled<Reg64>, ()> $(, $arg: $T)* ; $($c: $C),* => $($e),*;
            $ptr: $Ptr<Reg64, Scaled<Reg64>, i8> $(, $arg: $T)* ; $($c: $C),* => $($e),*;
            $ptr: $Ptr<Reg64, Scaled<Reg64>, i32> $(, $arg: $T)* ; $($c: $C),* => $($e),*;
        }}
        op_ptr! { $Trait { $($rest)* } }
    };

    (
        $Trait:ident {
            $arg:ident : $T:ident, $ptr:ident : $Ptr:ident <..> => $($e:expr),*;
            $($rest:tt)*
        }
    ) => {
        op! { $Trait {
            $arg: $T, $ptr: $Ptr<(), (), i8> => $($e),*;
            $arg: $T, $ptr: $Ptr<(), (), i32> => $($e),*;
            $arg: $T, $ptr: $Ptr<Reg64, (), ()> => $($e),*;
            $arg: $T, $ptr: $Ptr<Reg64, (), i8> => $($e),*;
            $arg: $T, $ptr: $Ptr<Reg64, (), i32> => $($e),*;
            $arg: $T, $ptr: $Ptr<(), Scaled<Reg64>, ()> => $($e),*;
            $arg: $T, $ptr: $Ptr<(), Scaled<Reg64>, i8> => $($e),*;
            $arg: $T, $ptr: $Ptr<(), Scaled<Reg64>, i32> => $($e),*;
            $arg: $T, $ptr: $Ptr<Reg64, Scaled<Reg64>, ()> => $($e),*;
            $arg: $T, $ptr: $Ptr<Reg64, Scaled<Reg64>, i8> => $($e),*;
            $arg: $T, $ptr: $Ptr<Reg64, Scaled<Reg64>, i32> => $($e),*;
        }}
        op_ptr! { $Trait { $($rest)* } }
    };

    (
        $Trait:ident {
            $arg:ident : $T:ident, $ptr:ident : $Ptr:ident <..> ; $($c:ident : $C:ty),* => $($e:expr),*;
            $($rest:tt)*
        }
    ) => {
        op! { $Trait {
            $arg: $T, $ptr: $Ptr<(), (), i8> ; $($c: $C),* => $($e),*;
            $arg: $T, $ptr: $Ptr<(), (), i32> ; $($c: $C),* => $($e),*;
            $arg: $T, $ptr: $Ptr<Reg64, (), ()> ; $($c: $C),* => $($e),*;
            $arg: $T, $ptr: $Ptr<Reg64, (), i8> ; $($c: $C),* => $($e),*;
            $arg: $T, $ptr: $Ptr<Reg64, (), i32> ; $($c: $C),* => $($e),*;
            $arg: $T, $ptr: $Ptr<(), Scaled<Reg64>, ()> ; $($c: $C),* => $($e),*;
            $arg: $T, $ptr: $Ptr<(), Scaled<Reg64>, i8> ; $($c: $C),* => $($e),*;
            $arg: $T, $ptr: $Ptr<(), Scaled<Reg64>, i32> ; $($c: $C),* => $($e),*;
            $arg: $T, $ptr: $Ptr<Reg64, Scaled<Reg64>, ()> ; $($c: $C),* => $($e),*;
            $arg: $T, $ptr: $Ptr<Reg64, Scaled<Reg64>, i8> ; $($c: $C),* => $($e),*;
            $arg: $T, $ptr: $Ptr<Reg64, Scaled<Reg64>, i32> ; $($c: $C),* => $($e),*;
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


macro_rules! forward {
    ($Trait:ident {}) => {};

    (
        $Trait:ident {
            <$($A:ident : $bound:ident ),*>
            $($arg:ident : $T:ty),* => ( $f:path ) ( $($e:expr),* );
            $($rest:tt)*
        }
    ) => {
        impl<W, $($A : $bound),*> $Trait<$($T),*> for W where W: ::EmitBytes {
            fn write(&mut self, $($arg: $T),*)
                -> ::std::result::Result<(), ::error::Error<W::Error>>
            {
                $f(self, $($e),*)
            }
        }
        forward! { $Trait { $($rest)* } }
    };

    ($Trait:ident {
        $($arg:ident : $T:ty),* => ( $f:path ) ( $($e:expr),* );
        $($rest:tt)*
    }) => {
        impl<W> $Trait<$($T),*> for W where W: ::EmitBytes {
            fn write(&mut self, $($arg: $T),*)
                -> ::std::result::Result<(), ::error::Error<W::Error>>
            {
                $f(self, $($e),*)
            }
        }
        forward! { $Trait { $($rest)* } }
    };

    (
        $Trait:ident {
            $($arg:ident : $T:ty),* ; $($c:ident : $C:ty),* => ( $f:path ) ( $($e:expr),* );
            $($rest:tt)*
        }
    ) => {
        impl<W> $Trait<$($T),*> for W where W: ::EmitBytes {
            fn write(&mut self, $($c: $C,)* $($arg: $T),*)
                -> ::std::result::Result<(), ::error::Error<W::Error>>
            {
                $f(self, $($e),*)
            }
        }
        forward! { $Trait { $($rest)* } }
    };
}


macro_rules! forward_ptr {
    ($Trait:ident {}) => {};

    ($Trait:ident {
        $ptr:ident : $Ptr:ident <..> => ( $f:path ) ( $($e:expr),* );
        $($rest:tt)*
    }) => {
        forward! { $Trait {
            $ptr: $Ptr<(), (), i8> => ($f)($($e),*);
            $ptr: $Ptr<(), (), i32> => ($f)($($e),*);
            $ptr: $Ptr<Reg64, (), ()> => ($f)($($e),*);
            $ptr: $Ptr<Reg64, (), i8> => ($f)($($e),*);
            $ptr: $Ptr<Reg64, (), i32> => ($f)($($e),*);
            $ptr: $Ptr<(), Scaled<Reg64>, ()> => ($f)($($e),*);
            $ptr: $Ptr<(), Scaled<Reg64>, i8> => ($f)($($e),*);
            $ptr: $Ptr<(), Scaled<Reg64>, i32> => ($f)($($e),*);
            $ptr: $Ptr<Reg64, Scaled<Reg64>, ()> => ($f)($($e),*);
            $ptr: $Ptr<Reg64, Scaled<Reg64>, i8> => ($f)($($e),*);
            $ptr: $Ptr<Reg64, Scaled<Reg64>, i32> => ($f)($($e),*);
        }}
        forward_ptr! { $Trait { $($rest)* } }
    };

    ($Trait:ident {
        $ptr:ident : $Ptr:ident <..>, $($arg:ident : $T:ty),* => ( $f:path ) ( $($e:expr),* );
        $($rest:tt)*
    }) => {
        forward! { $Trait {
            $ptr: $Ptr<(), (), i8> $(, $arg : $T)* => ($f)($($e),*);
            $ptr: $Ptr<(), (), i32> $(, $arg : $T)* => ($f)($($e),*);
            $ptr: $Ptr<Reg64, (), ()> $(, $arg : $T)* => ($f)($($e),*);
            $ptr: $Ptr<Reg64, (), i8> $(, $arg : $T)* => ($f)($($e),*);
            $ptr: $Ptr<Reg64, (), i32> $(, $arg : $T)* => ($f)($($e),*);
            $ptr: $Ptr<(), Scaled<Reg64>, ()> $(, $arg : $T)* => ($f)($($e),*);
            $ptr: $Ptr<(), Scaled<Reg64>, i8> $(, $arg : $T)* => ($f)($($e),*);
            $ptr: $Ptr<(), Scaled<Reg64>, i32> $(, $arg : $T)* => ($f)($($e),*);
            $ptr: $Ptr<Reg64, Scaled<Reg64>, ()> $(, $arg : $T)* => ($f)($($e),*);
            $ptr: $Ptr<Reg64, Scaled<Reg64>, i8> $(, $arg : $T)* => ($f)($($e),*);
            $ptr: $Ptr<Reg64, Scaled<Reg64>, i32> $(, $arg : $T)* => ($f)($($e),*);
        }}
        forward_ptr! { $Trait { $($rest)* } }
    };

    ($Trait:ident {
        $ptr:ident : $Ptr:ident <..>, $($arg:ident : $T:ty),* ; $($c:ident : $C:ty),* => ( $f:path ) ( $($e:expr),* );
        $($rest:tt)*
    }) => {
        forward! { $Trait {
            $ptr: $Ptr<(), (), i8> $(, $arg : $T)*; $($c: $C),* => ($f)($($e),*);
            $ptr: $Ptr<(), (), i32> $(, $arg : $T)*; $($c: $C),* => ($f)($($e),*);
            $ptr: $Ptr<Reg64, (), ()> $(, $arg : $T)*; $($c: $C),* => ($f)($($e),*);
            $ptr: $Ptr<Reg64, (), i8> $(, $arg : $T)*; $($c: $C),* => ($f)($($e),*);
            $ptr: $Ptr<Reg64, (), i32> $(, $arg : $T)*; $($c: $C),* => ($f)($($e),*);
            $ptr: $Ptr<(), Scaled<Reg64>, ()> $(, $arg : $T)*; $($c: $C),* => ($f)($($e),*);
            $ptr: $Ptr<(), Scaled<Reg64>, i8> $(, $arg : $T)*; $($c: $C),* => ($f)($($e),*);
            $ptr: $Ptr<(), Scaled<Reg64>, i32> $(, $arg : $T)*; $($c: $C),* => ($f)($($e),*);
            $ptr: $Ptr<Reg64, Scaled<Reg64>, ()> $(, $arg : $T)*; $($c: $C),* => ($f)($($e),*);
            $ptr: $Ptr<Reg64, Scaled<Reg64>, i8> $(, $arg : $T)*; $($c: $C),* => ($f)($($e),*);
            $ptr: $Ptr<Reg64, Scaled<Reg64>, i32> $(, $arg : $T)*; $($c: $C),* => ($f)($($e),*);
        }}
        forward_ptr! { $Trait { $($rest)* } }
    };

    ($Trait:ident {
        $arg:ident : $T:ty, $ptr:ident : $Ptr:ident <..> => ( $f:path ) ( $($e:expr),* );
        $($rest:tt)*
    }) => {
        forward! { $Trait {
            $arg: $T, $ptr: $Ptr<(), (), i8> => ($f)($($e),*);
            $arg: $T, $ptr: $Ptr<(), (), i32> => ($f)($($e),*);
            $arg: $T, $ptr: $Ptr<Reg64, (), ()> => ($f)($($e),*);
            $arg: $T, $ptr: $Ptr<Reg64, (), i8> => ($f)($($e),*);
            $arg: $T, $ptr: $Ptr<Reg64, (), i32> => ($f)($($e),*);
            $arg: $T, $ptr: $Ptr<(), Scaled<Reg64>, ()> => ($f)($($e),*);
            $arg: $T, $ptr: $Ptr<(), Scaled<Reg64>, i8> => ($f)($($e),*);
            $arg: $T, $ptr: $Ptr<(), Scaled<Reg64>, i32> => ($f)($($e),*);
            $arg: $T, $ptr: $Ptr<Reg64, Scaled<Reg64>, ()> => ($f)($($e),*);
            $arg: $T, $ptr: $Ptr<Reg64, Scaled<Reg64>, i8> => ($f)($($e),*);
            $arg: $T, $ptr: $Ptr<Reg64, Scaled<Reg64>, i32> => ($f)($($e),*);
        }}
        forward_ptr! { $Trait { $($rest)* } }
    };

    ($Trait:ident {
        $arg:ident : $T:ty, $ptr:ident : $Ptr:ident <..> ; $($c:ident : $C:ty),* => ( $f:path ) ( $($e:expr),* );
        $($rest:tt)*
    }) => {
        forward! { $Trait {
            $arg: $T, $ptr: $Ptr<(), (), i8>; $($c: $C),* => ($f)($($e),*);
            $arg: $T, $ptr: $Ptr<(), (), i32>; $($c: $C),* => ($f)($($e),*);
            $arg: $T, $ptr: $Ptr<Reg64, (), ()>; $($c: $C),* => ($f)($($e),*);
            $arg: $T, $ptr: $Ptr<Reg64, (), i8>; $($c: $C),* => ($f)($($e),*);
            $arg: $T, $ptr: $Ptr<Reg64, (), i32>; $($c: $C),* => ($f)($($e),*);
            $arg: $T, $ptr: $Ptr<(), Scaled<Reg64>, ()>; $($c: $C),* => ($f)($($e),*);
            $arg: $T, $ptr: $Ptr<(), Scaled<Reg64>, i8>; $($c: $C),* => ($f)($($e),*);
            $arg: $T, $ptr: $Ptr<(), Scaled<Reg64>, i32>; $($c: $C),* => ($f)($($e),*);
            $arg: $T, $ptr: $Ptr<Reg64, Scaled<Reg64>, ()>; $($c: $C),* => ($f)($($e),*);
            $arg: $T, $ptr: $Ptr<Reg64, Scaled<Reg64>, i8>; $($c: $C),* => ($f)($($e),*);
            $arg: $T, $ptr: $Ptr<Reg64, Scaled<Reg64>, i32>; $($c: $C),* => ($f)($($e),*);
        }}
        forward_ptr! { $Trait { $($rest)* } }
    };
}
