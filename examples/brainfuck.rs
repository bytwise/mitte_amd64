extern crate mitte_amd64;
extern crate memmap;

use std::fs::File;
use std::io::{self, Read, Write, Cursor, Stdin, Stdout};
use std::mem;

use mitte_amd64::Emit;
use mitte_amd64::reg::*;
use mitte_amd64::{word_ptr, qword_ptr};
use mitte_amd64::label::{BindLabel, Label};

use memmap::{Mmap, Protection};


fn main() {
    let mut args = std::env::args();
    if args.len() != 2 {
        println!("Usage: {} <file>", args.next().unwrap());
        return;
    }
    let _program = args.next().unwrap();
    let path = args.next().unwrap();

    let mut file = File::open(path).unwrap();

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();

    let mut brackets = Vec::new();
    let mut code_map = Mmap::anonymous(16 * 4096, Protection::ReadWrite).unwrap();

    {
        let mut code = unsafe {
            Cursor::new(code_map.as_mut_slice())
        };

        // function prologue
        code.emit_push(Rbp).unwrap();
        code.emit_mov(Rbp, Rsp).unwrap();
        code.emit_sub(Rsp, 32u8).unwrap();

        // `rax` will contain the data pointer
        code.emit_xor(Rax, Rax).unwrap();

        // `rcx` will be a pointer to the tape
        // `rdx` will be a pointer to the InOut struct

        for &b in &buffer {
            match b {
                b'>' => {
                    // use `ax` so that it wraps around after 0xffff to 0
                    code.emit_inc(Ax).unwrap();
                }
                b'<' => {
                    // use `ax` so that it wraps around after 0 to 0xffff
                    code.emit_dec(Ax).unwrap();
                }
                b'+' => {
                    code.emit_inc(word_ptr(Rcx + Rax * 2)).unwrap();
                }
                b'-' => {
                    code.emit_dec(word_ptr(Rcx + Rax * 2)).unwrap();
                }
                b'.' => {
                    // save `rax`, `rcx` and `rdx` on stack
                    code.emit_mov(qword_ptr(Rbp - 8), Rax).unwrap();
                    code.emit_mov(qword_ptr(Rbp - 16), Rcx).unwrap();
                    code.emit_mov(qword_ptr(Rbp - 24), Rdx).unwrap();

                    // set parameters and call `putchar`
                    code.emit_mov(Dx, word_ptr(Rcx + Rax * 2)).unwrap();
                    code.emit_mov(Rcx, qword_ptr(Rbp - 24)).unwrap();
                    code.emit_mov(Rax, putchar as u64).unwrap();
                    code.emit_call(Rax).unwrap();

                    // restore `rax`, `rcx` and `rdx` from stack
                    code.emit_mov(Rax, qword_ptr(Rbp - 8)).unwrap();
                    code.emit_mov(Rcx, qword_ptr(Rbp - 16)).unwrap();
                    code.emit_mov(Rdx, qword_ptr(Rbp - 24)).unwrap();
                }
                b',' => {
                    // save `rax`, `rcx` and `rdx` on stack
                    code.emit_mov(qword_ptr(Rbp - 8), Rax).unwrap();
                    code.emit_mov(qword_ptr(Rbp - 16), Rcx).unwrap();
                    code.emit_mov(qword_ptr(Rbp - 24), Rdx).unwrap();

                    // set parameters and call `getchar`
                    code.emit_mov(Rcx, Rdx).unwrap();
                    code.emit_mov(Rax, getchar as u64).unwrap();
                    code.emit_call(Rax).unwrap();
                    code.emit_movzx(Dx, Al).unwrap();

                    // restore `rax` and `rcx` from stack
                    code.emit_mov(Rax, qword_ptr(Rbp - 8)).unwrap();
                    code.emit_mov(Rcx, qword_ptr(Rbp - 16)).unwrap();

                    // save return value on tape
                    code.emit_mov(word_ptr(Rcx + Rax * 2), Dx).unwrap();

                    // restore `rdx` from stack
                    code.emit_mov(Rdx, qword_ptr(Rbp - 24)).unwrap();
                }
                b'[' => {
                    let mut start_label = Label::new();
                    let mut end_label = Label::new();

                    code.emit_cmp(word_ptr(Rcx + Rax * 2), 0).unwrap();
                    code.emit_jz(&mut end_label).unwrap();
                    code.bind_label(&mut start_label).unwrap();

                    brackets.push((start_label, end_label));
                }
                b']' => {
                    let (mut start_label, mut end_label) = brackets.pop().unwrap();
                    code.emit_cmp(word_ptr(Rcx + Rax * 2), 0).unwrap();
                    code.emit_jnz(&mut start_label).unwrap();
                    code.bind_label(&mut end_label).unwrap();
                }
                _ => {}
            }
        }

        // function epilogue
        code.emit_add(Rsp, 32u8).unwrap();
        code.emit_pop(Rbp).unwrap();
        code.emit_ret().unwrap();
    }

    code_map.set_protection(Protection::ReadExecute).unwrap();

    unsafe {
        let mut tape = vec![0u64; 0x1_0000];
        let mut in_out = InOut {
            stdin: io::stdin(),
            stdout: io::stdout(),
        };

        let f: extern "win64" fn(*mut u64, *mut InOut) = mem::transmute(code_map.ptr());
        f(tape.as_mut_ptr(), &mut in_out);
    }
}


struct InOut {
    stdin: Stdin,
    stdout: Stdout,
}


extern "win64" fn putchar(in_out: *mut InOut, c: u8) {
    unsafe {
        let _ = (*in_out).stdout.write_all(&[c]);
    }
}

extern "win64" fn getchar(in_out: *mut InOut) -> u8 {
    unsafe {
        let mut buf = [0];
        let _ = (*in_out).stdin.read_exact(&mut buf);
        buf[0]
    }
}
