extern crate mitte_amd64;
extern crate capstone;

use mitte_amd64::{Emit, Error};
use mitte_amd64::reg::*;
use mitte_amd64::operand::{Operand, byte_pointer, word_pointer, dword_pointer, qword_pointer};

use capstone::Capstone;
use capstone::arch::BuildsCapstone;
use capstone::arch::x86::ArchMode;

type Result<T> = std::result::Result<T, Error<std::io::Error>>;


const REGS8: [(Reg8, &'static str); 20] = [
    (Al, "al"),
    (Cl, "cl"),
    (Dl, "dl"),
    (Bl, "bl"),
    (Ah, "ah"),
    (Ch, "ch"),
    (Dh, "dh"),
    (Bh, "bh"),
    (R8b, "r8b"),
    (R9b, "r9b"),
    (R10b, "r10b"),
    (R11b, "r11b"),
    (R12b, "r12b"),
    (R13b, "r13b"),
    (R14b, "r14b"),
    (R15b, "r15b"),
    (Spl, "spl"),
    (Bpl, "bpl"),
    (Sil, "sil"),
    (Dil, "dil"),
];

const SIMPLE_REGS8: [(Reg8, &'static str); 8] = [
    (Al, "al"),
    (Cl, "cl"),
    (Dl, "dl"),
    (Bl, "bl"),
    (Ah, "ah"),
    (Ch, "ch"),
    (Dh, "dh"),
    (Bh, "bh"),
];

const REX_REGS8: [(Reg8, &'static str); 12] = [
    (Al, "al"),
    (Cl, "cl"),
    (Dl, "dl"),
    (Bl, "bl"),
    (R8b, "r8b"),
    (R9b, "r9b"),
    (R10b, "r10b"),
    (R11b, "r11b"),
    (R12b, "r12b"),
    (R13b, "r13b"),
    (R14b, "r14b"),
    (R15b, "r15b"),
];

const REGS16: [(Reg16, &'static str); 16] = [
    (Ax, "ax"),
    (Cx, "cx"),
    (Dx, "dx"),
    (Bx, "bx"),
    (Sp, "sp"),
    (Bp, "bp"),
    (Si, "si"),
    (Di, "di"),
    (R8w, "r8w"),
    (R9w, "r9w"),
    (R10w, "r10w"),
    (R11w, "r11w"),
    (R12w, "r12w"),
    (R13w, "r13w"),
    (R14w, "r14w"),
    (R15w, "r15w"),
];

const SIMPLE_REGS16: [(Reg16, &'static str); 8] = [
    (Ax, "ax"),
    (Cx, "cx"),
    (Dx, "dx"),
    (Bx, "bx"),
    (Sp, "sp"),
    (Bp, "bp"),
    (Si, "si"),
    (Di, "di"),
];

const REGS32: [(Reg32, &'static str); 16] = [
    (Eax, "eax"),
    (Ecx, "ecx"),
    (Edx, "edx"),
    (Ebx, "ebx"),
    (Esp, "esp"),
    (Ebp, "ebp"),
    (Esi, "esi"),
    (Edi, "edi"),
    (R8d, "r8d"),
    (R9d, "r9d"),
    (R10d, "r10d"),
    (R11d, "r11d"),
    (R12d, "r12d"),
    (R13d, "r13d"),
    (R14d, "r14d"),
    (R15d, "r15d"),
];

const SIMPLE_REGS32: [(Reg32, &'static str); 8] = [
    (Eax, "eax"),
    (Ecx, "ecx"),
    (Edx, "edx"),
    (Ebx, "ebx"),
    (Esp, "esp"),
    (Ebp, "ebp"),
    (Esi, "esi"),
    (Edi, "edi"),
];

const REGS64: [(Reg64, &'static str); 16] = [
    (Rax, "rax"),
    (Rcx, "rcx"),
    (Rdx, "rdx"),
    (Rbx, "rbx"),
    (Rsp, "rsp"),
    (Rbp, "rbp"),
    (Rsi, "rsi"),
    (Rdi, "rdi"),
    (R8, "r8"),
    (R9, "r9"),
    (R10, "r10"),
    (R11, "r11"),
    (R12, "r12"),
    (R13, "r13"),
    (R14, "r14"),
    (R15, "r15"),
];

const SIMPLE_REGS64: [(Reg64, &'static str); 8] = [
    (Rax, "rax"),
    (Rcx, "rcx"),
    (Rdx, "rdx"),
    (Rbx, "rbx"),
    (Rsp, "rsp"),
    (Rbp, "rbp"),
    (Rsi, "rsi"),
    (Rdi, "rdi"),
];


fn print_code(code: &[u8]) {
    print!("[");
    for b in code {
        print!("{:02x}", b);
    }
    println!("]");
}


fn test_disasm<S>(mnemonic: &str, expected: &[Option<S>], code: &[u8]) where S: AsRef<str> {
    let capstone = Capstone::new().x86().mode(ArchMode::Mode64).build().unwrap();
    let disasm = match capstone.disasm_all(code, 0x0) {
        Ok(disasm) => disasm,
        Err(error) => {
            print_code(code);
            panic!("failed to disassemble: {:?}", error);
        }
    };

    for (i, e) in disasm.iter().zip(expected) {
        println!("bytes: {:?}", i.bytes());
        assert_eq!(mnemonic, i.mnemonic().unwrap());
        assert_eq!(e.as_ref().map(S::as_ref), i.op_str(),
            "{} {:?} != {0} {:?}", mnemonic,
            e.as_ref().map(S::as_ref).unwrap(), i.op_str().unwrap());
    }
    assert_eq!(disasm.len() as usize, expected.len());
}


fn test_reg<'a, F, RS, AF, DF, R, T, S>(mnemonic: &str, f: F, regs: RS, arg: AF, disasm: DF)
    where F: Fn(&mut Vec<u8>, T) -> Result<()>,
          RS: AsRef<[(R, &'static str)]>,
          AF: Fn(R) -> T,
          DF: Fn(&'a str) -> S,
          R: Copy,
          S: 'a + AsRef<str>
{
    let mut code = Vec::new();

    for &(r, _) in regs.as_ref() {
        f(&mut code, arg(r)).unwrap();
    }

    print_code(&code);

    let mut expected_disasm = Vec::new();

    for &(_, s) in regs.as_ref() {
        expected_disasm.push(Some(disasm(s)));
    }

    test_disasm(mnemonic, &expected_disasm, &code);
}

fn test_reg_reg<'a, F, RS1, RS2, AF, DF, R1, R2, T, S>(mnemonic: &str, f: F, regs1: RS1, regs2: RS2, arg: AF, disasm: DF)
    where F: Fn(&mut Vec<u8>, T) -> Result<()>,
          RS1: AsRef<[(R1, &'static str)]>,
          RS2: AsRef<[(R2, &'static str)]>,
          AF: Fn(R1, R2) -> T,
          DF: Fn(&'a str, &'a str) -> S,
          R1: Copy,
          R2: Copy,
          S: 'a + AsRef<str>
{
    let mut code = Vec::new();

    for &(r1, _) in regs1.as_ref() {
        for &(r2, _) in regs2.as_ref() {
            f(&mut code, arg(r1, r2)).unwrap();
        }
    }

    print_code(&code);

    let mut expected_disasm = Vec::new();

    for &(_, s1) in regs1.as_ref() {
        for &(_, s2) in regs2.as_ref() {
            expected_disasm.push(Some(disasm(s1, s2)));
        }
    }

    test_disasm(mnemonic, &expected_disasm, &code);
}

fn test_reg_reg_reg<'a, F, RS1, RS2, RS3, AF, DF, R1, R2, R3, T, S>(mnemonic: &str, f: F, regs1: RS1, regs2: RS2, regs3: RS3, arg: AF, disasm: DF)
    where F: Fn(&mut Vec<u8>, T) -> Result<()>,
          RS1: AsRef<[(R1, &'static str)]>,
          RS2: AsRef<[(R2, &'static str)]>,
          RS3: AsRef<[(R3, &'static str)]>,
          AF: Fn(R1, R2, R3) -> T,
          DF: Fn(&'a str, &'a str, &'a str) -> S,
          R1: Copy,
          R2: Copy,
          R3: Copy,
          S: 'a + AsRef<str>
{
    let mut code = Vec::new();

    for &(r1, _) in regs1.as_ref() {
        for &(r2, _) in regs2.as_ref() {
            for &(r3, _) in regs3.as_ref() {
                f(&mut code, arg(r1, r2, r3)).unwrap();
            }
        }
    }

    print_code(&code);

    let mut expected_disasm = Vec::new();

    for &(_, s1) in regs1.as_ref() {
        for &(_, s2) in regs2.as_ref() {
            for &(_, s3) in regs3.as_ref() {
                expected_disasm.push(Some(disasm(s1, s2, s3)));
            }
        }
    }

    test_disasm(mnemonic, &expected_disasm, &code);
}


fn test_unit(mnemonic: &str, f: fn(&mut Vec<u8>) -> Result<()>) {
    let mut code = Vec::new();
    f(&mut code).unwrap();
    let expected_disasm = vec![Some("")];
    test_disasm(mnemonic, &expected_disasm, &code);
}


fn test_imm8(mnemonic: &str, f: fn(&mut Vec<u8>, Operand) -> Result<()>) {
    let mut code = Vec::new();
    f(&mut code, Operand::Imm8(0x42)).unwrap();
    let expected_disasm = vec![Some("0x42")];
    test_disasm(mnemonic, &expected_disasm, &code);
}

fn test_imm16(mnemonic: &str, f: fn(&mut Vec<u8>, Operand) -> Result<()>) {
    let mut code = Vec::new();
    f(&mut code, Operand::Imm16(0x1234)).unwrap();
    let expected_disasm = vec![Some("0x1234")];
    test_disasm(mnemonic, &expected_disasm, &code);
}

fn test_imm32(mnemonic: &str, f: fn(&mut Vec<u8>, Operand) -> Result<()>) {
    let mut code = Vec::new();
    f(&mut code, Operand::Imm32(0x12345678)).unwrap();
    let expected_disasm = vec![Some("0x12345678")];
    test_disasm(mnemonic, &expected_disasm, &code);
}


fn test_off8(mnemonic: &str, f: fn(&mut Vec<u8>, Operand) -> Result<()>) {
    let mut code = Vec::new();
    f(&mut code, Operand::Offset8(0x42)).unwrap();
    let expected_disasm = vec![Some("0x42")];
    test_disasm(mnemonic, &expected_disasm, &code);
}

fn test_off32(mnemonic: &str, f: fn(&mut Vec<u8>, Operand) -> Result<()>) {
    let mut code = Vec::new();
    f(&mut code, Operand::Offset32(0x12345678)).unwrap();
    let expected_disasm = vec![Some("0x12345678")];
    test_disasm(mnemonic, &expected_disasm, &code);
}


fn test_reg8(mnemonic: &str, f: fn(&mut Vec<u8>, Operand) -> Result<()>) {
    test_reg(mnemonic, f, REGS8, |r| Operand::Reg8(r), |s| s);
}

fn test_reg16(mnemonic: &str, f: fn(&mut Vec<u8>, Operand) -> Result<()>) {
    test_reg(mnemonic, f, REGS16, |r| Operand::Reg16(r), |s| s);
}

fn test_reg32(mnemonic: &str, f: fn(&mut Vec<u8>, Operand) -> Result<()>) {
    test_reg(mnemonic, f, REGS32, |r| Operand::Reg32(r), |s| s);
}

fn test_reg64(mnemonic: &str, f: fn(&mut Vec<u8>, Operand) -> Result<()>) {
    test_reg(mnemonic, f, REGS64, |r| Operand::Reg64(r), |s| s);
}


fn test_byte_ptr(mnemonic: &str, f: fn(&mut Vec<u8>, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    let mut code = Vec::new();
    f(&mut code, byte_pointer(0x42i8)).unwrap();
    let expected_disasm = vec![Some("byte ptr [0x42]")];
    test_disasm(mnemonic, &expected_disasm, &code);

    let mut code = Vec::new();
    f(&mut code, byte_pointer(0x12345678)).unwrap();
    let expected_disasm = vec![Some("byte ptr [0x12345678]")];
    test_disasm(mnemonic, &expected_disasm, &code);

    test_reg(mnemonic, f, REGS64,
             |r| byte_pointer(r),
             |s| format!("byte ptr [{}]", s));

    test_reg(mnemonic, f, &index_regs,
             |r| byte_pointer(r*4),
             |s| format!("byte ptr [{}*4]", s));

    test_reg(mnemonic, f, REGS64,
             |r| byte_pointer(r + 0x42i8),
             |s| format!("byte ptr [{} + 0x42]", s));

    test_reg(mnemonic, f, REGS64,
             |r| byte_pointer(r + 0x12345678),
             |s| format!("byte ptr [{} + 0x12345678]", s));

    test_reg(mnemonic, f, &index_regs,
             |r| byte_pointer(r*4 + 0x42i8),
             |s| format!("byte ptr [{}*4 + 0x42]", s));

    test_reg(mnemonic, f, &index_regs,
             |r| byte_pointer(r*4 + 0x12345678),
             |s| format!("byte ptr [{}*4 + 0x12345678]", s));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| byte_pointer(r1 + r2),
                 |s1, s2| format!("byte ptr [{} + {}]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| byte_pointer(r1 + r2 + 0x42i8),
                 |s1, s2| format!("byte ptr [{} + {} + 0x42]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| byte_pointer(r1 + r2 + 0x12345678),
                 |s1, s2| format!("byte ptr [{} + {} + 0x12345678]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| byte_pointer(r1 + r2),
                 |s1, s2| format!("byte ptr [{} + {}]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| byte_pointer(r1 + r2 + 0x42i8),
                 |s1, s2| format!("byte ptr [{} + {} + 0x42]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| byte_pointer(r1 + r2 + 0x12345678),
                 |s1, s2| format!("byte ptr [{} + {} + 0x12345678]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| byte_pointer(r1 + r2*2),
                 |s1, s2| format!("byte ptr [{} + {}*2]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| byte_pointer(r1 + r2*2 + 0x42i8),
                 |s1, s2| format!("byte ptr [{} + {}*2 + 0x42]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| byte_pointer(r1 + r2*2 + 0x12345678),
                 |s1, s2| format!("byte ptr [{} + {}*2 + 0x12345678]", s1, s2));
}


fn test_word_ptr(mnemonic: &str, f: fn(&mut Vec<u8>, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    let mut code = Vec::new();
    f(&mut code, word_pointer(0x42i8)).unwrap();
    print_code(&code);
    let expected_disasm = vec![Some("word ptr [0x42]")];
    test_disasm(mnemonic, &expected_disasm, &code);

    let mut code = Vec::new();
    f(&mut code, word_pointer(0x12345678)).unwrap();
    print_code(&code);
    let expected_disasm = vec![Some("word ptr [0x12345678]")];
    test_disasm(mnemonic, &expected_disasm, &code);

    test_reg(mnemonic, f, REGS64,
             |r| word_pointer(r),
             |s| format!("word ptr [{}]", s));

    test_reg(mnemonic, f, &index_regs,
             |r| word_pointer(r*4),
             |s| format!("word ptr [{}*4]", s));

    test_reg(mnemonic, f, REGS64,
             |r| word_pointer(r + 0x42i8),
             |s| format!("word ptr [{} + 0x42]", s));

    test_reg(mnemonic, f, REGS64,
             |r| word_pointer(r + 0x12345678),
             |s| format!("word ptr [{} + 0x12345678]", s));

    test_reg(mnemonic, f, &index_regs,
             |r| word_pointer(r*4 + 0x42i8),
             |s| format!("word ptr [{}*4 + 0x42]", s));

    test_reg(mnemonic, f, &index_regs,
             |r| word_pointer(r*4 + 0x12345678),
             |s| format!("word ptr [{}*4 + 0x12345678]", s));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| word_pointer(r1 + r2),
                 |s1, s2| format!("word ptr [{} + {}]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| word_pointer(r1 + r2 + 0x42i8),
                 |s1, s2| format!("word ptr [{} + {} + 0x42]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| word_pointer(r1 + r2 + 0x12345678),
                 |s1, s2| format!("word ptr [{} + {} + 0x12345678]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| word_pointer(r1 + r2),
                 |s1, s2| format!("word ptr [{} + {}]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| word_pointer(r1 + r2 + 0x42i8),
                 |s1, s2| format!("word ptr [{} + {} + 0x42]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| word_pointer(r1 + r2*2 + 0x12345678),
                 |s1, s2| format!("word ptr [{} + {}*2 + 0x12345678]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| word_pointer(r1 + r2*2),
                 |s1, s2| format!("word ptr [{} + {}*2]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| word_pointer(r1 + r2*2 + 0x42i8),
                 |s1, s2| format!("word ptr [{} + {}*2 + 0x42]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| word_pointer(r1 + r2*2 + 0x12345678),
                 |s1, s2| format!("word ptr [{} + {}*2 + 0x12345678]", s1, s2));
}


fn test_dword_ptr(mnemonic: &str, f: fn(&mut Vec<u8>, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    let mut code = Vec::new();
    f(&mut code, dword_pointer(0x42i8)).unwrap();
    let expected_disasm = vec![Some("dword ptr [0x42]")];
    test_disasm(mnemonic, &expected_disasm, &code);

    let mut code = Vec::new();
    f(&mut code, dword_pointer(0x12345678)).unwrap();
    let expected_disasm = vec![Some("dword ptr [0x12345678]")];
    test_disasm(mnemonic, &expected_disasm, &code);

    test_reg(mnemonic, f, REGS64,
             |r| dword_pointer(r),
             |s| format!("dword ptr [{}]", s));

    test_reg(mnemonic, f, &index_regs,
             |r| dword_pointer(r*4),
             |s| format!("dword ptr [{}*4]", s));

    test_reg(mnemonic, f, REGS64,
             |r| dword_pointer(r + 0x42i8),
             |s| format!("dword ptr [{} + 0x42]", s));

    test_reg(mnemonic, f, REGS64,
             |r| dword_pointer(r + 0x12345678),
             |s| format!("dword ptr [{} + 0x12345678]", s));

    test_reg(mnemonic, f, &index_regs,
             |r| dword_pointer(r*4 + 0x42i8),
             |s| format!("dword ptr [{}*4 + 0x42]", s));

    test_reg(mnemonic, f, &index_regs,
             |r| dword_pointer(r*4 + 0x12345678),
             |s| format!("dword ptr [{}*4 + 0x12345678]", s));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| dword_pointer(r1 + r2),
                 |s1, s2| format!("dword ptr [{} + {}]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| dword_pointer(r1 + r2 + 0x42i8),
                 |s1, s2| format!("dword ptr [{} + {} + 0x42]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| dword_pointer(r1 + r2 + 0x12345678),
                 |s1, s2| format!("dword ptr [{} + {} + 0x12345678]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| dword_pointer(r1 + r2),
                 |s1, s2| format!("dword ptr [{} + {}]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| dword_pointer(r1 + r2 + 0x42i8),
                 |s1, s2| format!("dword ptr [{} + {} + 0x42]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| dword_pointer(r1 + r2 + 0x12345678),
                 |s1, s2| format!("dword ptr [{} + {} + 0x12345678]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| dword_pointer(r1 + r2*2),
                 |s1, s2| format!("dword ptr [{} + {}*2]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| dword_pointer(r1 + r2*2 + 0x42i8),
                 |s1, s2| format!("dword ptr [{} + {}*2 + 0x42]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| dword_pointer(r1 + r2*2 + 0x12345678),
                 |s1, s2| format!("dword ptr [{} + {}*2 + 0x12345678]", s1, s2));
}


fn test_qword_ptr(mnemonic: &str, f: fn(&mut Vec<u8>, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    let mut code = Vec::new();
    f(&mut code, qword_pointer(0x42i8)).unwrap();
    print_code(&code);
    let expected_disasm = vec![Some("qword ptr [0x42]")];
    test_disasm(mnemonic, &expected_disasm, &code);

    let mut code = Vec::new();
    f(&mut code, qword_pointer(0x12345678)).unwrap();
    print_code(&code);
    let expected_disasm = vec![Some("qword ptr [0x12345678]")];
    test_disasm(mnemonic, &expected_disasm, &code);

    test_reg(mnemonic, f, REGS64,
             |r| qword_pointer(r),
             |s| format!("qword ptr [{}]", s));

    test_reg(mnemonic, f, &index_regs,
             |r| qword_pointer(r*4),
             |s| format!("qword ptr [{}*4]", s));

    test_reg(mnemonic, f, REGS64,
             |r| qword_pointer(r + 0x42i8),
             |s| format!("qword ptr [{} + 0x42]", s));

    test_reg(mnemonic, f, REGS64,
             |r| qword_pointer(r + 0x12345678),
             |s| format!("qword ptr [{} + 0x12345678]", s));

    test_reg(mnemonic, f, &index_regs,
             |r| qword_pointer(r*4 + 0x42i8),
             |s| format!("qword ptr [{}*4 + 0x42]", s));

    test_reg(mnemonic, f, &index_regs,
             |r| qword_pointer(r*4 + 0x12345678),
             |s| format!("qword ptr [{}*4 + 0x12345678]", s));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| qword_pointer(r1 + r2),
                 |s1, s2| format!("qword ptr [{} + {}]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| qword_pointer(r1 + r2 + 0x42i8),
                 |s1, s2| format!("qword ptr [{} + {} + 0x42]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| qword_pointer(r1 + r2 + 0x12345678),
                 |s1, s2| format!("qword ptr [{} + {} + 0x12345678]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| qword_pointer(r1 + r2),
                 |s1, s2| format!("qword ptr [{} + {}]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| qword_pointer(r1 + r2 + 0x42i8),
                 |s1, s2| format!("qword ptr [{} + {} + 0x42]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| qword_pointer(r1 + r2 + 0x12345678),
                 |s1, s2| format!("qword ptr [{} + {} + 0x12345678]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| qword_pointer(r1 + r2*2),
                 |s1, s2| format!("qword ptr [{} + {}*2]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| qword_pointer(r1 + r2*2 + 0x42i8),
                 |s1, s2| format!("qword ptr [{} + {}*2 + 0x42]", s1, s2));

    test_reg_reg(mnemonic, f,
                 &REGS64, &index_regs,
                 |r1, r2| qword_pointer(r1 + r2*2 + 0x12345678),
                 |s1, s2| format!("qword ptr [{} + {}*2 + 0x12345678]", s1, s2));
}


fn test_reg8_imm8(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    test_reg(mnemonic, |v, r| f(v, r, Operand::Imm8(0x42)),
             REGS8,
             |r| Operand::Reg8(r),
             |s| format!("{}, 0x42", s));
}

fn test_reg16_imm16(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    test_reg(mnemonic, |v, r| f(v, r, Operand::Imm16(0x1234)),
             REGS16,
             |r| Operand::Reg16(r),
             |s| format!("{}, 0x1234", s));
}

fn test_reg32_imm32(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    test_reg(mnemonic, |v, r| f(v, r, Operand::Imm32(0x12345678)),
             REGS32,
             |r| Operand::Reg32(r),
             |s| format!("{}, 0x12345678", s));
}

fn test_reg64_imm32(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    test_reg(mnemonic, |v, r| f(v, r, Operand::Imm32(0x12345678)),
             REGS64,
             |r| Operand::Reg64(r),
             |s| format!("{}, 0x12345678", s));
}

fn test_reg64_imm64(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    test_reg(mnemonic, |v, r| f(v, r, Operand::Imm64(0x123456789abcdef0)),
             REGS64,
             |r| Operand::Reg64(r),
             |s| format!("{}, 0x123456789abcdef0", s));
}


fn test_reg16_imm8(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    test_reg(mnemonic, |v, r| f(v, r, Operand::Imm8(0x42)),
             REGS16,
             |r| Operand::Reg16(r),
             |s| format!("{}, 0x42", s));
}

fn test_reg32_imm8(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    test_reg(mnemonic, |v, r| f(v, r, Operand::Imm8(0x42)),
             REGS32,
             |r| Operand::Reg32(r),
             |s| format!("{}, 0x42", s));
}

fn test_reg64_imm8(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    test_reg(mnemonic, |v, r| f(v, r, Operand::Imm8(0x42)),
             REGS64,
             |r| Operand::Reg64(r),
             |s| format!("{}, 0x42", s));
}


fn test_reg8_reg8(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    test_reg_reg(mnemonic, |v, (r1, r2)| f(v, r1, r2),
                 SIMPLE_REGS8, SIMPLE_REGS8,
                 |r1, r2| (Operand::Reg8(r1), Operand::Reg8(r2)),
                 |s1, s2| format!("{}, {}", s1, s2));
    test_reg_reg(mnemonic, |v, (r1, r2)| f(v, r1, r2),
                 REX_REGS8, REX_REGS8,
                 |r1, r2| (Operand::Reg8(r1), Operand::Reg8(r2)),
                 |s1, s2| format!("{}, {}", s1, s2));
}

fn test_reg16_reg16(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    test_reg_reg(mnemonic, |v, (r1, r2)| f(v, r1, r2),
                 REGS16, REGS16,
                 |r1, r2| (Operand::Reg16(r1), Operand::Reg16(r2)),
                 |s1, s2| format!("{}, {}", s1, s2));
}

fn test_reg32_reg32(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    test_reg_reg(mnemonic, |v, (r1, r2)| f(v, r1, r2),
                 REGS32, REGS32,
                 |r1, r2| (Operand::Reg32(r1), Operand::Reg32(r2)),
                 |s1, s2| format!("{}, {}", s1, s2));
}

fn test_reg64_reg64(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    test_reg_reg(mnemonic, |v, (r1, r2)| f(v, r1, r2),
                 REGS64, REGS64,
                 |r1, r2| (Operand::Reg64(r1), Operand::Reg64(r2)),
                 |s1, s2| format!("{}, {}", s1, s2));
}


fn test_reg16_reg8(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    test_reg_reg(mnemonic, |v, (r1, r2)| f(v, r1, r2),
                 SIMPLE_REGS16, SIMPLE_REGS8,
                 |r1, r2| (Operand::Reg16(r1), Operand::Reg8(r2)),
                 |s1, s2| format!("{}, {}", s1, s2));
    test_reg_reg(mnemonic, |v, (r1, r2)| f(v, r1, r2),
                 REGS16, REX_REGS8,
                 |r1, r2| (Operand::Reg16(r1), Operand::Reg8(r2)),
                 |s1, s2| format!("{}, {}", s1, s2));
}

fn test_reg32_reg8(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    test_reg_reg(mnemonic, |v, (r1, r2)| f(v, r1, r2),
                 SIMPLE_REGS32, SIMPLE_REGS8,
                 |r1, r2| (Operand::Reg32(r1), Operand::Reg8(r2)),
                 |s1, s2| format!("{}, {}", s1, s2));
    test_reg_reg(mnemonic, |v, (r1, r2)| f(v, r1, r2),
                 REGS32, REX_REGS8,
                 |r1, r2| (Operand::Reg32(r1), Operand::Reg8(r2)),
                 |s1, s2| format!("{}, {}", s1, s2));
}

fn test_reg64_reg8(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    test_reg_reg(mnemonic, |v, (r1, r2)| f(v, r1, r2),
                 REGS64, REX_REGS8,
                 |r1, r2| (Operand::Reg64(r1), Operand::Reg8(r2)),
                 |s1, s2| format!("{}, {}", s1, s2));
}


fn test_reg32_reg16(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    test_reg_reg(mnemonic, |v, (r1, r2)| f(v, r1, r2),
                 REGS32, REGS16,
                 |r1, r2| (Operand::Reg32(r1), Operand::Reg16(r2)),
                 |s1, s2| format!("{}, {}", s1, s2));
}

fn test_reg64_reg16(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    test_reg_reg(mnemonic, |v, (r1, r2)| f(v, r1, r2),
                 REGS64, REGS16,
                 |r1, r2| (Operand::Reg64(r1), Operand::Reg16(r2)),
                 |s1, s2| format!("{}, {}", s1, s2));
}


fn test_reg8_byte_ptr(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();
    let simple_index_regs = SIMPLE_REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS8,
             |r1| (Operand::Reg8(r1), byte_pointer(0x42i8)),
             |s1| format!("{}, byte ptr [0x42]", s1));

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS8,
             |r1| (Operand::Reg8(r1), byte_pointer(0x12345678)),
             |s1| format!("{}, byte ptr [0x12345678]", s1));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS8, SIMPLE_REGS64,
                 |r1, r2| (Operand::Reg8(r1), byte_pointer(r2)),
                 |s1, s2| format!("{}, byte ptr [{}]", s1, s2));
    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REX_REGS8, REGS64,
                 |r1, r2| (Operand::Reg8(r1), byte_pointer(r2)),
                 |s1, s2| format!("{}, byte ptr [{}]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS8, &simple_index_regs,
                 |r1, r2| (Operand::Reg8(r1), byte_pointer(r2*4)),
                 |s1, s2| format!("{}, byte ptr [{}*4]", s1, s2));
    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REX_REGS8, &index_regs,
                 |r1, r2| (Operand::Reg8(r1), byte_pointer(r2*4)),
                 |s1, s2| format!("{}, byte ptr [{}*4]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS8, SIMPLE_REGS64,
                 |r1, r2| (Operand::Reg8(r1), byte_pointer(r2 + 0x42i8)),
                 |s1, s2| format!("{}, byte ptr [{} + 0x42]", s1, s2));
    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REX_REGS8, REGS64,
                 |r1, r2| (Operand::Reg8(r1), byte_pointer(r2 + 0x42i8)),
                 |s1, s2| format!("{}, byte ptr [{} + 0x42]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS8, SIMPLE_REGS64,
                 |r1, r2| (Operand::Reg8(r1), byte_pointer(r2 + 0x12345678)),
                 |s1, s2| format!("{}, byte ptr [{} + 0x12345678]", s1, s2));
    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REX_REGS8, REGS64,
                 |r1, r2| (Operand::Reg8(r1), byte_pointer(r2 + 0x12345678)),
                 |s1, s2| format!("{}, byte ptr [{} + 0x12345678]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS8, &simple_index_regs,
                 |r1, r2| (Operand::Reg8(r1), byte_pointer(r2*4 + 0x42i8)),
                 |s1, s2| format!("{}, byte ptr [{}*4 + 0x42]", s1, s2));
    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REX_REGS8, &index_regs,
                 |r1, r2| (Operand::Reg8(r1), byte_pointer(r2*4 + 0x42i8)),
                 |s1, s2| format!("{}, byte ptr [{}*4 + 0x42]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS8, &simple_index_regs,
                 |r1, r2| (Operand::Reg8(r1), byte_pointer(r2*4 + 0x12345678)),
                 |s1, s2| format!("{}, byte ptr [{}*4 + 0x12345678]", s1, s2));
    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REX_REGS8, &index_regs,
                 |r1, r2| (Operand::Reg8(r1), byte_pointer(r2*4 + 0x12345678)),
                 |s1, s2| format!("{}, byte ptr [{}*4 + 0x12345678]", s1, s2));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS8, SIMPLE_REGS64, &simple_index_regs,
                     |r1, r2, r3| (Operand::Reg8(r1), byte_pointer(r2 + r3*4)),
                     |s1, s2, s3| format!("{}, byte ptr [{} + {}*4]", s1, s2, s3));
    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REX_REGS8, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg8(r1), byte_pointer(r2 + r3*4)),
                     |s1, s2, s3| format!("{}, byte ptr [{} + {}*4]", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS8, SIMPLE_REGS64, &simple_index_regs,
                     |r1, r2, r3| (Operand::Reg8(r1), byte_pointer(r2 + r3*4 + 0x42i8)),
                     |s1, s2, s3| format!("{}, byte ptr [{} + {}*4 + 0x42]", s1, s2, s3));
    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REX_REGS8, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg8(r1), byte_pointer(r2 + r3*4 + 0x42i8)),
                     |s1, s2, s3| format!("{}, byte ptr [{} + {}*4 + 0x42]", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS8, SIMPLE_REGS64, &simple_index_regs,
                     |r1, r2, r3| (Operand::Reg8(r1), byte_pointer(r2 + r3*4 + 0x12345678)),
                     |s1, s2, s3| format!("{}, byte ptr [{} + {}*4 + 0x12345678]", s1, s2, s3));
    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REX_REGS8, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg8(r1), byte_pointer(r2 + r3*4 + 0x12345678)),
                     |s1, s2, s3| format!("{}, byte ptr [{} + {}*4 + 0x12345678]", s1, s2, s3));
}


fn test_reg16_word_ptr(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS16,
             |r1| (Operand::Reg16(r1), word_pointer(0x42i8)),
             |s1| format!("{}, word ptr [0x42]", s1));

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS16,
             |r1| (Operand::Reg16(r1), word_pointer(0x12345678)),
             |s1| format!("{}, word ptr [0x12345678]", s1));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS16, REGS64,
                 |r1, r2| (Operand::Reg16(r1), word_pointer(r2)),
                 |s1, s2| format!("{}, word ptr [{}]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS16, &index_regs,
                 |r1, r2| (Operand::Reg16(r1), word_pointer(r2*4)),
                 |s1, s2| format!("{}, word ptr [{}*4]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS16, REGS64,
                 |r1, r2| (Operand::Reg16(r1), word_pointer(r2 + 0x42i8)),
                 |s1, s2| format!("{}, word ptr [{} + 0x42]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS16, REGS64,
                 |r1, r2| (Operand::Reg16(r1), word_pointer(r2 + 0x12345678)),
                 |s1, s2| format!("{}, word ptr [{} + 0x12345678]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS16, &index_regs,
                 |r1, r2| (Operand::Reg16(r1), word_pointer(r2*4 + 0x42i8)),
                 |s1, s2| format!("{}, word ptr [{}*4 + 0x42]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS16, &index_regs,
                 |r1, r2| (Operand::Reg16(r1), word_pointer(r2*4 + 0x12345678)),
                 |s1, s2| format!("{}, word ptr [{}*4 + 0x12345678]", s1, s2));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS16, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg16(r1), word_pointer(r2 + r3*4)),
                     |s1, s2, s3| format!("{}, word ptr [{} + {}*4]", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS16, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg16(r1), word_pointer(r2 + r3*4 + 0x42i8)),
                     |s1, s2, s3| format!("{}, word ptr [{} + {}*4 + 0x42]", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS16, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg16(r1), word_pointer(r2 + r3*4 + 0x12345678)),
                     |s1, s2, s3| format!("{}, word ptr [{} + {}*4 + 0x12345678]", s1, s2, s3));
}


fn test_reg32_dword_ptr(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS32,
             |r1| (Operand::Reg32(r1), dword_pointer(0x42i8)),
             |s1| format!("{}, dword ptr [0x42]", s1));

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS32,
             |r1| (Operand::Reg32(r1), dword_pointer(0x12345678)),
             |s1| format!("{}, dword ptr [0x12345678]", s1));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS32, REGS64,
                 |r1, r2| (Operand::Reg32(r1), dword_pointer(r2)),
                 |s1, s2| format!("{}, dword ptr [{}]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS32, &index_regs,
                 |r1, r2| (Operand::Reg32(r1), dword_pointer(r2*4)),
                 |s1, s2| format!("{}, dword ptr [{}*4]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS32, REGS64,
                 |r1, r2| (Operand::Reg32(r1), dword_pointer(r2 + 0x42i8)),
                 |s1, s2| format!("{}, dword ptr [{} + 0x42]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS32, REGS64,
                 |r1, r2| (Operand::Reg32(r1), dword_pointer(r2 + 0x12345678)),
                 |s1, s2| format!("{}, dword ptr [{} + 0x12345678]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS32, &index_regs,
                 |r1, r2| (Operand::Reg32(r1), dword_pointer(r2*4 + 0x42i8)),
                 |s1, s2| format!("{}, dword ptr [{}*4 + 0x42]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS32, &index_regs,
                 |r1, r2| (Operand::Reg32(r1), dword_pointer(r2*4 + 0x12345678)),
                 |s1, s2| format!("{}, dword ptr [{}*4 + 0x12345678]", s1, s2));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS32, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg32(r1), dword_pointer(r2 + r3*4)),
                     |s1, s2, s3| format!("{}, dword ptr [{} + {}*4]", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS32, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg32(r1), dword_pointer(r2 + r3*4 + 0x42i8)),
                     |s1, s2, s3| format!("{}, dword ptr [{} + {}*4 + 0x42]", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS32, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg32(r1), dword_pointer(r2 + r3*4 + 0x12345678)),
                     |s1, s2, s3| format!("{}, dword ptr [{} + {}*4 + 0x12345678]", s1, s2, s3));
}


fn test_reg64_qword_ptr(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS64,
             |r1| (Operand::Reg64(r1), qword_pointer(0x42i8)),
             |s1| format!("{}, qword ptr [0x42]", s1));

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS64,
             |r1| (Operand::Reg64(r1), qword_pointer(0x12345678)),
             |s1| format!("{}, qword ptr [0x12345678]", s1));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, REGS64,
                 |r1, r2| (Operand::Reg64(r1), qword_pointer(r2)),
                 |s1, s2| format!("{}, qword ptr [{}]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, &index_regs,
                 |r1, r2| (Operand::Reg64(r1), qword_pointer(r2*4)),
                 |s1, s2| format!("{}, qword ptr [{}*4]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, REGS64,
                 |r1, r2| (Operand::Reg64(r1), qword_pointer(r2 + 0x42i8)),
                 |s1, s2| format!("{}, qword ptr [{} + 0x42]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, REGS64,
                 |r1, r2| (Operand::Reg64(r1), qword_pointer(r2 + 0x12345678)),
                 |s1, s2| format!("{}, qword ptr [{} + 0x12345678]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, &index_regs,
                 |r1, r2| (Operand::Reg64(r1), qword_pointer(r2*4 + 0x42i8)),
                 |s1, s2| format!("{}, qword ptr [{}*4 + 0x42]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, &index_regs,
                 |r1, r2| (Operand::Reg64(r1), qword_pointer(r2*4 + 0x12345678)),
                 |s1, s2| format!("{}, qword ptr [{}*4 + 0x12345678]", s1, s2));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS64, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg64(r1), qword_pointer(r2 + r3*4)),
                     |s1, s2, s3| format!("{}, qword ptr [{} + {}*4]", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS64, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg64(r1), qword_pointer(r2 + r3*4 + 0x42i8)),
                     |s1, s2, s3| format!("{}, qword ptr [{} + {}*4 + 0x42]", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS64, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg64(r1), qword_pointer(r2 + r3*4 + 0x12345678)),
                     |s1, s2, s3| format!("{}, qword ptr [{} + {}*4 + 0x12345678]", s1, s2, s3));
}


fn test_reg16_byte_ptr(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS16,
             |r1| (Operand::Reg16(r1), byte_pointer(0x42i8)),
             |s1| format!("{}, byte ptr [0x42]", s1));

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS16,
             |r1| (Operand::Reg16(r1), byte_pointer(0x12345678)),
             |s1| format!("{}, byte ptr [0x12345678]", s1));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS16, REGS64,
                 |r1, r2| (Operand::Reg16(r1), byte_pointer(r2)),
                 |s1, s2| format!("{}, byte ptr [{}]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS16, &index_regs,
                 |r1, r2| (Operand::Reg16(r1), byte_pointer(r2*4)),
                 |s1, s2| format!("{}, byte ptr [{}*4]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS16, REGS64,
                 |r1, r2| (Operand::Reg16(r1), byte_pointer(r2 + 0x42i8)),
                 |s1, s2| format!("{}, byte ptr [{} + 0x42]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS16, REGS64,
                 |r1, r2| (Operand::Reg16(r1), byte_pointer(r2 + 0x12345678)),
                 |s1, s2| format!("{}, byte ptr [{} + 0x12345678]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS16, &index_regs,
                 |r1, r2| (Operand::Reg16(r1), byte_pointer(r2*4 + 0x42i8)),
                 |s1, s2| format!("{}, byte ptr [{}*4 + 0x42]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS16, &index_regs,
                 |r1, r2| (Operand::Reg16(r1), byte_pointer(r2*4 + 0x12345678)),
                 |s1, s2| format!("{}, byte ptr [{}*4 + 0x12345678]", s1, s2));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS16, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg16(r1), byte_pointer(r2 + r3*4)),
                     |s1, s2, s3| format!("{}, byte ptr [{} + {}*4]", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS16, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg16(r1), byte_pointer(r2 + r3*4 + 0x42i8)),
                     |s1, s2, s3| format!("{}, byte ptr [{} + {}*4 + 0x42]", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS16, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg16(r1), byte_pointer(r2 + r3*4 + 0x12345678)),
                     |s1, s2, s3| format!("{}, byte ptr [{} + {}*4 + 0x12345678]", s1, s2, s3));
}


fn test_reg32_byte_ptr(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS32,
             |r1| (Operand::Reg32(r1), byte_pointer(0x42i8)),
             |s1| format!("{}, byte ptr [0x42]", s1));

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS32,
             |r1| (Operand::Reg32(r1), byte_pointer(0x12345678)),
             |s1| format!("{}, byte ptr [0x12345678]", s1));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS32, REGS64,
                 |r1, r2| (Operand::Reg32(r1), byte_pointer(r2)),
                 |s1, s2| format!("{}, byte ptr [{}]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS32, &index_regs,
                 |r1, r2| (Operand::Reg32(r1), byte_pointer(r2*4)),
                 |s1, s2| format!("{}, byte ptr [{}*4]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS32, REGS64,
                 |r1, r2| (Operand::Reg32(r1), byte_pointer(r2 + 0x42i8)),
                 |s1, s2| format!("{}, byte ptr [{} + 0x42]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS32, REGS64,
                 |r1, r2| (Operand::Reg32(r1), byte_pointer(r2 + 0x12345678)),
                 |s1, s2| format!("{}, byte ptr [{} + 0x12345678]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS32, &index_regs,
                 |r1, r2| (Operand::Reg32(r1), byte_pointer(r2*4 + 0x42i8)),
                 |s1, s2| format!("{}, byte ptr [{}*4 + 0x42]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS32, &index_regs,
                 |r1, r2| (Operand::Reg32(r1), byte_pointer(r2*4 + 0x12345678)),
                 |s1, s2| format!("{}, byte ptr [{}*4 + 0x12345678]", s1, s2));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS32, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg32(r1), byte_pointer(r2 + r3*4)),
                     |s1, s2, s3| format!("{}, byte ptr [{} + {}*4]", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS32, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg32(r1), byte_pointer(r2 + r3*4 + 0x42i8)),
                     |s1, s2, s3| format!("{}, byte ptr [{} + {}*4 + 0x42]", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS32, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg32(r1), byte_pointer(r2 + r3*4 + 0x12345678)),
                     |s1, s2, s3| format!("{}, byte ptr [{} + {}*4 + 0x12345678]", s1, s2, s3));
}


fn test_reg64_byte_ptr(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS64,
             |r1| (Operand::Reg64(r1), byte_pointer(0x42i8)),
             |s1| format!("{}, byte ptr [0x42]", s1));

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS64,
             |r1| (Operand::Reg64(r1), byte_pointer(0x12345678)),
             |s1| format!("{}, byte ptr [0x12345678]", s1));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, REGS64,
                 |r1, r2| (Operand::Reg64(r1), byte_pointer(r2)),
                 |s1, s2| format!("{}, byte ptr [{}]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, &index_regs,
                 |r1, r2| (Operand::Reg64(r1), byte_pointer(r2*4)),
                 |s1, s2| format!("{}, byte ptr [{}*4]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, REGS64,
                 |r1, r2| (Operand::Reg64(r1), byte_pointer(r2 + 0x42i8)),
                 |s1, s2| format!("{}, byte ptr [{} + 0x42]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, REGS64,
                 |r1, r2| (Operand::Reg64(r1), byte_pointer(r2 + 0x12345678)),
                 |s1, s2| format!("{}, byte ptr [{} + 0x12345678]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, &index_regs,
                 |r1, r2| (Operand::Reg64(r1), byte_pointer(r2*4 + 0x42i8)),
                 |s1, s2| format!("{}, byte ptr [{}*4 + 0x42]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, &index_regs,
                 |r1, r2| (Operand::Reg64(r1), byte_pointer(r2*4 + 0x12345678)),
                 |s1, s2| format!("{}, byte ptr [{}*4 + 0x12345678]", s1, s2));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS64, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg64(r1), byte_pointer(r2 + r3*4)),
                     |s1, s2, s3| format!("{}, byte ptr [{} + {}*4]", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS64, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg64(r1), byte_pointer(r2 + r3*4 + 0x42i8)),
                     |s1, s2, s3| format!("{}, byte ptr [{} + {}*4 + 0x42]", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS64, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg64(r1), byte_pointer(r2 + r3*4 + 0x12345678)),
                     |s1, s2, s3| format!("{}, byte ptr [{} + {}*4 + 0x12345678]", s1, s2, s3));
}


fn test_reg32_word_ptr(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS32,
             |r1| (Operand::Reg32(r1), word_pointer(0x42i8)),
             |s1| format!("{}, word ptr [0x42]", s1));

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS32,
             |r1| (Operand::Reg32(r1), word_pointer(0x12345678)),
             |s1| format!("{}, word ptr [0x12345678]", s1));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS32, REGS64,
                 |r1, r2| (Operand::Reg32(r1), word_pointer(r2)),
                 |s1, s2| format!("{}, word ptr [{}]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS32, &index_regs,
                 |r1, r2| (Operand::Reg32(r1), word_pointer(r2*4)),
                 |s1, s2| format!("{}, word ptr [{}*4]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS32, REGS64,
                 |r1, r2| (Operand::Reg32(r1), word_pointer(r2 + 0x42i8)),
                 |s1, s2| format!("{}, word ptr [{} + 0x42]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS32, REGS64,
                 |r1, r2| (Operand::Reg32(r1), word_pointer(r2 + 0x12345678)),
                 |s1, s2| format!("{}, word ptr [{} + 0x12345678]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS32, &index_regs,
                 |r1, r2| (Operand::Reg32(r1), word_pointer(r2*4 + 0x42i8)),
                 |s1, s2| format!("{}, word ptr [{}*4 + 0x42]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS32, &index_regs,
                 |r1, r2| (Operand::Reg32(r1), word_pointer(r2*4 + 0x12345678)),
                 |s1, s2| format!("{}, word ptr [{}*4 + 0x12345678]", s1, s2));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS32, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg32(r1), word_pointer(r2 + r3*4)),
                     |s1, s2, s3| format!("{}, word ptr [{} + {}*4]", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS32, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg32(r1), word_pointer(r2 + r3*4 + 0x42i8)),
                     |s1, s2, s3| format!("{}, word ptr [{} + {}*4 + 0x42]", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS32, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg32(r1), word_pointer(r2 + r3*4 + 0x12345678)),
                     |s1, s2, s3| format!("{}, word ptr [{} + {}*4 + 0x12345678]", s1, s2, s3));
}


fn test_reg64_word_ptr(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS64,
             |r1| (Operand::Reg64(r1), word_pointer(0x42i8)),
             |s1| format!("{}, word ptr [0x42]", s1));

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS64,
             |r1| (Operand::Reg64(r1), word_pointer(0x12345678)),
             |s1| format!("{}, word ptr [0x12345678]", s1));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, REGS64,
                 |r1, r2| (Operand::Reg64(r1), word_pointer(r2)),
                 |s1, s2| format!("{}, word ptr [{}]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, &index_regs,
                 |r1, r2| (Operand::Reg64(r1), word_pointer(r2*4)),
                 |s1, s2| format!("{}, word ptr [{}*4]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, REGS64,
                 |r1, r2| (Operand::Reg64(r1), word_pointer(r2 + 0x42i8)),
                 |s1, s2| format!("{}, word ptr [{} + 0x42]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, REGS64,
                 |r1, r2| (Operand::Reg64(r1), word_pointer(r2 + 0x12345678)),
                 |s1, s2| format!("{}, word ptr [{} + 0x12345678]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, &index_regs,
                 |r1, r2| (Operand::Reg64(r1), word_pointer(r2*4 + 0x42i8)),
                 |s1, s2| format!("{}, word ptr [{}*4 + 0x42]", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, &index_regs,
                 |r1, r2| (Operand::Reg64(r1), word_pointer(r2*4 + 0x12345678)),
                 |s1, s2| format!("{}, word ptr [{}*4 + 0x12345678]", s1, s2));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS64, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg64(r1), word_pointer(r2 + r3*4)),
                     |s1, s2, s3| format!("{}, word ptr [{} + {}*4]", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS64, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg64(r1), word_pointer(r2 + r3*4 + 0x42i8)),
                     |s1, s2, s3| format!("{}, word ptr [{} + {}*4 + 0x42]", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS64, REGS64, &index_regs,
                     |r1, r2, r3| (Operand::Reg64(r1), word_pointer(r2 + r3*4 + 0x12345678)),
                     |s1, s2, s3| format!("{}, word ptr [{} + {}*4 + 0x12345678]", s1, s2, s3));
}


fn test_byte_ptr_imm8(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    {
        let mut code = Vec::new();
        f(&mut code, byte_pointer(0x42i8), Operand::Imm8(0x78)).unwrap();
        let expected_disasm = vec![Some("byte ptr [0x42], 0x78")];
        test_disasm(mnemonic, &expected_disasm, &code);
    }

    {
        let mut code = Vec::new();
        f(&mut code, byte_pointer(0x12345678), Operand::Imm8(0x78)).unwrap();
        let expected_disasm = vec![Some("byte ptr [0x12345678], 0x78")];
        test_disasm(mnemonic, &expected_disasm, &code);
    }

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             REGS64,
             |r| (byte_pointer(r), Operand::Imm8(0x78)),
             |s| format!("byte ptr [{}], 0x78", s));

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             &index_regs,
             |r| (byte_pointer(r*4), Operand::Imm8(0x78)),
             |s| format!("byte ptr [{}*4], 0x78", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             REGS64,
             |r| (byte_pointer(r + 0x42i8), Operand::Imm8(0x78)),
             |s| format!("byte ptr [{} + 0x42], 0x78", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             REGS64,
             |r| (byte_pointer(r + 0x12345678), Operand::Imm8(0x78)),
             |s| format!("byte ptr [{} + 0x12345678], 0x78", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             &index_regs,
             |r| (byte_pointer(r*4 + 0x42i8), Operand::Imm8(0x78)),
             |s| format!("byte ptr [{}*4 + 0x42], 0x78", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             &index_regs,
             |r| (byte_pointer(r*4 + 0x12345678), Operand::Imm8(0x78)),
             |s| format!("byte ptr [{}*4 + 0x12345678], 0x78", s));

    test_reg_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
                 REGS64, &index_regs,
                 |r1, r2| (byte_pointer(r1 + r2*4), Operand::Imm8(0x78)),
                 |s1, s2| format!("byte ptr [{} + {}*4], 0x78", s1, s2));

    test_reg_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
                 REGS64, &index_regs,
                 |r1, r2| (byte_pointer(r1 + r2*4 + 0x42i8), Operand::Imm8(0x78)),
                 |s1, s2| format!("byte ptr [{} + {}*4 + 0x42], 0x78", s1, s2));

    test_reg_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
                 REGS64, &index_regs,
                 |r1, r2| (byte_pointer(r1 + r2*4 + 0x12345678), Operand::Imm8(0x78)),
                 |s1, s2| format!("byte ptr [{} + {}*4 + 0x12345678], 0x78", s1, s2));
}


fn test_byte_ptr_reg8(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();
    let simple_index_regs = SIMPLE_REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS8,
             |r| (byte_pointer(0x42i8), Operand::Reg8(r)),
             |s| format!("byte ptr [0x42], {}", s));

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS8,
             |r| (byte_pointer(0x12345678), Operand::Reg8(r)),
             |s| format!("byte ptr [0x12345678], {}", s));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 SIMPLE_REGS64, REGS8,
                 |r1, r2| (byte_pointer(r1), Operand::Reg8(r2)),
                 |s1, s2| format!("byte ptr [{}], {}", s1, s2));
    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, REX_REGS8,
                 |r1, r2| (byte_pointer(r1), Operand::Reg8(r2)),
                 |s1, s2| format!("byte ptr [{}], {}", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 &simple_index_regs, REGS8,
                 |r1, r2| (byte_pointer(r1*4), Operand::Reg8(r2)),
                 |s1, s2| format!("byte ptr [{}*4], {}", s1, s2));
    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 &index_regs, REX_REGS8,
                 |r1, r2| (byte_pointer(r1*4), Operand::Reg8(r2)),
                 |s1, s2| format!("byte ptr [{}*4], {}", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 SIMPLE_REGS64, REGS8,
                 |r1, r2| (byte_pointer(r1 + 0x42i8), Operand::Reg8(r2)),
                 |s1, s2| format!("byte ptr [{} + 0x42], {}", s1, s2));
    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, REX_REGS8,
                 |r1, r2| (byte_pointer(r1 + 0x42i8), Operand::Reg8(r2)),
                 |s1, s2| format!("byte ptr [{} + 0x42], {}", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 SIMPLE_REGS64, REGS8,
                 |r1, r2| (byte_pointer(r1 + 0x12345678), Operand::Reg8(r2)),
                 |s1, s2| format!("byte ptr [{} + 0x12345678], {}", s1, s2));
    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, REX_REGS8,
                 |r1, r2| (byte_pointer(r1 + 0x12345678), Operand::Reg8(r2)),
                 |s1, s2| format!("byte ptr [{} + 0x12345678], {}", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 &simple_index_regs, REGS8,
                 |r1, r2| (byte_pointer(r1*4 + 0x42i8), Operand::Reg8(r2)),
                 |s1, s2| format!("byte ptr [{}*4 + 0x42], {}", s1, s2));
    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 &index_regs, REX_REGS8,
                 |r1, r2| (byte_pointer(r1*4 + 0x42i8), Operand::Reg8(r2)),
                 |s1, s2| format!("byte ptr [{}*4 + 0x42], {}", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 &simple_index_regs, REGS8,
                 |r1, r2| (byte_pointer(r1*4 + 0x12345678), Operand::Reg8(r2)),
                 |s1, s2| format!("byte ptr [{}*4 + 0x12345678], {}", s1, s2));
    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 &index_regs, REX_REGS8,
                 |r1, r2| (byte_pointer(r1*4 + 0x12345678), Operand::Reg8(r2)),
                 |s1, s2| format!("byte ptr [{}*4 + 0x12345678], {}", s1, s2));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     SIMPLE_REGS64, &simple_index_regs, REGS8,
                     |r1, r2, r3| (byte_pointer(r1 + r2*4), Operand::Reg8(r3)),
                     |s1, s2, s3| format!("byte ptr [{} + {}*4], {}", s1, s2, s3));
    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS64, &index_regs, REX_REGS8,
                     |r1, r2, r3| (byte_pointer(r1 + r2*4), Operand::Reg8(r3)),
                     |s1, s2, s3| format!("byte ptr [{} + {}*4], {}", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     SIMPLE_REGS64, &simple_index_regs, REGS8,
                     |r1, r2, r3| (byte_pointer(r1 + r2*4 + 0x42i8), Operand::Reg8(r3)),
                     |s1, s2, s3| format!("byte ptr [{} + {}*4 + 0x42], {}", s1, s2, s3));
    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS64, &index_regs, REX_REGS8,
                     |r1, r2, r3| (byte_pointer(r1 + r2*4 + 0x42i8), Operand::Reg8(r3)),
                     |s1, s2, s3| format!("byte ptr [{} + {}*4 + 0x42], {}", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     SIMPLE_REGS64, &simple_index_regs, REGS8,
                     |r1, r2, r3| (byte_pointer(r1 + r2*4 + 0x12345678), Operand::Reg8(r3)),
                     |s1, s2, s3| format!("byte ptr [{} + {}*4 + 0x12345678], {}", s1, s2, s3));
    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS64, &index_regs, REX_REGS8,
                     |r1, r2, r3| (byte_pointer(r1 + r2*4 + 0x12345678), Operand::Reg8(r3)),
                     |s1, s2, s3| format!("byte ptr [{} + {}*4 + 0x12345678], {}", s1, s2, s3));
}


fn test_word_ptr_imm8(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    {
        let mut code = Vec::new();
        f(&mut code, word_pointer(0x42i8), Operand::Imm8(0x5a)).unwrap();
        let expected_disasm = vec![Some("word ptr [0x42], 0x5a")];
        test_disasm(mnemonic, &expected_disasm, &code);
    }

    {
        let mut code = Vec::new();
        f(&mut code, word_pointer(0x12345678), Operand::Imm8(0x5a)).unwrap();
        let expected_disasm = vec![Some("word ptr [0x12345678], 0x5a")];
        test_disasm(mnemonic, &expected_disasm, &code);
    }

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             REGS64,
             |r| (word_pointer(r), Operand::Imm8(0x5a)),
             |s| format!("word ptr [{}], 0x5a", s));

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             &index_regs,
             |r| (word_pointer(r*4), Operand::Imm8(0x5a)),
             |s| format!("word ptr [{}*4], 0x5a", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             REGS64,
             |r| (word_pointer(r + 0x42i8), Operand::Imm8(0x5a)),
             |s| format!("word ptr [{} + 0x42], 0x5a", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             REGS64,
             |r| (word_pointer(r + 0x12345678), Operand::Imm8(0x5a)),
             |s| format!("word ptr [{} + 0x12345678], 0x5a", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             &index_regs,
             |r| (word_pointer(r*4 + 0x42i8), Operand::Imm8(0x5a)),
             |s| format!("word ptr [{}*4 + 0x42], 0x5a", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             &index_regs,
             |r| (word_pointer(r*4 + 0x12345678), Operand::Imm8(0x5a)),
             |s| format!("word ptr [{}*4 + 0x12345678], 0x5a", s));

    test_reg_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
                 REGS64, &index_regs,
                 |r1, r2| (word_pointer(r1 + r2*4), Operand::Imm8(0x5a)),
                 |s1, s2| format!("word ptr [{} + {}*4], 0x5a", s1, s2));

    test_reg_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
                 REGS64, &index_regs,
                 |r1, r2| (word_pointer(r1 + r2*4 + 0x42i8), Operand::Imm8(0x5a)),
                 |s1, s2| format!("word ptr [{} + {}*4 + 0x42], 0x5a", s1, s2));

    test_reg_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
                 REGS64, &index_regs,
                 |r1, r2| (word_pointer(r1 + r2*4 + 0x12345678), Operand::Imm8(0x5a)),
                 |s1, s2| format!("word ptr [{} + {}*4 + 0x12345678], 0x5a", s1, s2));
}


fn test_word_ptr_imm16(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    {
        let mut code = Vec::new();
        f(&mut code, word_pointer(0x42i8), Operand::Imm16(0x1234)).unwrap();
        let expected_disasm = vec![Some("word ptr [0x42], 0x1234")];
        test_disasm(mnemonic, &expected_disasm, &code);
    }

    {
        let mut code = Vec::new();
        f(&mut code, word_pointer(0x12345678), Operand::Imm16(0x1234)).unwrap();
        let expected_disasm = vec![Some("word ptr [0x12345678], 0x1234")];
        test_disasm(mnemonic, &expected_disasm, &code);
    }

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             REGS64,
             |r| (word_pointer(r), Operand::Imm16(0x1234)),
             |s| format!("word ptr [{}], 0x1234", s));

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             &index_regs,
             |r| (word_pointer(r*4), Operand::Imm16(0x1234)),
             |s| format!("word ptr [{}*4], 0x1234", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             REGS64,
             |r| (word_pointer(r + 0x42i8), Operand::Imm16(0x1234)),
             |s| format!("word ptr [{} + 0x42], 0x1234", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             REGS64,
             |r| (word_pointer(r + 0x12345678), Operand::Imm16(0x1234)),
             |s| format!("word ptr [{} + 0x12345678], 0x1234", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             &index_regs,
             |r| (word_pointer(r*4 + 0x42i8), Operand::Imm16(0x1234)),
             |s| format!("word ptr [{}*4 + 0x42], 0x1234", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             &index_regs,
             |r| (word_pointer(r*4 + 0x12345678), Operand::Imm16(0x1234)),
             |s| format!("word ptr [{}*4 + 0x12345678], 0x1234", s));

    test_reg_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
                 REGS64, &index_regs,
                 |r1, r2| (word_pointer(r1 + r2*4), Operand::Imm16(0x1234)),
                 |s1, s2| format!("word ptr [{} + {}*4], 0x1234", s1, s2));

    test_reg_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
                 REGS64, &index_regs,
                 |r1, r2| (word_pointer(r1 + r2*4 + 0x42i8), Operand::Imm16(0x1234)),
                 |s1, s2| format!("word ptr [{} + {}*4 + 0x42], 0x1234", s1, s2));

    test_reg_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
                 REGS64, &index_regs,
                 |r1, r2| (word_pointer(r1 + r2*4 + 0x12345678), Operand::Imm16(0x1234)),
                 |s1, s2| format!("word ptr [{} + {}*4 + 0x12345678], 0x1234", s1, s2));
}


fn test_word_ptr_reg16(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS16,
             |r| (word_pointer(0x42i8), Operand::Reg16(r)),
             |s| format!("word ptr [0x42], {}", s));

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS16,
             |r| (word_pointer(0x12345678), Operand::Reg16(r)),
             |s| format!("word ptr [0x12345678], {}", s));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, REGS16,
                 |r1, r2| (word_pointer(r1), Operand::Reg16(r2)),
                 |s1, s2| format!("word ptr [{}], {}", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 &index_regs, REGS16,
                 |r1, r2| (word_pointer(r1*4), Operand::Reg16(r2)),
                 |s1, s2| format!("word ptr [{}*4], {}", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, REGS16,
                 |r1, r2| (word_pointer(r1 + 0x42i8), Operand::Reg16(r2)),
                 |s1, s2| format!("word ptr [{} + 0x42], {}", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, REGS16,
                 |r1, r2| (word_pointer(r1 + 0x12345678), Operand::Reg16(r2)),
                 |s1, s2| format!("word ptr [{} + 0x12345678], {}", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 &index_regs, REGS16,
                 |r1, r2| (word_pointer(r1*4 + 0x42i8), Operand::Reg16(r2)),
                 |s1, s2| format!("word ptr [{}*4 + 0x42], {}", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 &index_regs, REGS16,
                 |r1, r2| (word_pointer(r1*4 + 0x12345678), Operand::Reg16(r2)),
                 |s1, s2| format!("word ptr [{}*4 + 0x12345678], {}", s1, s2));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS64, &index_regs, REGS16,
                     |r1, r2, r3| (word_pointer(r1 + r2*4), Operand::Reg16(r3)),
                     |s1, s2, s3| format!("word ptr [{} + {}*4], {}", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS64, &index_regs, REGS16,
                     |r1, r2, r3| (word_pointer(r1 + r2*4 + 0x42i8), Operand::Reg16(r3)),
                     |s1, s2, s3| format!("word ptr [{} + {}*4 + 0x42], {}", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS64, &index_regs, REGS16,
                     |r1, r2, r3| (word_pointer(r1 + r2*4 + 0x12345678), Operand::Reg16(r3)),
                     |s1, s2, s3| format!("word ptr [{} + {}*4 + 0x12345678], {}", s1, s2, s3));
}


fn test_dword_ptr_imm8(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    {
        let mut code = Vec::new();
        f(&mut code, dword_pointer(0x42i8), Operand::Imm8(0x5a)).unwrap();
        let expected_disasm = vec![Some("dword ptr [0x42], 0x5a")];
        test_disasm(mnemonic, &expected_disasm, &code);
    }

    {
        let mut code = Vec::new();
        f(&mut code, dword_pointer(0x12345678), Operand::Imm8(0x5a)).unwrap();
        let expected_disasm = vec![Some("dword ptr [0x12345678], 0x5a")];
        test_disasm(mnemonic, &expected_disasm, &code);
    }

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             REGS64,
             |r| (dword_pointer(r), Operand::Imm8(0x5a)),
             |s| format!("dword ptr [{}], 0x5a", s));

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             &index_regs,
             |r| (dword_pointer(r*4), Operand::Imm8(0x5a)),
             |s| format!("dword ptr [{}*4], 0x5a", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             REGS64,
             |r| (dword_pointer(r + 0x42i8), Operand::Imm8(0x5a)),
             |s| format!("dword ptr [{} + 0x42], 0x5a", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             REGS64,
             |r| (dword_pointer(r + 0x12345678), Operand::Imm8(0x5a)),
             |s| format!("dword ptr [{} + 0x12345678], 0x5a", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             &index_regs,
             |r| (dword_pointer(r*4 + 0x42i8), Operand::Imm8(0x5a)),
             |s| format!("dword ptr [{}*4 + 0x42], 0x5a", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             &index_regs,
             |r| (dword_pointer(r*4 + 0x12345678), Operand::Imm8(0x5a)),
             |s| format!("dword ptr [{}*4 + 0x12345678], 0x5a", s));

    test_reg_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
                 REGS64, &index_regs,
                 |r1, r2| (dword_pointer(r1 + r2*4), Operand::Imm8(0x5a)),
                 |s1, s2| format!("dword ptr [{} + {}*4], 0x5a", s1, s2));

    test_reg_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
                 REGS64, &index_regs,
                 |r1, r2| (dword_pointer(r1 + r2*4 + 0x42i8), Operand::Imm8(0x5a)),
                 |s1, s2| format!("dword ptr [{} + {}*4 + 0x42], 0x5a", s1, s2));

    test_reg_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
                 REGS64, &index_regs,
                 |r1, r2| (dword_pointer(r1 + r2*4 + 0x12345678), Operand::Imm8(0x5a)),
                 |s1, s2| format!("dword ptr [{} + {}*4 + 0x12345678], 0x5a", s1, s2));
}


fn test_dword_ptr_imm32(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    {
        let mut code = Vec::new();
        f(&mut code, dword_pointer(0x42i8), Operand::Imm32(0x12345678)).unwrap();
        let expected_disasm = vec![Some("dword ptr [0x42], 0x12345678")];
        test_disasm(mnemonic, &expected_disasm, &code);
    }

    {
        let mut code = Vec::new();
        f(&mut code, dword_pointer(0x12345678), Operand::Imm32(0x12345678)).unwrap();
        let expected_disasm = vec![Some("dword ptr [0x12345678], 0x12345678")];
        test_disasm(mnemonic, &expected_disasm, &code);
    }

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             REGS64,
             |r| (dword_pointer(r), Operand::Imm32(0x12345678)),
             |s| format!("dword ptr [{}], 0x12345678", s));

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             &index_regs,
             |r| (dword_pointer(r*4), Operand::Imm32(0x12345678)),
             |s| format!("dword ptr [{}*4], 0x12345678", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             REGS64,
             |r| (dword_pointer(r + 0x42i8), Operand::Imm32(0x12345678)),
             |s| format!("dword ptr [{} + 0x42], 0x12345678", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             REGS64,
             |r| (dword_pointer(r + 0x12345678), Operand::Imm32(0x12345678)),
             |s| format!("dword ptr [{} + 0x12345678], 0x12345678", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             &index_regs,
             |r| (dword_pointer(r*4 + 0x42i8), Operand::Imm32(0x12345678)),
             |s| format!("dword ptr [{}*4 + 0x42], 0x12345678", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             &index_regs,
             |r| (dword_pointer(r*4 + 0x12345678), Operand::Imm32(0x12345678)),
             |s| format!("dword ptr [{}*4 + 0x12345678], 0x12345678", s));

    test_reg_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
                 REGS64, &index_regs,
                 |r1, r2| (dword_pointer(r1 + r2*4), Operand::Imm32(0x12345678)),
                 |s1, s2| format!("dword ptr [{} + {}*4], 0x12345678", s1, s2));

    test_reg_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
                 REGS64, &index_regs,
                 |r1, r2| (dword_pointer(r1 + r2*4 + 0x42i8), Operand::Imm32(0x12345678)),
                 |s1, s2| format!("dword ptr [{} + {}*4 + 0x42], 0x12345678", s1, s2));

    test_reg_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
                 REGS64, &index_regs,
                 |r1, r2| (dword_pointer(r1 + r2*4 + 0x12345678), Operand::Imm32(0x12345678)),
                 |s1, s2| format!("dword ptr [{} + {}*4 + 0x12345678], 0x12345678", s1, s2));
}


fn test_dword_ptr_reg32(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS32,
             |r| (dword_pointer(0x42i8), Operand::Reg32(r)),
             |s| format!("dword ptr [0x42], {}", s));

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS32,
             |r| (dword_pointer(0x12345678), Operand::Reg32(r)),
             |s| format!("dword ptr [0x12345678], {}", s));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, REGS32,
                 |r1, r2| (dword_pointer(r1), Operand::Reg32(r2)),
                 |s1, s2| format!("dword ptr [{}], {}", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 &index_regs, REGS32,
                 |r1, r2| (dword_pointer(r1*4), Operand::Reg32(r2)),
                 |s1, s2| format!("dword ptr [{}*4], {}", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, REGS32,
                 |r1, r2| (dword_pointer(r1 + 0x42i8), Operand::Reg32(r2)),
                 |s1, s2| format!("dword ptr [{} + 0x42], {}", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, REGS32,
                 |r1, r2| (dword_pointer(r1 + 0x12345678), Operand::Reg32(r2)),
                 |s1, s2| format!("dword ptr [{} + 0x12345678], {}", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 &index_regs, REGS32,
                 |r1, r2| (dword_pointer(r1*4 + 0x42i8), Operand::Reg32(r2)),
                 |s1, s2| format!("dword ptr [{}*4 + 0x42], {}", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 &index_regs, REGS32,
                 |r1, r2| (dword_pointer(r1*4 + 0x12345678), Operand::Reg32(r2)),
                 |s1, s2| format!("dword ptr [{}*4 + 0x12345678], {}", s1, s2));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS64, &index_regs, REGS32,
                     |r1, r2, r3| (dword_pointer(r1 + r2*4), Operand::Reg32(r3)),
                     |s1, s2, s3| format!("dword ptr [{} + {}*4], {}", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS64, &index_regs, REGS32,
                     |r1, r2, r3| (dword_pointer(r1 + r2*4 + 0x42i8), Operand::Reg32(r3)),
                     |s1, s2, s3| format!("dword ptr [{} + {}*4 + 0x42], {}", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS64, &index_regs, REGS32,
                     |r1, r2, r3| (dword_pointer(r1 + r2*4 + 0x12345678), Operand::Reg32(r3)),
                     |s1, s2, s3| format!("dword ptr [{} + {}*4 + 0x12345678], {}", s1, s2, s3));
}


fn test_qword_ptr_imm8(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    {
        let mut code = Vec::new();
        f(&mut code, qword_pointer(0x42i8), Operand::Imm8(0x5a)).unwrap();
        let expected_disasm = vec![Some("qword ptr [0x42], 0x5a")];
        test_disasm(mnemonic, &expected_disasm, &code);
    }

    {
        let mut code = Vec::new();
        f(&mut code, qword_pointer(0x12345678), Operand::Imm8(0x5a)).unwrap();
        let expected_disasm = vec![Some("qword ptr [0x12345678], 0x5a")];
        test_disasm(mnemonic, &expected_disasm, &code);
    }

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             REGS64,
             |r| (qword_pointer(r), Operand::Imm8(0x5a)),
             |s| format!("qword ptr [{}], 0x5a", s));

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             &index_regs,
             |r| (qword_pointer(r*4), Operand::Imm8(0x5a)),
             |s| format!("qword ptr [{}*4], 0x5a", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             REGS64,
             |r| (qword_pointer(r + 0x42i8), Operand::Imm8(0x5a)),
             |s| format!("qword ptr [{} + 0x42], 0x5a", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             REGS64,
             |r| (qword_pointer(r + 0x12345678), Operand::Imm8(0x5a)),
             |s| format!("qword ptr [{} + 0x12345678], 0x5a", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             &index_regs,
             |r| (qword_pointer(r*4 + 0x42i8), Operand::Imm8(0x5a)),
             |s| format!("qword ptr [{}*4 + 0x42], 0x5a", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             &index_regs,
             |r| (qword_pointer(r*4 + 0x12345678), Operand::Imm8(0x5a)),
             |s| format!("qword ptr [{}*4 + 0x12345678], 0x5a", s));

    test_reg_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
                 REGS64, &index_regs,
                 |r1, r2| (qword_pointer(r1 + r2*4), Operand::Imm8(0x5a)),
                 |s1, s2| format!("qword ptr [{} + {}*4], 0x5a", s1, s2));

    test_reg_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
                 REGS64, &index_regs,
                 |r1, r2| (qword_pointer(r1 + r2*4 + 0x42i8), Operand::Imm8(0x5a)),
                 |s1, s2| format!("qword ptr [{} + {}*4 + 0x42], 0x5a", s1, s2));

    test_reg_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
                 REGS64, &index_regs,
                 |r1, r2| (qword_pointer(r1 + r2*4 + 0x12345678), Operand::Imm8(0x5a)),
                 |s1, s2| format!("qword ptr [{} + {}*4 + 0x12345678], 0x5a", s1, s2));
}


fn test_qword_ptr_imm32(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    {
        let mut code = Vec::new();
        f(&mut code, qword_pointer(0x42i8), Operand::Imm32(0x12345678)).unwrap();
        let expected_disasm = vec![Some("qword ptr [0x42], 0x12345678")];
        test_disasm(mnemonic, &expected_disasm, &code);
    }

    {
        let mut code = Vec::new();
        f(&mut code, qword_pointer(0x12345678), Operand::Imm32(0x12345678)).unwrap();
        let expected_disasm = vec![Some("qword ptr [0x12345678], 0x12345678")];
        test_disasm(mnemonic, &expected_disasm, &code);
    }

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             REGS64,
             |r| (qword_pointer(r), Operand::Imm32(0x12345678)),
             |s| format!("qword ptr [{}], 0x12345678", s));

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             &index_regs,
             |r| (qword_pointer(r*4), Operand::Imm32(0x12345678)),
             |s| format!("qword ptr [{}*4], 0x12345678", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             REGS64,
             |r| (qword_pointer(r + 0x42i8), Operand::Imm32(0x12345678)),
             |s| format!("qword ptr [{} + 0x42], 0x12345678", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             REGS64,
             |r| (qword_pointer(r + 0x12345678), Operand::Imm32(0x12345678)),
             |s| format!("qword ptr [{} + 0x12345678], 0x12345678", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             &index_regs,
             |r| (qword_pointer(r*4 + 0x42i8), Operand::Imm32(0x12345678)),
             |s| format!("qword ptr [{}*4 + 0x42], 0x12345678", s));

    test_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
             &index_regs,
             |r| (qword_pointer(r*4 + 0x12345678), Operand::Imm32(0x12345678)),
             |s| format!("qword ptr [{}*4 + 0x12345678], 0x12345678", s));

    test_reg_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
                 REGS64, &index_regs,
                 |r1, r2| (qword_pointer(r1 + r2*4), Operand::Imm32(0x12345678)),
                 |s1, s2| format!("qword ptr [{} + {}*4], 0x12345678", s1, s2));

    test_reg_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
                 REGS64, &index_regs,
                 |r1, r2| (qword_pointer(r1 + r2*4 + 0x42i8), Operand::Imm32(0x12345678)),
                 |s1, s2| format!("qword ptr [{} + {}*4 + 0x42], 0x12345678", s1, s2));

    test_reg_reg(mnemonic, |v, (m, imm)| f(v, m, imm),
                 REGS64, &index_regs,
                 |r1, r2| (qword_pointer(r1 + r2*4 + 0x12345678), Operand::Imm32(0x12345678)),
                 |s1, s2| format!("qword ptr [{} + {}*4 + 0x12345678], 0x12345678", s1, s2));
}


fn test_qword_ptr_reg64(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    let index_regs = REGS64.iter().filter(|&&(r, _)| r != Rsp && r != R12)
        .cloned().collect::<Vec<_>>();

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS64,
             |r| (qword_pointer(0x42i8), Operand::Reg64(r)),
             |s| format!("qword ptr [0x42], {}", s));

    test_reg(mnemonic, |v, (r, m)| f(v, r, m),
             REGS64,
             |r| (qword_pointer(0x12345678), Operand::Reg64(r)),
             |s| format!("qword ptr [0x12345678], {}", s));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, REGS64,
                 |r1, r2| (qword_pointer(r1), Operand::Reg64(r2)),
                 |s1, s2| format!("qword ptr [{}], {}", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 &index_regs, REGS64,
                 |r1, r2| (qword_pointer(r1*4), Operand::Reg64(r2)),
                 |s1, s2| format!("qword ptr [{}*4], {}", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, REGS64,
                 |r1, r2| (qword_pointer(r1 + 0x42i8), Operand::Reg64(r2)),
                 |s1, s2| format!("qword ptr [{} + 0x42], {}", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 REGS64, REGS64,
                 |r1, r2| (qword_pointer(r1 + 0x12345678), Operand::Reg64(r2)),
                 |s1, s2| format!("qword ptr [{} + 0x12345678], {}", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 &index_regs, REGS64,
                 |r1, r2| (qword_pointer(r1*4 + 0x42i8), Operand::Reg64(r2)),
                 |s1, s2| format!("qword ptr [{}*4 + 0x42], {}", s1, s2));

    test_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                 &index_regs, REGS64,
                 |r1, r2| (qword_pointer(r1*4 + 0x12345678), Operand::Reg64(r2)),
                 |s1, s2| format!("qword ptr [{}*4 + 0x12345678], {}", s1, s2));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS64, &index_regs, REGS64,
                     |r1, r2, r3| (qword_pointer(r1 + r2*4), Operand::Reg64(r3)),
                     |s1, s2, s3| format!("qword ptr [{} + {}*4], {}", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS64, &index_regs, REGS64,
                     |r1, r2, r3| (qword_pointer(r1 + r2*4 + 0x42i8), Operand::Reg64(r3)),
                     |s1, s2, s3| format!("qword ptr [{} + {}*4 + 0x42], {}", s1, s2, s3));

    test_reg_reg_reg(mnemonic, |v, (r, m)| f(v, r, m),
                     REGS64, &index_regs, REGS64,
                     |r1, r2, r3| (qword_pointer(r1 + r2*4 + 0x12345678), Operand::Reg64(r3)),
                     |s1, s2, s3| format!("qword ptr [{} + {}*4 + 0x12345678], {}", s1, s2, s3));
}


fn test_shift_reg8(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    test_reg(mnemonic, |v, r| f(v, r, Operand::Reg8(Cl)),
             REGS8,
             |r| Operand::Reg8(r),
             |s| format!("{}, cl", s));
}

fn test_shift_reg16(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    test_reg(mnemonic, |v, r| f(v, r, Operand::Reg8(Cl)),
             REGS16,
             |r| Operand::Reg16(r),
             |s| format!("{}, cl", s));
}

fn test_shift_reg32(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    test_reg(mnemonic, |v, r| f(v, r, Operand::Reg8(Cl)),
             REGS32,
             |r| Operand::Reg32(r),
             |s| format!("{}, cl", s));
}

fn test_shift_reg64(mnemonic: &str, f: fn(&mut Vec<u8>, Operand, Operand) -> Result<()>) {
    test_reg(mnemonic, |v, r| f(v, r, Operand::Reg8(Cl)),
             REGS64,
             |r| Operand::Reg64(r),
             |s| format!("{}, cl", s));
}


macro_rules! test_op2 {
    ($mnemonic:expr, $f:path) => {
        test_reg8_imm8($mnemonic, $f);
        test_reg16_imm16($mnemonic, $f);
        test_reg32_imm32($mnemonic, $f);
        test_reg64_imm32($mnemonic, $f);

        test_reg16_imm8($mnemonic, $f);
        test_reg32_imm8($mnemonic, $f);
        test_reg64_imm8($mnemonic, $f);

        test_reg8_reg8($mnemonic, $f);
        test_reg16_reg16($mnemonic, $f);
        test_reg32_reg32($mnemonic, $f);
        test_reg64_reg64($mnemonic, $f);

        test_reg8_byte_ptr($mnemonic, $f);
        test_reg16_word_ptr($mnemonic, $f);
        test_reg32_dword_ptr($mnemonic, $f);
        test_reg64_qword_ptr($mnemonic, $f);

        test_byte_ptr_imm8($mnemonic, $f);
        test_word_ptr_imm16($mnemonic, $f);
        test_dword_ptr_imm32($mnemonic, $f);
        test_qword_ptr_imm32($mnemonic, $f);

        test_byte_ptr_reg8($mnemonic, $f);
        test_word_ptr_reg16($mnemonic, $f);
        test_dword_ptr_reg32($mnemonic, $f);
        test_qword_ptr_reg64($mnemonic, $f);
    }
}


macro_rules! test_cmovcc {
    ($( ($test:ident, $mnemonic:expr, $f:path), )*) => {
        $(
            #[test]
            fn $test() {
                test_reg16_reg16($mnemonic, $f);
                test_reg32_reg32($mnemonic, $f);
                test_reg64_reg64($mnemonic, $f);

                test_reg16_word_ptr($mnemonic, $f);
                test_reg32_dword_ptr($mnemonic, $f);
                test_reg64_qword_ptr($mnemonic, $f);
            }
        )*
    }
}

macro_rules! test_jcc {
    ($( ($test:ident, $mnemonic:expr, $f:path), )*) => {
        $(
            #[test]
            fn $test() {
                test_off8($mnemonic, $f);
                test_off32($mnemonic, $f);
            }
        )*
    }
}

macro_rules! test_setcc {
    ($( ($test:ident, $mnemonic:expr, $f:path), )*) => {
        $(
            #[test]
            fn $test() {
                test_reg8($mnemonic, $f);
                test_byte_ptr($mnemonic, $f);
            }
        )*
    }
}

macro_rules! test_shift {
    ($mnemonic:expr, $f:path) => {
        test_reg8_imm8($mnemonic, $f);
        test_reg16_imm8($mnemonic, $f);
        test_reg32_imm8($mnemonic, $f);
        test_reg64_imm8($mnemonic, $f);

        test_shift_reg8($mnemonic, $f);
        test_shift_reg16($mnemonic, $f);
        test_shift_reg32($mnemonic, $f);
        test_shift_reg64($mnemonic, $f);

        test_byte_ptr_imm8($mnemonic, $f);
        test_word_ptr_imm8($mnemonic, $f);
        test_dword_ptr_imm8($mnemonic, $f);
        test_qword_ptr_imm8($mnemonic, $f);
    }
}

macro_rules! test_op1 {
    ($mnemonic:expr, $f:path) => {
        test_reg8($mnemonic, $f);
        test_reg16($mnemonic, $f);
        test_reg32($mnemonic, $f);
        test_reg64($mnemonic, $f);

        test_byte_ptr($mnemonic, $f);
        test_word_ptr($mnemonic, $f);
        test_dword_ptr($mnemonic, $f);
        test_qword_ptr($mnemonic, $f);
    }
}


#[test]
fn test_add() {
    test_op2!("add", Emit::emit_add);
}

#[test]
fn test_or() {
    test_op2!("or", Emit::emit_or);
}

#[test]
fn test_adc() {
    test_op2!("adc", Emit::emit_adc);
}

#[test]
fn test_sbb() {
    test_op2!("sbb", Emit::emit_sbb);
}

#[test]
fn test_and() {
    test_op2!("and", Emit::emit_and);
}

#[test]
fn test_sub() {
    test_op2!("sub", Emit::emit_sub);
}

#[test]
fn test_xor() {
    test_op2!("xor", Emit::emit_xor);
}

#[test]
fn test_cmp() {
    test_op2!("cmp", Emit::emit_cmp);
}

#[test]
fn test_shl() {
    test_shift!("shl", Emit::emit_shl);
}

#[test]
fn test_shr() {
    test_shift!("shr", Emit::emit_shr);
}

#[test]
fn test_sar() {
    test_shift!("sar", Emit::emit_sar);
}

#[test]
fn test_not() {
    test_op1!("not", Emit::emit_not);
}

#[test]
fn test_neg() {
    test_op1!("neg", Emit::emit_neg);
}

#[test]
fn test_mul() {
    test_op1!("mul", Emit::emit_mul);
}

#[test]
fn test_imul() {
    test_op1!("imul", Emit::emit_imul);
}

#[test]
fn test_div() {
    test_op1!("div", Emit::emit_div);
}

#[test]
fn test_idiv() {
    test_op1!("idiv", Emit::emit_idiv);
}

#[test]
fn test_inc() {
    test_op1!("inc", Emit::emit_inc);
}

#[test]
fn test_dec() {
    test_op1!("dec", Emit::emit_dec);
}

#[test]
fn test_test() {
    test_reg8_imm8("test", Emit::emit_test);
    test_reg16_imm16("test", Emit::emit_test);
    test_reg32_imm32("test", Emit::emit_test);
    test_reg64_imm32("test", Emit::emit_test);

    test_reg8_reg8("test", Emit::emit_test);
    test_reg16_reg16("test", Emit::emit_test);
    test_reg32_reg32("test", Emit::emit_test);
    test_reg64_reg64("test", Emit::emit_test);

    test_byte_ptr_imm8("test", Emit::emit_test);
    test_word_ptr_imm16("test", Emit::emit_test);
    test_dword_ptr_imm32("test", Emit::emit_test);
    test_qword_ptr_imm32("test", Emit::emit_test);

    test_byte_ptr_reg8("test", Emit::emit_test);
    test_word_ptr_reg16("test", Emit::emit_test);
    test_dword_ptr_reg32("test", Emit::emit_test);
    test_qword_ptr_reg64("test", Emit::emit_test);
}

#[test]
fn test_mov() {
    test_reg8_imm8("mov", Emit::emit_mov);
    test_reg16_imm16("mov", Emit::emit_mov);
    test_reg32_imm32("mov", Emit::emit_mov);
    test_reg64_imm32("mov", Emit::emit_mov);
    test_reg64_imm64("movabs", Emit::emit_mov);

    test_reg8_reg8("mov", Emit::emit_mov);
    test_reg16_reg16("mov", Emit::emit_mov);
    test_reg32_reg32("mov", Emit::emit_mov);
    test_reg64_reg64("mov", Emit::emit_mov);

    test_reg8_byte_ptr("mov", Emit::emit_mov);
    test_reg16_word_ptr("mov", Emit::emit_mov);
    test_reg32_dword_ptr("mov", Emit::emit_mov);
    test_reg64_qword_ptr("mov", Emit::emit_mov);

    test_byte_ptr_imm8("mov", Emit::emit_mov);
    test_word_ptr_imm16("mov", Emit::emit_mov);
    test_dword_ptr_imm32("mov", Emit::emit_mov);
    test_qword_ptr_imm32("mov", Emit::emit_mov);

    test_byte_ptr_reg8("mov", Emit::emit_mov);
    test_word_ptr_reg16("mov", Emit::emit_mov);
    test_dword_ptr_reg32("mov", Emit::emit_mov);
    test_qword_ptr_reg64("mov", Emit::emit_mov);
}

#[test]
fn test_push() {
    test_imm8("push", Emit::emit_push);
    test_imm16("push", Emit::emit_push);
    test_imm32("push", Emit::emit_push);

    test_reg16("push", Emit::emit_push);
    test_reg64("push", Emit::emit_push);

    test_word_ptr("push", Emit::emit_push);
    test_qword_ptr("push", Emit::emit_push);
}

#[test]
fn test_pop() {
    test_reg16("pop", Emit::emit_pop);
    test_reg64("pop", Emit::emit_pop);
    test_word_ptr("pop", Emit::emit_pop);
    test_qword_ptr("pop", Emit::emit_pop);
}

#[test]
fn test_call() {
    test_off32("call", Emit::emit_call);
    test_reg64("call", Emit::emit_call);
}

#[test]
fn test_jmp() {
    test_off8("jmp", Emit::emit_jmp);
    test_off32("jmp", Emit::emit_jmp);
    test_reg64("jmp", Emit::emit_jmp);
}

#[test]
fn test_ret() {
    test_unit("ret", Emit::emit_ret);
}

test_cmovcc! {
    (test_cmova,   "cmova",  Emit::emit_cmova),
    (test_cmovae,  "cmovae", Emit::emit_cmovae),
    (test_cmovb,   "cmovb",  Emit::emit_cmovb),
    (test_cmovbe,  "cmovbe", Emit::emit_cmovbe),
    (test_cmovc,   "cmovb",  Emit::emit_cmovc),
    (test_cmove,   "cmove",  Emit::emit_cmove),
    (test_cmovg,   "cmovg",  Emit::emit_cmovg),
    (test_cmovge,  "cmovge", Emit::emit_cmovge),
    (test_cmovl,   "cmovl",  Emit::emit_cmovl),
    (test_cmovle,  "cmovle", Emit::emit_cmovle),
    (test_cmovna,  "cmovbe", Emit::emit_cmovna),
    (test_cmovnae, "cmovb",  Emit::emit_cmovnae),
    (test_cmovnb,  "cmovae", Emit::emit_cmovnb),
    (test_cmovnbe, "cmova",  Emit::emit_cmovnbe),
    (test_cmovnc,  "cmovae", Emit::emit_cmovnc),
    (test_cmovne,  "cmovne", Emit::emit_cmovne),
    (test_cmovng,  "cmovle", Emit::emit_cmovng),
    (test_cmovnge, "cmovl",  Emit::emit_cmovnge),
    (test_cmovnl,  "cmovge", Emit::emit_cmovnl),
    (test_cmovnle, "cmovg",  Emit::emit_cmovnle),
    (test_cmovno,  "cmovno", Emit::emit_cmovno),
    (test_cmovnp,  "cmovnp", Emit::emit_cmovnp),
    (test_cmovns,  "cmovns", Emit::emit_cmovns),
    (test_cmovnz,  "cmovne", Emit::emit_cmovnz),
    (test_cmovo,   "cmovo",  Emit::emit_cmovo),
    (test_cmovp,   "cmovp",  Emit::emit_cmovp),
    (test_cmovpe,  "cmovp",  Emit::emit_cmovpe),
    (test_cmovpo,  "cmovnp", Emit::emit_cmovpo),
    (test_cmovs,   "cmovs",  Emit::emit_cmovs),
    (test_cmovz,   "cmove",  Emit::emit_cmovz),
}

test_jcc! {
    (test_ja,   "ja",  Emit::emit_ja),
    (test_jae,  "jae", Emit::emit_jae),
    (test_jb,   "jb",  Emit::emit_jb),
    (test_jbe,  "jbe", Emit::emit_jbe),
    (test_jc,   "jb",  Emit::emit_jc),
    (test_je,   "je",  Emit::emit_je),
    (test_jg,   "jg",  Emit::emit_jg),
    (test_jge,  "jge", Emit::emit_jge),
    (test_jl,   "jl",  Emit::emit_jl),
    (test_jle,  "jle", Emit::emit_jle),
    (test_jna,  "jbe", Emit::emit_jna),
    (test_jnae, "jb",  Emit::emit_jnae),
    (test_jnb,  "jae", Emit::emit_jnb),
    (test_jnbe, "ja",  Emit::emit_jnbe),
    (test_jnc,  "jae", Emit::emit_jnc),
    (test_jne,  "jne", Emit::emit_jne),
    (test_jng,  "jle", Emit::emit_jng),
    (test_jnge, "jl",  Emit::emit_jnge),
    (test_jnl,  "jge", Emit::emit_jnl),
    (test_jnle, "jg",  Emit::emit_jnle),
    (test_jno,  "jno", Emit::emit_jno),
    (test_jnp,  "jnp", Emit::emit_jnp),
    (test_jns,  "jns", Emit::emit_jns),
    (test_jnz,  "jne", Emit::emit_jnz),
    (test_jo,   "jo",  Emit::emit_jo),
    (test_jp,   "jp",  Emit::emit_jp),
    (test_jpe,  "jp",  Emit::emit_jpe),
    (test_jpo,  "jnp", Emit::emit_jpo),
    (test_js,   "js",  Emit::emit_js),
    (test_jz,   "je",  Emit::emit_jz),
}

test_setcc! {
    (test_seta,   "seta",  Emit::emit_seta),
    (test_setae,  "setae", Emit::emit_setae),
    (test_setb,   "setb",  Emit::emit_setb),
    (test_setbe,  "setbe", Emit::emit_setbe),
    (test_setc,   "setb",  Emit::emit_setc),
    (test_sete,   "sete",  Emit::emit_sete),
    (test_setg,   "setg",  Emit::emit_setg),
    (test_setge,  "setge", Emit::emit_setge),
    (test_setl,   "setl",  Emit::emit_setl),
    (test_setle,  "setle", Emit::emit_setle),
    (test_setna,  "setbe", Emit::emit_setna),
    (test_setnae, "setb",  Emit::emit_setnae),
    (test_setnb,  "setae", Emit::emit_setnb),
    (test_setnbe, "seta",  Emit::emit_setnbe),
    (test_setnc,  "setae", Emit::emit_setnc),
    (test_setne,  "setne", Emit::emit_setne),
    (test_setng,  "setle", Emit::emit_setng),
    (test_setnge, "setl",  Emit::emit_setnge),
    (test_setnl,  "setge", Emit::emit_setnl),
    (test_setnle, "setg",  Emit::emit_setnle),
    (test_setno,  "setno", Emit::emit_setno),
    (test_setnp,  "setnp", Emit::emit_setnp),
    (test_setns,  "setns", Emit::emit_setns),
    (test_setnz,  "setne", Emit::emit_setnz),
    (test_seto,   "seto",  Emit::emit_seto),
    (test_setp,   "setp",  Emit::emit_setp),
    (test_setpe,  "setp",  Emit::emit_setpe),
    (test_setpo,  "setnp", Emit::emit_setpo),
    (test_sets,   "sets",  Emit::emit_sets),
    (test_setz,   "sete",  Emit::emit_setz),
}

#[test]
fn test_lea() {
    test_reg16_word_ptr("lea", Emit::emit_lea);
    test_reg32_dword_ptr("lea", Emit::emit_lea);
    test_reg64_qword_ptr("lea", Emit::emit_lea);
}

#[test]
fn test_movzx() {
    test_reg16_reg8("movzx", Emit::emit_movzx);
    test_reg32_reg8("movzx", Emit::emit_movzx);
    test_reg64_reg8("movzx", Emit::emit_movzx);

    test_reg32_reg16("movzx", Emit::emit_movzx);
    test_reg64_reg16("movzx", Emit::emit_movzx);

    test_reg16_byte_ptr("movzx", Emit::emit_movzx);
    test_reg32_byte_ptr("movzx", Emit::emit_movzx);
    test_reg64_byte_ptr("movzx", Emit::emit_movzx);

    test_reg32_word_ptr("movzx", Emit::emit_movzx);
    test_reg64_word_ptr("movzx", Emit::emit_movzx);
}

#[test]
fn test_movsx() {
    test_reg16_reg8("movsx", Emit::emit_movsx);
    test_reg32_reg8("movsx", Emit::emit_movsx);
    test_reg64_reg8("movsx", Emit::emit_movsx);

    test_reg32_reg16("movsx", Emit::emit_movsx);
    test_reg64_reg16("movsx", Emit::emit_movsx);

    test_reg16_byte_ptr("movsx", Emit::emit_movsx);
    test_reg32_byte_ptr("movsx", Emit::emit_movsx);
    test_reg64_byte_ptr("movsx", Emit::emit_movsx);

    test_reg32_word_ptr("movsx", Emit::emit_movsx);
    test_reg64_word_ptr("movsx", Emit::emit_movsx);
}

#[test]
fn test_cdq() {
    test_unit("cdq", Emit::emit_cdq);
}

#[test]
fn test_xchg() {
    test_reg8_reg8("xchg", Emit::emit_xchg);
    test_different_reg_reg("xchg", |v, (r1, r2)| Emit::emit_xchg(v, r1, r2),
                           REGS16,
                           |r1, r2| (Operand::Reg16(r1), Operand::Reg16(r2)),
                           |s1, s2| format!("{}, {}", s1, s2));
    test_different_reg_reg("xchg", |v, (r1, r2)| Emit::emit_xchg(v, r1, r2),
                           REGS32,
                           |r1, r2| (Operand::Reg32(r1), Operand::Reg32(r2)),
                           |s1, s2| format!("{}, {}", s1, s2));
    test_different_reg_reg("xchg", |v, (r1, r2)| Emit::emit_xchg(v, r1, r2),
                           REGS64,
                           |r1, r2| (Operand::Reg64(r1), Operand::Reg64(r2)),
                           |s1, s2| format!("{}, {}", s1, s2));

    test_byte_ptr_reg8("xchg", Emit::emit_xchg);
    test_word_ptr_reg16("xchg", Emit::emit_xchg);
    test_dword_ptr_reg32("xchg", Emit::emit_xchg);
    test_qword_ptr_reg64("xchg", Emit::emit_xchg);

    fn test_different_reg_reg<'a, F, RS, AF, DF, R, T, S>(mnemonic: &str, f: F, regs: RS, arg: AF, disasm: DF)
        where F: Fn(&mut Vec<u8>, T) -> Result<()>,
              RS: AsRef<[(R, &'static str)]>,
              AF: Fn(R, R) -> T,
              DF: Fn(&'a str, &'a str) -> S,
              R: Copy + PartialEq,
              S: 'a + AsRef<str>
    {
        let mut code = Vec::new();

        let regs = regs.as_ref();

        for i in 0..(regs.len()-1) {
            let &(r1, _) = &regs[i];
            for &(r2, _) in &regs[i+1..] {
                f(&mut code, arg(r1, r2)).unwrap();
            }
        }

        print_code(&code);

        let mut expected_disasm = Vec::new();

        for i in 0..(regs.len()-1) {
            let &(_, s1) = &regs[i];
            for &(_, s2) in &regs[i+1..] {
                expected_disasm.push(Some(disasm(s1, s2)));
            }
        }

        test_disasm(mnemonic, &expected_disasm, &code);
    }
}

#[test]
fn test_ud2() {
    test_unit("ud2", Emit::emit_ud2);
}
