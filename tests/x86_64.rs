extern crate mitte_amd64;
extern crate capstone;

use mitte_amd64::x86_64::error::Error;
use mitte_amd64::x86_64::base::Emit;
use mitte_amd64::x86_64::Register;
use mitte_amd64::x86_64::types::*;
use mitte_amd64::x86_64::reg::*;
use mitte_amd64::x86_64::ptr::{Byte, Word, DWord, QWord, Pointer};

use capstone::Capstone;
use capstone::arch::BuildsCapstone;
use capstone::arch::x86::ArchMode;

type Result<T> = std::result::Result<T, Error<std::convert::Infallible>>;


fn print_code(code: &[u8]) {
    print!("[");
    for b in code {
        print!("{:02x}", b);
    }
    println!("]");
}


fn test_disasm<S>(mnemonic: &str, expected: S, code: &[u8]) where S: AsRef<str> {
    let capstone = Capstone::new().x86()
        .mode(ArchMode::Mode64)
        .build().unwrap();
    let disasm = match capstone.disasm_all(code, 0x0) {
        Ok(disasm) => disasm,
        Err(error) => {
            print_code(code);
            panic!("failed to disassemble: {:?}", error);
        }
    };

    for (i, e) in disasm.iter().zip(std::iter::once(expected)) {
        println!("disasm: {:?} {:?}", i.mnemonic(), i.op_str());
        assert_eq!(mnemonic, i.mnemonic().unwrap(),
            "{} {:?} != {} {:?}",
            mnemonic, e.as_ref(),
            i.mnemonic().unwrap(), i.op_str().unwrap());
        assert_eq!(Some(e.as_ref()), i.op_str(),
            "{} {:?} != {0} {:?}", mnemonic,
            e.as_ref(), i.op_str().unwrap());
    }
    assert_eq!(disasm.len(), 1);
}


fn are_registers_compatible<R1, R2>(r1: R1, r2: R2) -> bool
where R1: Register, R2: Register
{
    if r1.needs_rex() && !r2.is_encodable_with_rex() {
        return false;
    }
    if r2.needs_rex() && !r1.is_encodable_with_rex() {
        return false;
    }
    true
}


fn is_signed_nbit_integer(n: u8, value: impl Into<i64>) -> bool {
    let value = value.into();
    ((-1) << (n - 1)) <= value && value < (1 << (n - 1))
}


trait TestCases: Sized + Copy + 'static {
    fn test_cases() -> Vec<(Self, String)>;
}

impl TestCases for Condition {
    fn test_cases() -> Vec<(Self, String)> {
        vec![
            (Condition::O, "o".into()),
            (Condition::No, "no".into()),
            (Condition::B, "b".into()),
            (Condition::Ae, "ae".into()),
            (Condition::E, "e".into()),
            (Condition::Ne, "ne".into()),
            (Condition::Be, "be".into()),
            (Condition::A, "a".into()),
            (Condition::S, "s".into()),
            (Condition::Ns, "ns".into()),
            (Condition::P, "p".into()),
            (Condition::Np, "np".into()),
            (Condition::L, "l".into()),
            (Condition::Ge, "ge".into()),
            (Condition::Le, "le".into()),
            (Condition::G, "g".into()),
        ]
    }
}

impl TestCases for u8 {
    fn test_cases() -> Vec<(Self, String)> {
        vec![
            (0, "0".into()),
            (1, "1".into()),
            (31, "0x1f".into()),
            (32, "0x20".into()),
            (63, "0x3f".into()),
            (64, "0x40".into()),
            (0x7f, "0x7f".into()),
            (0x80, "0x80".into()),
        ]
    }
}

impl TestCases for i8 {
    fn test_cases() -> Vec<(Self, String)> {
        vec![
            (0, "0".into()),
            (1, "1".into()),
            (31, "0x1f".into()),
            (32, "0x20".into()),
            (63, "0x3f".into()),
            (64, "0x40".into()),
            (0x7f, "0x7f".into()),
            (-1, "-1".into()),
            (-0x80, "-0x80".into()),
        ]
    }
}

impl TestCases for u16 {
    fn test_cases() -> Vec<(Self, String)> {
        vec![
            (0, "0".into()),
            (0x80, "0x80".into()),
            (0x800, "0x800".into()),
            (0x7fff, "0x7fff".into()),
            (0x8000, "0x8000".into()),
            (0xff80, "0xff80".into()),
            (0xffff, "0xffff".into()),
        ]
    }
}

impl TestCases for u32 {
    fn test_cases() -> Vec<(Self, String)> {
        vec![
            (0, "0".into()),
            (0x80, "0x80".into()),
            (0x8000, "0x8000".into()),
            (0x80_0000, "0x800000".into()),
            (0x7fff_ffff, "0x7fffffff".into()),
            (0x8000_0000, "0x80000000".into()),
            (0xffff_8000, "0xffff8000".into()),
            (0xffff_ff80, "0xffffff80".into()),
            (0xffff_ffff, "0xffffffff".into()),
        ]
    }
}

impl TestCases for i32 {
    fn test_cases() -> Vec<(Self, String)> {
        vec![
            (0, "0".into()),
            (0x80, "0x80".into()),
            (0x8000, "0x8000".into()),
            (0x80_0000, "0x800000".into()),
            (0x7fff_ffff, "0x7fffffff".into()),
            (-0x80, "-0x80".into()),
            (-0x8000, "-0x8000".into()),
            (-0x80_0000, "-0x800000".into()),
            (-0x8000_0000, "-0x80000000".into()),
        ]
    }
}

impl TestCases for u64 {
    fn test_cases() -> Vec<(Self, String)> {
        vec![
            (0, "0".into()),
            (0x80, "0x80".into()),
            (0x8000, "0x8000".into()),
            (0x80_0000, "0x800000".into()),
            (0x8000_0000, "0x80000000".into()),
            (0x8000_0000_0000, "0x800000000000".into()),
            (0x7fff_ffff_ffff_ffff, "0x7fffffffffffffff".into()),
            (0x8000_0000_0000_0000, "0x8000000000000000".into()),
            (0xffff_8000_0000_0000, "0xffff800000000000".into()),
            (0xffff_ffff_8000_0000, "0xffffffff80000000".into()),
            (0xffff_ffff_ffff_8000, "0xffffffffffff8000".into()),
            (0xffff_ffff_ffff_ff80, "0xffffffffffffff80".into()),
            (0xffff_ffff_ffff_ffff, "0xffffffffffffffff".into()),
        ]
    }
}

impl TestCases for Rel8 {
    fn test_cases() -> Vec<(Self, String)> {
        vec![
            (0_i8.into(), "0".into()),
            (8_i8.into(), "8".into()),
            (0x7f_i8.into(), "0x7f".into()),
            ((-1_i8).into(), "0xffffffffffffffff".into()),
            ((-0x8_i8).into(), "0xfffffffffffffff8".into()),
        ]
    }
}

impl TestCases for Rel32 {
    fn test_cases() -> Vec<(Self, String)> {
        vec![
            (0_i32.into(), "0".into()),
            (0x80_i32.into(), "0x80".into()),
            (0x8000_i32.into(), "0x8000".into()),
            (0x80_0000_i32.into(), "0x800000".into()),
            (0x7fff_ffff_i32.into(), "0x7fffffff".into()),
            ((-1_i32).into(), "0xffffffffffffffff".into()),
            ((-0x80_i32).into(), "0xffffffffffffff80".into()),
            ((-0x8000_i32).into(), "0xffffffffffff8000".into()),
            ((-0x80_0000_i32).into(), "0xffffffffff800000".into()),
            ((-0x800_0000_i32).into(), "0xfffffffff8000000".into()),
        ]
    }
}

impl TestCases for Reg8 {
    fn test_cases() -> Vec<(Self, String)> {
        vec![
            (Al, "al".into()),
            (Cl, "cl".into()),
            (Dl, "dl".into()),
            (Bl, "bl".into()),
            (Ah, "ah".into()),
            (Ch, "ch".into()),
            (Dh, "dh".into()),
            (Bh, "bh".into()),
            (R8b, "r8b".into()),
            (R9b, "r9b".into()),
            (R10b, "r10b".into()),
            (R11b, "r11b".into()),
            (R12b, "r12b".into()),
            (R13b, "r13b".into()),
            (R14b, "r14b".into()),
            (R15b, "r15b".into()),
            (Spl, "spl".into()),
            (Bpl, "bpl".into()),
            (Sil, "sil".into()),
            (Dil, "dil".into()),
        ]
    }
}

impl TestCases for Reg16 {
    fn test_cases() -> Vec<(Self, String)> {
        vec![
            (Ax, "ax".into()),
            (Cx, "cx".into()),
            (Dx, "dx".into()),
            (Bx, "bx".into()),
            (Sp, "sp".into()),
            (Bp, "bp".into()),
            (Si, "si".into()),
            (Di, "di".into()),
            (R8w, "r8w".into()),
            (R9w, "r9w".into()),
            (R10w, "r10w".into()),
            (R11w, "r11w".into()),
            (R12w, "r12w".into()),
            (R13w, "r13w".into()),
            (R14w, "r14w".into()),
            (R15w, "r15w".into()),
        ]
    }
}

impl TestCases for Reg32 {
    fn test_cases() -> Vec<(Self, String)> {
        vec![
            (Eax, "eax".into()),
            (Ecx, "ecx".into()),
            (Edx, "edx".into()),
            (Ebx, "ebx".into()),
            (Esp, "esp".into()),
            (Ebp, "ebp".into()),
            (Esi, "esi".into()),
            (Edi, "edi".into()),
            (R8d, "r8d".into()),
            (R9d, "r9d".into()),
            (R10d, "r10d".into()),
            (R11d, "r11d".into()),
            (R12d, "r12d".into()),
            (R13d, "r13d".into()),
            (R14d, "r14d".into()),
            (R15d, "r15d".into()),
        ]
    }
}

impl TestCases for Reg64 {
    fn test_cases() -> Vec<(Self, String)> {
        vec![
            (Rax, "rax".into()),
            (Rcx, "rcx".into()),
            (Rdx, "rdx".into()),
            (Rbx, "rbx".into()),
            (Rsp, "rsp".into()),
            (Rbp, "rbp".into()),
            (Rsi, "rsi".into()),
            (Rdi, "rdi".into()),
            (R8, "r8".into()),
            (R9, "r9".into()),
            (R10, "r10".into()),
            (R11, "r11".into()),
            (R12, "r12".into()),
            (R13, "r13".into()),
            (R14, "r14".into()),
            (R15, "r15".into()),
        ]
    }
}

fn pointer_test_cases<P>(size: &str, pointer: fn(Pointer) -> P) -> Vec<(P, String)> {
    let mut test_cases = Vec::new();

    test_cases.push((pointer(0x42_i8.into()), format!("{size} ptr [0x42]")));
    test_cases.push((pointer(0x12345678_i32.into()), format!("{size} ptr [0x12345678]")));

    for (r1, s1) in Reg64::test_cases() {
        test_cases.push((pointer(r1.into()), format!("{size} ptr [{s1}]")));
        test_cases.push((pointer((r1 + 0x42_i8).into()), format!("{size} ptr [{s1} + 0x42]")));
        test_cases.push((
            pointer((r1 + 0x12345678_i32).into()),
            format!("{size} ptr [{s1} + 0x12345678]")
        ));

        if r1 != Rsp && r1 != R12 {
            test_cases.push((pointer((r1*4).into()), format!("{size} ptr [{s1}*4]")));
            test_cases.push((
                pointer((r1*4 + 0x42_i8).into()),
                format!("{size} ptr [{s1}*4 + 0x42]")
            ));
            test_cases.push((
                pointer((r1*4 + 0x12345678_i32).into()),
                format!("{size} ptr [{s1}*4 + 0x12345678]")
            ));

            for (r2, s2) in Reg64::test_cases() {
                if r2 == Rsp || r2 == R12 {
                    continue;
                }

                test_cases.push((
                    pointer((r1 + r2).into()),
                    format!("{size} ptr [{s1} + {s2}]")
                ));
                test_cases.push((
                    pointer((r1 + r2 + 0x42_i8).into()),
                    format!("{size} ptr [{s1} + {s2} + 0x42]")
                ));
                test_cases.push((
                    pointer((r1 + r2 + 0x12345678_i32).into()),
                    format!("{size} ptr [{s1} + {s2} + 0x12345678]")
                ));
                test_cases.push((
                    pointer((r1 + r2*4).into()),
                    format!("{size} ptr [{s1} + {s2}*4]")
                ));
                test_cases.push((
                    pointer((r1 + r2*4 + 0x42_i8).into()),
                    format!("{size} ptr [{s1} + {s2}*4 + 0x42]")
                ));
                test_cases.push((
                    pointer((r1 + r2*4 + 0x12345678_i32).into()),
                    format!("{size} ptr [{s1} + {s2}*4 + 0x12345678]")
                ));
            }
        }
    }

    test_cases
}

impl TestCases for Byte<Pointer> {
    fn test_cases() -> Vec<(Self, String)> {
        pointer_test_cases("byte", |p| Byte(p))
    }
}

impl TestCases for Word<Pointer> {
    fn test_cases() -> Vec<(Self, String)> {
        pointer_test_cases("word", |p| Word(p))
    }
}

impl TestCases for DWord<Pointer> {
    fn test_cases() -> Vec<(Self, String)> {
        pointer_test_cases("dword", |p| DWord(p))
    }
}

impl TestCases for QWord<Pointer> {
    fn test_cases() -> Vec<(Self, String)> {
        pointer_test_cases("qword", |p| QWord(p))
    }
}


#[track_caller]
fn test0(mnemonic: &str, f: fn(&mut Vec<u8>) -> Result<()>) {
    let mut code = Vec::new();
    f(&mut code).unwrap();
    test_disasm(mnemonic, "", &code);
}

#[track_caller]
fn test1_format_filter<A1>(
    mnemonic: &str,
    f: fn(&mut Vec<u8>, A1) -> Result<()>,
    s: impl Fn(&str) -> String,
    mut filter: impl FnMut(A1) -> bool
)
    where A1: TestCases
{
    let mut code = Vec::new();
    for (a1, s1) in A1::test_cases() {
        if filter(a1) {
            f(&mut code, a1).unwrap();
            test_disasm(mnemonic, s(&s1), &code);
            code.clear();
        }
    }
}

#[track_caller]
fn test1_format<A1>(
    mnemonic: &str,
    f: fn(&mut Vec<u8>, A1) -> Result<()>,
    s: impl Fn(&str) -> String
)
    where A1: TestCases
{
    test1_format_filter(mnemonic, f, s, |_| true);
}

#[track_caller]
fn test1<A1>(mnemonic: &str, f: fn(&mut Vec<u8>, A1) -> Result<()>)
    where A1: TestCases
{
    test1_format(mnemonic, f, |s1| format!("{}", s1));
}

#[track_caller]
fn test2_format_filter<A1, A2>(
    mnemonic: &str,
    f: fn(&mut Vec<u8>, A1, A2) -> Result<()>,
    s: impl Fn(&str, &str) -> String,
    mut filter: impl FnMut(A1, A2) -> bool
)
    where A1: TestCases, A2: TestCases
{
    let mut code = Vec::new();
    for (a1, s1) in A1::test_cases() {
        for (a2, s2) in A2::test_cases() {
            if filter(a1, a2) {
                f(&mut code, a1, a2).unwrap();
                test_disasm(mnemonic, s(&s1, &s2), &code);
                code.clear();
            }
        }
    }
}

#[track_caller]
fn test2_filter<A1, A2>(
    mnemonic: &str,
    f: fn(&mut Vec<u8>, A1, A2) -> Result<()>,
    filter: impl FnMut(A1, A2) -> bool
)
    where A1: TestCases, A2: TestCases
{
    test2_format_filter(mnemonic,
        f,
        |s1, s2| format!("{}, {}", s1, s2),
        filter)
}

#[track_caller]
fn test2<A1, A2>(mnemonic: &str, f: fn(&mut Vec<u8>, A1, A2) -> Result<()>)
    where A1: TestCases, A2: TestCases
{
    test2_filter(mnemonic, f, |_, _| true);
}

#[track_caller]
fn test2_cond<A2>(mnemonic: &str, f: fn(&mut Vec<u8>, Condition, A2) -> Result<()>)
    where A2: TestCases
{
    let mut code = Vec::new();
    for (a1, s1) in Condition::test_cases() {
        for (a2, s2) in A2::test_cases() {
            f(&mut code, a1, a2).unwrap();
            test_disasm(&format!("{mnemonic}{s1}"), s2, &code);
            code.clear();
        }
    }
}

#[track_caller]
fn test3_cond<A2, A3>(mnemonic: &str, f: fn(&mut Vec<u8>, Condition, A2, A3) -> Result<()>)
    where A2: TestCases, A3: TestCases
{
    let mut code = Vec::new();
    for (a1, s1) in Condition::test_cases() {
        for (a2, s2) in A2::test_cases() {
            for (a3, s3) in A3::test_cases() {
                f(&mut code, a1, a2, a3).unwrap();
                test_disasm(&format!("{mnemonic}{s1}"), format!("{s2}, {s3}"), &code);
                code.clear();
            }
        }
    }
}


#[test]
fn test_adc_al_i8() {
    test1_format("adc", Emit::emit_adc_al_i8, |s| format!("al, {s}"));
}

#[test]
fn test_adc_ax_i16() {
    test1_format("adc", Emit::emit_adc_ax_i16, |s| format!("ax, {s}"));
}

#[test]
fn test_adc_eax_i32() {
    test1_format("adc", Emit::emit_adc_eax_i32, |s| format!("eax, {s}"));
}

#[test]
fn test_adc_rax_i32() {
    test1_format("adc", Emit::emit_adc_rax_i32, |s| format!("rax, {s}"));
}

#[test]
fn test_adc_ri8() {
    test2("adc", Emit::emit_adc_ri8);
}

#[test]
fn test_adc_ri16() {
    test2("adc", Emit::emit_adc_ri16);
}

#[test]
fn test_adc_ri32() {
    test2("adc", Emit::emit_adc_ri32);
}

#[test]
fn test_adc_r64_i32() {
    test2("adc", Emit::emit_adc_r64_i32);
}

#[test]
fn test_adc_r16_i8() {
    test2("adc", Emit::emit_adc_r16_i8);
}

#[test]
fn test_adc_r32_i8() {
    test2("adc", Emit::emit_adc_r32_i8);
}

#[test]
fn test_adc_r64_i8() {
    test2("adc", Emit::emit_adc_r64_i8);
}

#[test]
fn test_adc_rr8() {
    test2_filter("adc", Emit::emit_adc_rr8, |r1, r2| {
        are_registers_compatible(r1, r2)
    });
}

#[test]
fn test_adc_rr16() {
    test2("adc", Emit::emit_adc_rr16);
}

#[test]
fn test_adc_rr32() {
    test2("adc", Emit::emit_adc_rr32);
}

#[test]
fn test_adc_rr64() {
    test2("adc", Emit::emit_adc_rr64);
}

#[test]
fn test_adc_rm8() {
    test2_filter("adc", Emit::emit_adc_rm8, |r, _| {
        r.is_encodable_with_rex()
    });
}

#[test]
fn test_adc_rm16() {
    test2("adc", Emit::emit_adc_rm16);
}

#[test]
fn test_adc_rm32() {
    test2("adc", Emit::emit_adc_rm32);
}

#[test]
fn test_adc_rm64() {
    test2("adc", Emit::emit_adc_rm64);
}

#[test]
fn test_adc_mi8() {
    test2("adc", Emit::emit_adc_mi8);
}

#[test]
fn test_adc_mi16() {
    test2("adc", Emit::emit_adc_mi16);
}

#[test]
fn test_adc_mi32() {
    test2("adc", Emit::emit_adc_mi32);
}

#[test]
fn test_adc_m64_i32() {
    test2("adc", Emit::emit_adc_m64_i32);
}

#[test]
fn test_adc_m16_i8() {
    test2("adc", Emit::emit_adc_m16_i8);
}

#[test]
fn test_adc_m32_i8() {
    test2("adc", Emit::emit_adc_m32_i8);
}

#[test]
fn test_adc_m64_i8() {
    test2("adc", Emit::emit_adc_m64_i8);
}

#[test]
fn test_adc_mr8() {
    test2_filter("adc", Emit::emit_adc_mr8, |_, r| {
        r.is_encodable_with_rex()
    });
}

#[test]
fn test_adc_mr16() {
    test2("adc", Emit::emit_adc_mr16);
}

#[test]
fn test_adc_mr32() {
    test2("adc", Emit::emit_adc_mr32);
}

#[test]
fn test_adc_mr64() {
    test2("adc", Emit::emit_adc_mr64);
}

#[test]
fn test_add_al_i8() {
    test1_format("add", Emit::emit_add_al_i8, |s| format!("al, {s}"));
}

#[test]
fn test_add_ax_i16() {
    test1_format("add", Emit::emit_add_ax_i16, |s| format!("ax, {s}"));
}

#[test]
fn test_add_eax_i32() {
    test1_format("add", Emit::emit_add_eax_i32, |s| format!("eax, {s}"));
}

#[test]
fn test_add_rax_i32() {
    test1_format("add", Emit::emit_add_rax_i32, |s| format!("rax, {s}"));
}

#[test]
fn test_add_ri8() {
    test2("add", Emit::emit_add_ri8);
}

#[test]
fn test_add_ri16() {
    test2("add", Emit::emit_add_ri16);
}

#[test]
fn test_add_ri32() {
    test2("add", Emit::emit_add_ri32);
}

#[test]
fn test_add_r64_i32() {
    test2("add", Emit::emit_add_r64_i32);
}

#[test]
fn test_add_r16_i8() {
    test2("add", Emit::emit_add_r16_i8);
}

#[test]
fn test_add_r32_i8() {
    test2("add", Emit::emit_add_r32_i8);
}

#[test]
fn test_add_r64_i8() {
    test2("add", Emit::emit_add_r64_i8);
}

#[test]
fn test_add_rr8() {
    test2_filter("add", Emit::emit_add_rr8, |r1, r2| {
        are_registers_compatible(r1, r2)
    });
}

#[test]
fn test_add_rr16() {
    test2("add", Emit::emit_add_rr16);
}

#[test]
fn test_add_rr32() {
    test2("add", Emit::emit_add_rr32);
}

#[test]
fn test_add_rr64() {
    test2("add", Emit::emit_add_rr64);
}

#[test]
fn test_add_rm8() {
    test2_filter("add", Emit::emit_add_rm8, |r, _| {
        r.is_encodable_with_rex()
    });
}

#[test]
fn test_add_rm16() {
    test2("add", Emit::emit_add_rm16);
}

#[test]
fn test_add_rm32() {
    test2("add", Emit::emit_add_rm32);
}

#[test]
fn test_add_rm64() {
    test2("add", Emit::emit_add_rm64);
}

#[test]
fn test_add_mi8() {
    test2("add", Emit::emit_add_mi8);
}

#[test]
fn test_add_mi16() {
    test2("add", Emit::emit_add_mi16);
}

#[test]
fn test_add_mi32() {
    test2("add", Emit::emit_add_mi32);
}

#[test]
fn test_add_m64_i32() {
    test2("add", Emit::emit_add_m64_i32);
}

#[test]
fn test_add_m16_i8() {
    test2("add", Emit::emit_add_m16_i8);
}

#[test]
fn test_add_m32_i8() {
    test2("add", Emit::emit_add_m32_i8);
}

#[test]
fn test_add_m64_i8() {
    test2("add", Emit::emit_add_m64_i8);
}

#[test]
fn test_add_mr8() {
    test2_filter("add", Emit::emit_add_mr8, |_, r| {
        r.is_encodable_with_rex()
    });
}

#[test]
fn test_add_mr16() {
    test2("add", Emit::emit_add_mr16);
}

#[test]
fn test_add_mr32() {
    test2("add", Emit::emit_add_mr32);
}

#[test]
fn test_add_mr64() {
    test2("add", Emit::emit_add_mr64);
}

#[test]
fn test_and_al_i8() {
    test1_format("and", Emit::emit_and_al_i8, |s| format!("al, {s}"));
}

#[test]
fn test_and_ax_i16() {
    test1_format("and", Emit::emit_and_ax_i16, |s| format!("ax, {s}"));
}

#[test]
fn test_and_eax_i32() {
    test1_format("and", Emit::emit_and_eax_i32, |s| format!("eax, {s}"));
}

#[test]
fn test_and_rax_i32() {
    test1_format_filter::<u64>("and", |e, imm| e.emit_and_rax_i32(imm as i32),
        |s| format!("rax, {s}"),
        |imm| is_signed_nbit_integer(32, imm as i64));
}

#[test]
fn test_and_ri8() {
    test2("and", Emit::emit_and_ri8);
}

#[test]
fn test_and_ri16() {
    test2("and", Emit::emit_and_ri16);
}

#[test]
fn test_and_ri32() {
    test2("and", Emit::emit_and_ri32);
}

#[test]
fn test_and_r64_i32() {
    test2_filter::<_, u64>("and", |e, r, imm| e.emit_and_r64_i32(r, imm as i32),
        |_, imm| is_signed_nbit_integer(32, imm as i64));
}

#[test]
fn test_and_r16_i8() {
    test2_filter::<_, u16>("and", |e, r, imm| e.emit_and_r16_i8(r, imm as i8),
        |_, imm| is_signed_nbit_integer(8, imm as i16));
}

#[test]
fn test_and_r32_i8() {
    test2_filter::<_, u32>("and", |e, r, imm| e.emit_and_r32_i8(r, imm as i8),
        |_, imm| is_signed_nbit_integer(8, imm as i32));
}

#[test]
fn test_and_r64_i8() {
    test2_filter::<_, u64>("and", |e, r, imm| e.emit_and_r64_i8(r, imm as i8),
        |_, imm| is_signed_nbit_integer(8, imm as i64));
}

#[test]
fn test_and_rr8() {
    test2_filter("and", Emit::emit_and_rr8, |r1, r2| {
        are_registers_compatible(r1, r2)
    });
}

#[test]
fn test_and_rr16() {
    test2("and", Emit::emit_and_rr16);
}

#[test]
fn test_and_rr32() {
    test2("and", Emit::emit_and_rr32);
}

#[test]
fn test_and_rr64() {
    test2("and", Emit::emit_and_rr64);
}

#[test]
fn test_and_rm8() {
    test2_filter("and", Emit::emit_and_rm8, |r, _| {
        r.is_encodable_with_rex()
    });
}

#[test]
fn test_and_rm16() {
    test2("and", Emit::emit_and_rm16);
}

#[test]
fn test_and_rm32() {
    test2("and", Emit::emit_and_rm32);
}

#[test]
fn test_and_rm64() {
    test2("and", Emit::emit_and_rm64);
}

#[test]
fn test_and_mi8() {
    test2("and", Emit::emit_and_mi8);
}

#[test]
fn test_and_mi16() {
    test2("and", Emit::emit_and_mi16);
}

#[test]
fn test_and_mi32() {
    test2("and", Emit::emit_and_mi32);
}

#[test]
fn test_and_m64_i32() {
    test2_filter::<_, u64>("and", |e, m, imm| e.emit_and_m64_i32(m, imm as i32),
        |_, imm| is_signed_nbit_integer(32, imm as i64));
}

#[test]
fn test_and_m16_i8() {
    test2_filter::<_, u16>("and", |e, m, imm| e.emit_and_m16_i8(m, imm as i8),
        |_, imm| is_signed_nbit_integer(8, imm as i16));
}

#[test]
fn test_and_m32_i8() {
    test2_filter::<_, u32>("and", |e, m, imm| e.emit_and_m32_i8(m, imm as i8),
        |_, imm| is_signed_nbit_integer(8, imm as i32));
}

#[test]
fn test_and_m64_i8() {
    test2_filter::<_, u64>("and", |e, m, imm| e.emit_and_m64_i8(m, imm as i8),
        |_, imm| is_signed_nbit_integer(8, imm as i64));
}

#[test]
fn test_and_mr8() {
    test2_filter("and", Emit::emit_and_mr8, |_, r| {
        r.is_encodable_with_rex()
    });
}

#[test]
fn test_and_mr16() {
    test2("and", Emit::emit_and_mr16);
}

#[test]
fn test_and_mr32() {
    test2("and", Emit::emit_and_mr32);
}

#[test]
fn test_and_mr64() {
    test2("and", Emit::emit_and_mr64);
}

#[test]
fn test_bsf_rr16() {
    test2("bsf", Emit::emit_bsf_rr16);
}

#[test]
fn test_bsf_rr32() {
    test2("bsf", Emit::emit_bsf_rr32);
}

#[test]
fn test_bsf_rr64() {
    test2("bsf", Emit::emit_bsf_rr64);
}

#[test]
fn test_bsf_rm16() {
    test2("bsf", Emit::emit_bsf_rm16);
}

#[test]
fn test_bsf_rm32() {
    test2("bsf", Emit::emit_bsf_rm32);
}

#[test]
fn test_bsf_rm64() {
    test2("bsf", Emit::emit_bsf_rm64);
}

#[test]
fn test_bsr_rr16() {
    test2("bsr", Emit::emit_bsr_rr16);
}

#[test]
fn test_bsr_rr32() {
    test2("bsr", Emit::emit_bsr_rr32);
}

#[test]
fn test_bsr_rr64() {
    test2("bsr", Emit::emit_bsr_rr64);
}

#[test]
fn test_bsr_rm16() {
    test2("bsr", Emit::emit_bsr_rm16);
}

#[test]
fn test_bsr_rm32() {
    test2("bsr", Emit::emit_bsr_rm32);
}

#[test]
fn test_bsr_rm64() {
    test2("bsr", Emit::emit_bsr_rm64);
}

#[test]
fn test_call_rel32() {
    test1("call", Emit::emit_call_rel32);
}

#[test]
fn test_call_r64() {
    test1("call", Emit::emit_call_r64);
}

#[test]
fn test_cdq() {
    test0("cdq", Emit::emit_cdq);
}

#[test]
fn test_cmovcc_rr16() {
    test3_cond("cmov", Emit::emit_cmovcc_rr16);
}

#[test]
fn test_cmovcc_rr32() {
    test3_cond("cmov", Emit::emit_cmovcc_rr32);
}

#[test]
fn test_cmovcc_rr64() {
    test3_cond("cmov", Emit::emit_cmovcc_rr64);
}

#[test]
fn test_cmovcc_rm16() {
    test3_cond("cmov", Emit::emit_cmovcc_rm16);
}

#[test]
fn test_cmovcc_rm32() {
    test3_cond("cmov", Emit::emit_cmovcc_rm32);
}

#[test]
fn test_cmovcc_rm64() {
    test3_cond("cmov", Emit::emit_cmovcc_rm64);
}

#[test]
fn test_cmp_al_i8() {
    test1_format("cmp", Emit::emit_cmp_al_i8, |s| format!("al, {s}"));
}

#[test]
fn test_cmp_ax_i16() {
    test1_format("cmp", Emit::emit_cmp_ax_i16, |s| format!("ax, {s}"));
}

#[test]
fn test_cmp_eax_i32() {
    test1_format("cmp", Emit::emit_cmp_eax_i32, |s| format!("eax, {s}"));
}

#[test]
fn test_cmp_rax_i32() {
    test1_format("cmp", Emit::emit_cmp_rax_i32, |s| format!("rax, {s}"));
}

#[test]
fn test_cmp_ri8() {
    test2("cmp", Emit::emit_cmp_ri8);
}

#[test]
fn test_cmp_ri16() {
    test2("cmp", Emit::emit_cmp_ri16);
}

#[test]
fn test_cmp_ri32() {
    test2("cmp", Emit::emit_cmp_ri32);
}

#[test]
fn test_cmp_r64_i32() {
    test2("cmp", Emit::emit_cmp_r64_i32);
}

#[test]
fn test_cmp_r16_i8() {
    test2("cmp", Emit::emit_cmp_r16_i8);
}

#[test]
fn test_cmp_r32_i8() {
    test2("cmp", Emit::emit_cmp_r32_i8);
}

#[test]
fn test_cmp_r64_i8() {
    test2("cmp", Emit::emit_cmp_r64_i8);
}

#[test]
fn test_cmp_rr8() {
    test2_filter("cmp", Emit::emit_cmp_rr8, |r1, r2| {
        are_registers_compatible(r1, r2)
    });
}

#[test]
fn test_cmp_rr16() {
    test2("cmp", Emit::emit_cmp_rr16);
}

#[test]
fn test_cmp_rr32() {
    test2("cmp", Emit::emit_cmp_rr32);
}

#[test]
fn test_cmp_rr64() {
    test2("cmp", Emit::emit_cmp_rr64);
}

#[test]
fn test_cmp_rm8() {
    test2_filter("cmp", Emit::emit_cmp_rm8, |r, _| {
        r.is_encodable_with_rex()
    });
}

#[test]
fn test_cmp_rm16() {
    test2("cmp", Emit::emit_cmp_rm16);
}

#[test]
fn test_cmp_rm32() {
    test2("cmp", Emit::emit_cmp_rm32);
}

#[test]
fn test_cmp_rm64() {
    test2("cmp", Emit::emit_cmp_rm64);
}

#[test]
fn test_cmp_mi8() {
    test2("cmp", Emit::emit_cmp_mi8);
}

#[test]
fn test_cmp_mi16() {
    test2("cmp", Emit::emit_cmp_mi16);
}

#[test]
fn test_cmp_mi32() {
    test2("cmp", Emit::emit_cmp_mi32);
}

#[test]
fn test_cmp_m64_i32() {
    test2("cmp", Emit::emit_cmp_m64_i32);
}

#[test]
fn test_cmp_m16_i8() {
    test2("cmp", Emit::emit_cmp_m16_i8);
}

#[test]
fn test_cmp_m32_i8() {
    test2("cmp", Emit::emit_cmp_m32_i8);
}

#[test]
fn test_cmp_m64_i8() {
    test2("cmp", Emit::emit_cmp_m64_i8);
}

#[test]
fn test_cmp_mr8() {
    test2_filter("cmp", Emit::emit_cmp_mr8, |_, r| {
        r.is_encodable_with_rex()
    });
}

#[test]
fn test_cmp_mr16() {
    test2("cmp", Emit::emit_cmp_mr16);
}

#[test]
fn test_cmp_mr32() {
    test2("cmp", Emit::emit_cmp_mr32);
}

#[test]
fn test_cmp_mr64() {
    test2("cmp", Emit::emit_cmp_mr64);
}

#[test]
fn test_dec_r8() {
    test1("dec", Emit::emit_dec_r8);
}

#[test]
fn test_dec_r16() {
    test1("dec", Emit::emit_dec_r16);
}

#[test]
fn test_dec_r32() {
    test1("dec", Emit::emit_dec_r32);
}

#[test]
fn test_dec_r64() {
    test1("dec", Emit::emit_dec_r64);
}

#[test]
fn test_dec_m8() {
    test1("dec", Emit::emit_dec_m8);
}

#[test]
fn test_dec_m16() {
    test1("dec", Emit::emit_dec_m16);
}

#[test]
fn test_dec_m32() {
    test1("dec", Emit::emit_dec_m32);
}

#[test]
fn test_dec_m64() {
    test1("dec", Emit::emit_dec_m64);
}

#[test]
fn test_div_r8() {
    test1("div", Emit::emit_div_r8);
}

#[test]
fn test_div_r16() {
    test1("div", Emit::emit_div_r16);
}

#[test]
fn test_div_r32() {
    test1("div", Emit::emit_div_r32);
}

#[test]
fn test_div_r64() {
    test1("div", Emit::emit_div_r64);
}

#[test]
fn test_div_m8() {
    test1("div", Emit::emit_div_m8);
}

#[test]
fn test_div_m16() {
    test1("div", Emit::emit_div_m16);
}

#[test]
fn test_div_m32() {
    test1("div", Emit::emit_div_m32);
}

#[test]
fn test_div_m64() {
    test1("div", Emit::emit_div_m64);
}

#[test]
fn test_idiv_r8() {
    test1("idiv", Emit::emit_idiv_r8);
}

#[test]
fn test_idiv_r16() {
    test1("idiv", Emit::emit_idiv_r16);
}

#[test]
fn test_idiv_r32() {
    test1("idiv", Emit::emit_idiv_r32);
}

#[test]
fn test_idiv_r64() {
    test1("idiv", Emit::emit_idiv_r64);
}

#[test]
fn test_idiv_m8() {
    test1("idiv", Emit::emit_idiv_m8);
}

#[test]
fn test_idiv_m16() {
    test1("idiv", Emit::emit_idiv_m16);
}

#[test]
fn test_idiv_m32() {
    test1("idiv", Emit::emit_idiv_m32);
}

#[test]
fn test_idiv_m64() {
    test1("idiv", Emit::emit_idiv_m64);
}

#[test]
fn test_imul_r8() {
    test1("imul", Emit::emit_imul_r8);
}

#[test]
fn test_imul_r16() {
    test1("imul", Emit::emit_imul_r16);
}

#[test]
fn test_imul_r32() {
    test1("imul", Emit::emit_imul_r32);
}

#[test]
fn test_imul_r64() {
    test1("imul", Emit::emit_imul_r64);
}

#[test]
fn test_imul_m8() {
    test1("imul", Emit::emit_imul_m8);
}

#[test]
fn test_imul_m16() {
    test1("imul", Emit::emit_imul_m16);
}

#[test]
fn test_imul_m32() {
    test1("imul", Emit::emit_imul_m32);
}

#[test]
fn test_imul_m64() {
    test1("imul", Emit::emit_imul_m64);
}

#[test]
fn test_inc_r8() {
    test1("inc", Emit::emit_inc_r8);
}

#[test]
fn test_inc_r16() {
    test1("inc", Emit::emit_inc_r16);
}

#[test]
fn test_inc_r32() {
    test1("inc", Emit::emit_inc_r32);
}

#[test]
fn test_inc_r64() {
    test1("inc", Emit::emit_inc_r64);
}

#[test]
fn test_inc_m8() {
    test1("inc", Emit::emit_inc_m8);
}

#[test]
fn test_inc_m16() {
    test1("inc", Emit::emit_inc_m16);
}

#[test]
fn test_inc_m32() {
    test1("inc", Emit::emit_inc_m32);
}

#[test]
fn test_inc_m64() {
    test1("inc", Emit::emit_inc_m64);
}

#[test]
fn test_jcc_rel8() {
    test2_cond("j", Emit::emit_jcc_rel8);
}

#[test]
fn test_jcc_rel32() {
    test2_cond("j", Emit::emit_jcc_rel32);
}

#[test]
fn test_jmp_rel8() {
    test1("jmp", Emit::emit_jmp_rel8);
}

#[test]
fn test_jmp_rel32() {
    test1("jmp", Emit::emit_jmp_rel32);
}

#[test]
fn test_jmp_r64() {
    test1("jmp", Emit::emit_jmp_r64);
}

#[test]
#[ignore]
fn test_lea_rm16() {
    // FIXME capstone formats without "word ptr"
    test2("lea", Emit::emit_lea_rm16);
}

#[test]
#[ignore]
fn test_lea_rm32() {
    // FIXME capstone formats without "dword ptr"
    test2("lea", Emit::emit_lea_rm32);
}

#[test]
#[ignore]
fn test_lea_rm64() {
    // FIXME capstone formats without "qword ptr"
    test2("lea", Emit::emit_lea_rm64);
}

#[test]
fn test_mul_r8() {
    test1("mul", Emit::emit_mul_r8);
}

#[test]
fn test_mul_r16() {
    test1("mul", Emit::emit_mul_r16);
}

#[test]
fn test_mul_r32() {
    test1("mul", Emit::emit_mul_r32);
}

#[test]
fn test_mul_r64() {
    test1("mul", Emit::emit_mul_r64);
}

#[test]
fn test_mul_m8() {
    test1("mul", Emit::emit_mul_m8);
}

#[test]
fn test_mul_m16() {
    test1("mul", Emit::emit_mul_m16);
}

#[test]
fn test_mul_m32() {
    test1("mul", Emit::emit_mul_m32);
}

#[test]
fn test_mul_m64() {
    test1("mul", Emit::emit_mul_m64);
}

#[test]
fn test_mov_ri8() {
    test2("mov", Emit::emit_mov_ri8);
}

#[test]
fn test_mov_ri16() {
    test2("mov", Emit::emit_mov_ri16);
}

#[test]
fn test_mov_ri32() {
    test2("mov", Emit::emit_mov_ri32);
}

#[test]
fn test_mov_ri64() {
    test2("movabs", Emit::emit_mov_ri64);
}

#[test]
fn test_mov_r64_i32() {
    test2_filter::<_, u64>("mov", |e, r, imm| e.emit_mov_r64_i32(r, imm as i32),
        |_, imm| is_signed_nbit_integer(32, imm as i64));
}

#[test]
fn test_mov_rr8() {
    test2_filter("mov", Emit::emit_mov_rr8, |r1, r2| {
        are_registers_compatible(r1, r2)
    });
}

#[test]
fn test_mov_rr16() {
    test2("mov", Emit::emit_mov_rr16);
}

#[test]
fn test_mov_rr32() {
    test2("mov", Emit::emit_mov_rr32);
}

#[test]
fn test_mov_rr64() {
    test2("mov", Emit::emit_mov_rr64);
}

#[test]
fn test_mov_rm8() {
    test2_filter("mov", Emit::emit_mov_rm8, |r, _| {
        r.is_encodable_with_rex()
    });
}

#[test]
fn test_mov_rm16() {
    test2("mov", Emit::emit_mov_rm16);
}

#[test]
fn test_mov_rm32() {
    test2("mov", Emit::emit_mov_rm32);
}

#[test]
fn test_mov_rm64() {
    test2("mov", Emit::emit_mov_rm64);
}

#[test]
fn test_mov_mi8() {
    test2("mov", Emit::emit_mov_mi8);
}

#[test]
fn test_mov_mi16() {
    test2("mov", Emit::emit_mov_mi16);
}

#[test]
fn test_mov_mi32() {
    test2("mov", Emit::emit_mov_mi32);
}

#[test]
fn test_mov_m64_i32() {
    test2_filter::<_, u64>("mov", |e, m, imm| e.emit_mov_m64_i32(m, imm as i32),
        |_, imm| is_signed_nbit_integer(32, imm as i64));
}

#[test]
fn test_mov_mr8() {
    test2_filter("mov", Emit::emit_mov_mr8, |_, r| {
        r.is_encodable_with_rex()
    });
}

#[test]
fn test_mov_mr16() {
    test2("mov", Emit::emit_mov_mr16);
}

#[test]
fn test_mov_mr32() {
    test2("mov", Emit::emit_mov_mr32);
}

#[test]
fn test_mov_mr64() {
    test2("mov", Emit::emit_mov_mr64);
}

#[test]
fn test_movsx_r16_r8() {
    test2_filter("movsx", Emit::emit_movsx_r16_r8, |r1, r2| {
        are_registers_compatible(r1, r2)
    });
}

#[test]
fn test_movsx_r32_r8() {
    test2_filter("movsx", Emit::emit_movsx_r32_r8, |r1, r2| {
        are_registers_compatible(r1, r2)
    });
}

#[test]
fn test_movsx_r64_r8() {
    test2_filter("movsx", Emit::emit_movsx_r64_r8, |r1, r2| {
        are_registers_compatible(r1, r2)
    });
}

#[test]
fn test_movsx_r32_r16() {
    test2("movsx", Emit::emit_movsx_r32_r16);
}

#[test]
fn test_movsx_r64_r16() {
    test2("movsx", Emit::emit_movsx_r64_r16);
}

#[test]
fn test_movsx_r16_m8() {
    test2("movsx", Emit::emit_movsx_r16_m8);
}

#[test]
fn test_movsx_r32_m8() {
    test2("movsx", Emit::emit_movsx_r32_m8);
}

#[test]
fn test_movsx_r64_m8() {
    test2("movsx", Emit::emit_movsx_r64_m8);
}

#[test]
fn test_movsx_r32_m16() {
    test2("movsx", Emit::emit_movsx_r32_m16);
}

#[test]
fn test_movsx_r64_m16() {
    test2("movsx", Emit::emit_movsx_r64_m16);
}

#[test]
fn test_movzx_r16_r8() {
    test2_filter("movzx", Emit::emit_movzx_r16_r8, |r1, r2| {
        are_registers_compatible(r1, r2)
    });
}

#[test]
fn test_movzx_r32_r8() {
    test2_filter("movzx", Emit::emit_movzx_r32_r8, |r1, r2| {
        are_registers_compatible(r1, r2)
    });
}

#[test]
fn test_movzx_r64_r8() {
    test2_filter("movzx", Emit::emit_movzx_r64_r8, |r1, r2| {
        are_registers_compatible(r1, r2)
    });
}

#[test]
fn test_movzx_r32_r16() {
    test2("movzx", Emit::emit_movzx_r32_r16);
}

#[test]
fn test_movzx_r64_r16() {
    test2("movzx", Emit::emit_movzx_r64_r16);
}

#[test]
fn test_movzx_r16_m8() {
    test2("movzx", Emit::emit_movzx_r16_m8);
}

#[test]
fn test_movzx_r32_m8() {
    test2("movzx", Emit::emit_movzx_r32_m8);
}

#[test]
fn test_movzx_r64_m8() {
    test2("movzx", Emit::emit_movzx_r64_m8);
}

#[test]
fn test_movzx_r32_m16() {
    test2("movzx", Emit::emit_movzx_r32_m16);
}

#[test]
fn test_movzx_r64_m16() {
    test2("movzx", Emit::emit_movzx_r64_m16);
}

#[test]
fn test_neg_r8() {
    test1("neg", Emit::emit_neg_r8);
}

#[test]
fn test_neg_r16() {
    test1("neg", Emit::emit_neg_r16);
}

#[test]
fn test_neg_r32() {
    test1("neg", Emit::emit_neg_r32);
}

#[test]
fn test_neg_r64() {
    test1("neg", Emit::emit_neg_r64);
}

#[test]
fn test_neg_m8() {
    test1("neg", Emit::emit_neg_m8);
}

#[test]
fn test_neg_m16() {
    test1("neg", Emit::emit_neg_m16);
}

#[test]
fn test_neg_m32() {
    test1("neg", Emit::emit_neg_m32);
}

#[test]
fn test_neg_m64() {
    test1("neg", Emit::emit_neg_m64);
}

#[test]
fn test_nop() {
    test0("nop", Emit::emit_nop);
}

#[test]
fn test_not_r8() {
    test1("not", Emit::emit_not_r8);
}

#[test]
fn test_not_r16() {
    test1("not", Emit::emit_not_r16);
}

#[test]
fn test_not_r32() {
    test1("not", Emit::emit_not_r32);
}

#[test]
fn test_not_r64() {
    test1("not", Emit::emit_not_r64);
}

#[test]
fn test_not_m8() {
    test1("not", Emit::emit_not_m8);
}

#[test]
fn test_not_m16() {
    test1("not", Emit::emit_not_m16);
}

#[test]
fn test_not_m32() {
    test1("not", Emit::emit_not_m32);
}

#[test]
fn test_not_m64() {
    test1("not", Emit::emit_not_m64);
}

#[test]
fn test_or_al_i8() {
    test1_format("or", Emit::emit_or_al_i8, |s| format!("al, {s}"));
}

#[test]
fn test_or_ax_i16() {
    test1_format("or", Emit::emit_or_ax_i16, |s| format!("ax, {s}"));
}

#[test]
fn test_or_eax_i32() {
    test1_format("or", Emit::emit_or_eax_i32, |s| format!("eax, {s}"));
}

#[test]
fn test_or_rax_i32() {
    test1_format_filter::<u64>("and", |e, imm| e.emit_and_rax_i32(imm as i32),
        |s| format!("rax, {s}"),
        |imm| is_signed_nbit_integer(32, imm as i64));
}

#[test]
fn test_or_ri8() {
    test2("or", Emit::emit_or_ri8);
}

#[test]
fn test_or_ri16() {
    test2("or", Emit::emit_or_ri16);
}

#[test]
fn test_or_ri32() {
    test2("or", Emit::emit_or_ri32);
}

#[test]
fn test_or_r64_i32() {
    test2_filter::<_, u64>("or", |e, r, imm| e.emit_or_r64_i32(r, imm as i32),
        |_, imm| is_signed_nbit_integer(32, imm as i64));
}

#[test]
fn test_or_r16_i8() {
    test2_filter::<_, u16>("or", |e, r, imm| e.emit_or_r16_i8(r, imm as i8),
        |_, imm| is_signed_nbit_integer(8, imm as i16));
}

#[test]
fn test_or_r32_i8() {
    test2_filter::<_, u32>("or", |e, r, imm| e.emit_or_r32_i8(r, imm as i8),
        |_, imm| is_signed_nbit_integer(8, imm as i32));
}

#[test]
fn test_or_r64_i8() {
    test2_filter::<_, u64>("or", |e, r, imm| e.emit_or_r64_i8(r, imm as i8),
        |_, imm| is_signed_nbit_integer(8, imm as i64));
}

#[test]
fn test_or_rr8() {
    test2_filter("or", Emit::emit_or_rr8, |r1, r2| {
        are_registers_compatible(r1, r2)
    });
}

#[test]
fn test_or_rr16() {
    test2("or", Emit::emit_or_rr16);
}

#[test]
fn test_or_rr32() {
    test2("or", Emit::emit_or_rr32);
}

#[test]
fn test_or_rr64() {
    test2("or", Emit::emit_or_rr64);
}

#[test]
fn test_or_rm8() {
    test2_filter("or", Emit::emit_or_rm8, |r, _| {
        r.is_encodable_with_rex()
    });
}

#[test]
fn test_or_rm16() {
    test2("or", Emit::emit_or_rm16);
}

#[test]
fn test_or_rm32() {
    test2("or", Emit::emit_or_rm32);
}

#[test]
fn test_or_rm64() {
    test2("or", Emit::emit_or_rm64);
}

#[test]
fn test_or_mi8() {
    test2("or", Emit::emit_or_mi8);
}

#[test]
fn test_or_mi16() {
    test2("or", Emit::emit_or_mi16);
}

#[test]
fn test_or_mi32() {
    test2("or", Emit::emit_or_mi32);
}

#[test]
fn test_or_m64_i32() {
    test2_filter::<_, u64>("or", |e, m, imm| e.emit_or_m64_i32(m, imm as i32),
        |_, imm| is_signed_nbit_integer(32, imm as i64));
}

#[test]
fn test_or_m16_i8() {
    test2_filter::<_, u16>("or", |e, m, imm| e.emit_or_m16_i8(m, imm as i8),
        |_, imm| is_signed_nbit_integer(8, imm as i16));
}

#[test]
fn test_or_m32_i8() {
    test2_filter::<_, u32>("or", |e, m, imm| e.emit_or_m32_i8(m, imm as i8),
        |_, imm| is_signed_nbit_integer(8, imm as i32));
}

#[test]
fn test_or_m64_i8() {
    test2_filter::<_, u64>("or", |e, m, imm| e.emit_or_m64_i8(m, imm as i8),
        |_, imm| is_signed_nbit_integer(8, imm as i64));
}

#[test]
fn test_or_mr8() {
    test2_filter("or", Emit::emit_or_mr8, |_, r| {
        r.is_encodable_with_rex()
    });
}

#[test]
fn test_or_mr16() {
    test2("or", Emit::emit_or_mr16);
}

#[test]
fn test_or_mr32() {
    test2("or", Emit::emit_or_mr32);
}

#[test]
fn test_or_mr64() {
    test2("or", Emit::emit_or_mr64);
}

#[test]
fn test_pop_r16() {
    test1("pop", Emit::emit_pop_r16);
}

#[test]
fn test_pop_r64() {
    test1("pop", Emit::emit_pop_r64);
}

#[test]
fn test_pop_m16() {
    test1("pop", Emit::emit_pop_m16);
}

#[test]
fn test_pop_m64() {
    test1("pop", Emit::emit_pop_m64);
}

#[test]
fn test_push_i8() {
    test1("push", Emit::emit_push_i8);
}

#[test]
fn test_push_i16() {
    test1("push", Emit::emit_push_i16);
}

#[test]
fn test_push_i32() {
    test1("push", Emit::emit_push_i32);
}

#[test]
fn test_push_r16() {
    test1("push", Emit::emit_push_r16);
}

#[test]
fn test_push_r64() {
    test1("push", Emit::emit_push_r64);
}

#[test]
fn test_push_m16() {
    test1("push", Emit::emit_push_m16);
}

#[test]
fn test_push_m64() {
    test1("push", Emit::emit_push_m64);
}

#[test]
fn test_ret() {
    test0("ret", Emit::emit_ret);
}

#[test]
fn test_sar_r8_1() {
    test1_format("sar", Emit::emit_sar_r8_1, |s| format!("{s}, 1"));
}

#[test]
fn test_sar_r16_1() {
    test1_format("sar", Emit::emit_sar_r16_1, |s| format!("{s}, 1"));
}

#[test]
fn test_sar_r32_1() {
    test1_format("sar", Emit::emit_sar_r32_1, |s| format!("{s}, 1"));
}

#[test]
fn test_sar_r64_1() {
    test1_format("sar", Emit::emit_sar_r64_1, |s| format!("{s}, 1"));
}

#[test]
fn test_sar_r8_cl() {
    test1_format("sar", Emit::emit_sar_r8_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_sar_r16_cl() {
    test1_format("sar", Emit::emit_sar_r16_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_sar_r32_cl() {
    test1_format("sar", Emit::emit_sar_r32_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_sar_r64_cl() {
    test1_format("sar", Emit::emit_sar_r64_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_sar_ri8() {
    test2("sar", Emit::emit_sar_ri8);
}

#[test]
fn test_sar_ri16() {
    test2("sar", Emit::emit_sar_ri16);
}

#[test]
fn test_sar_ri32() {
    test2("sar", Emit::emit_sar_ri32);
}

#[test]
fn test_sar_ri64() {
    test2("sar", Emit::emit_sar_ri64);
}

#[test]
fn test_sar_m8_1() {
    test1_format("sar", Emit::emit_sar_m8_1, |s| format!("{s}, 1"));
}

#[test]
fn test_sar_m16_1() {
    test1_format("sar", Emit::emit_sar_m16_1, |s| format!("{s}, 1"));
}

#[test]
fn test_sar_m32_1() {
    test1_format("sar", Emit::emit_sar_m32_1, |s| format!("{s}, 1"));
}

#[test]
fn test_sar_m64_1() {
    test1_format("sar", Emit::emit_sar_m64_1, |s| format!("{s}, 1"));
}

#[test]
fn test_sar_m8_cl() {
    test1_format("sar", Emit::emit_sar_m8_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_sar_m16_cl() {
    test1_format("sar", Emit::emit_sar_m16_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_sar_m32_cl() {
    test1_format("sar", Emit::emit_sar_m32_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_sar_m64_cl() {
    test1_format("sar", Emit::emit_sar_m64_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_sar_mi8() {
    test2("sar", Emit::emit_sar_mi8);
}

#[test]
fn test_sar_mi16() {
    test2("sar", Emit::emit_sar_mi16);
}

#[test]
fn test_sar_mi32() {
    test2("sar", Emit::emit_sar_mi32);
}

#[test]
fn test_sar_mi64() {
    test2("sar", Emit::emit_sar_mi64);
}

#[test]
fn test_sbb_al_i8() {
    test1_format("sbb", Emit::emit_sbb_al_i8, |s| format!("al, {s}"));
}

#[test]
fn test_sbb_ax_i16() {
    test1_format("sbb", Emit::emit_sbb_ax_i16, |s| format!("ax, {s}"));
}

#[test]
fn test_sbb_eax_i32() {
    test1_format("sbb", Emit::emit_sbb_eax_i32, |s| format!("eax, {s}"));
}

#[test]
fn test_sbb_rax_i32() {
    test1_format("sbb", Emit::emit_sbb_rax_i32, |s| format!("rax, {s}"));
}

#[test]
fn test_sbb_ri8() {
    test2("sbb", Emit::emit_sbb_ri8);
}

#[test]
fn test_sbb_ri16() {
    test2("sbb", Emit::emit_sbb_ri16);
}

#[test]
fn test_sbb_ri32() {
    test2("sbb", Emit::emit_sbb_ri32);
}

#[test]
fn test_sbb_r64_i32() {
    test2("sbb", Emit::emit_sbb_r64_i32);
}

#[test]
fn test_sbb_r16_i8() {
    test2("sbb", Emit::emit_sbb_r16_i8);
}

#[test]
fn test_sbb_r32_i8() {
    test2("sbb", Emit::emit_sbb_r32_i8);
}

#[test]
fn test_sbb_r64_i8() {
    test2("sbb", Emit::emit_sbb_r64_i8);
}

#[test]
fn test_sbb_rr8() {
    test2_filter("sbb", Emit::emit_sbb_rr8, |r1, r2| {
        are_registers_compatible(r1, r2)
    });
}

#[test]
fn test_sbb_rr16() {
    test2("sbb", Emit::emit_sbb_rr16);
}

#[test]
fn test_sbb_rr32() {
    test2("sbb", Emit::emit_sbb_rr32);
}

#[test]
fn test_sbb_rr64() {
    test2("sbb", Emit::emit_sbb_rr64);
}

#[test]
fn test_sbb_rm8() {
    test2_filter("sbb", Emit::emit_sbb_rm8, |r, _| {
        r.is_encodable_with_rex()
    });
}

#[test]
fn test_sbb_rm16() {
    test2("sbb", Emit::emit_sbb_rm16);
}

#[test]
fn test_sbb_rm32() {
    test2("sbb", Emit::emit_sbb_rm32);
}

#[test]
fn test_sbb_rm64() {
    test2("sbb", Emit::emit_sbb_rm64);
}

#[test]
fn test_sbb_mi8() {
    test2("sbb", Emit::emit_sbb_mi8);
}

#[test]
fn test_sbb_mi16() {
    test2("sbb", Emit::emit_sbb_mi16);
}

#[test]
fn test_sbb_mi32() {
    test2("sbb", Emit::emit_sbb_mi32);
}

#[test]
fn test_sbb_m64_i32() {
    test2("sbb", Emit::emit_sbb_m64_i32);
}

#[test]
fn test_sbb_m16_i8() {
    test2("sbb", Emit::emit_sbb_m16_i8);
}

#[test]
fn test_sbb_m32_i8() {
    test2("sbb", Emit::emit_sbb_m32_i8);
}

#[test]
fn test_sbb_m64_i8() {
    test2("sbb", Emit::emit_sbb_m64_i8);
}

#[test]
fn test_sbb_mr8() {
    test2_filter("sbb", Emit::emit_sbb_mr8, |_, r| {
        r.is_encodable_with_rex()
    });
}

#[test]
fn test_sbb_mr16() {
    test2("sbb", Emit::emit_sbb_mr16);
}

#[test]
fn test_sbb_mr32() {
    test2("sbb", Emit::emit_sbb_mr32);
}

#[test]
fn test_sbb_mr64() {
    test2("sbb", Emit::emit_sbb_mr64);
}

#[test]
fn test_setcc_r8() {
    test2_cond("set", Emit::emit_setcc_r8);
}

#[test]
fn test_setcc_m8() {
    test2_cond("set", Emit::emit_setcc_m8);
}

#[test]
fn test_shl_r8_1() {
    test1_format("shl", Emit::emit_shl_r8_1, |s| format!("{s}, 1"));
}

#[test]
fn test_shl_r16_1() {
    test1_format("shl", Emit::emit_shl_r16_1, |s| format!("{s}, 1"));
}

#[test]
fn test_shl_r32_1() {
    test1_format("shl", Emit::emit_shl_r32_1, |s| format!("{s}, 1"));
}

#[test]
fn test_shl_r64_1() {
    test1_format("shl", Emit::emit_shl_r64_1, |s| format!("{s}, 1"));
}

#[test]
fn test_shl_r8_cl() {
    test1_format("shl", Emit::emit_shl_r8_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_shl_r16_cl() {
    test1_format("shl", Emit::emit_shl_r16_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_shl_r32_cl() {
    test1_format("shl", Emit::emit_shl_r32_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_shl_r64_cl() {
    test1_format("shl", Emit::emit_shl_r64_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_shl_ri8() {
    test2("shl", Emit::emit_shl_ri8);
}

#[test]
fn test_shl_ri16() {
    test2("shl", Emit::emit_shl_ri16);
}

#[test]
fn test_shl_ri32() {
    test2("shl", Emit::emit_shl_ri32);
}

#[test]
fn test_shl_ri64() {
    test2("shl", Emit::emit_shl_ri64);
}

#[test]
fn test_shl_m8_1() {
    test1_format("shl", Emit::emit_shl_m8_1, |s| format!("{s}, 1"));
}

#[test]
fn test_shl_m16_1() {
    test1_format("shl", Emit::emit_shl_m16_1, |s| format!("{s}, 1"));
}

#[test]
fn test_shl_m32_1() {
    test1_format("shl", Emit::emit_shl_m32_1, |s| format!("{s}, 1"));
}

#[test]
fn test_shl_m64_1() {
    test1_format("shl", Emit::emit_shl_m64_1, |s| format!("{s}, 1"));
}

#[test]
fn test_shl_m8_cl() {
    test1_format("shl", Emit::emit_shl_m8_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_shl_m16_cl() {
    test1_format("shl", Emit::emit_shl_m16_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_shl_m32_cl() {
    test1_format("shl", Emit::emit_shl_m32_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_shl_m64_cl() {
    test1_format("shl", Emit::emit_shl_m64_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_shl_mi8() {
    test2("shl", Emit::emit_shl_mi8);
}

#[test]
fn test_shl_mi16() {
    test2("shl", Emit::emit_shl_mi16);
}

#[test]
fn test_shl_mi32() {
    test2("shl", Emit::emit_shl_mi32);
}

#[test]
fn test_shl_mi64() {
    test2("shl", Emit::emit_shl_mi64);
}

#[test]
fn test_shr_r8_1() {
    test1_format("shr", Emit::emit_shr_r8_1, |s| format!("{s}, 1"));
}

#[test]
fn test_shr_r16_1() {
    test1_format("shr", Emit::emit_shr_r16_1, |s| format!("{s}, 1"));
}

#[test]
fn test_shr_r32_1() {
    test1_format("shr", Emit::emit_shr_r32_1, |s| format!("{s}, 1"));
}

#[test]
fn test_shr_r64_1() {
    test1_format("shr", Emit::emit_shr_r64_1, |s| format!("{s}, 1"));
}

#[test]
fn test_shr_r8_cl() {
    test1_format("shr", Emit::emit_shr_r8_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_shr_r16_cl() {
    test1_format("shr", Emit::emit_shr_r16_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_shr_r32_cl() {
    test1_format("shr", Emit::emit_shr_r32_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_shr_r64_cl() {
    test1_format("shr", Emit::emit_shr_r64_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_shr_ri8() {
    test2("shr", Emit::emit_shr_ri8);
}

#[test]
fn test_shr_ri16() {
    test2("shr", Emit::emit_shr_ri16);
}

#[test]
fn test_shr_ri32() {
    test2("shr", Emit::emit_shr_ri32);
}

#[test]
fn test_shr_ri64() {
    test2("shr", Emit::emit_shr_ri64);
}

#[test]
fn test_shr_m8_1() {
    test1_format("shr", Emit::emit_shr_m8_1, |s| format!("{s}, 1"));
}

#[test]
fn test_shr_m16_1() {
    test1_format("shr", Emit::emit_shr_m16_1, |s| format!("{s}, 1"));
}

#[test]
fn test_shr_m32_1() {
    test1_format("shr", Emit::emit_shr_m32_1, |s| format!("{s}, 1"));
}

#[test]
fn test_shr_m64_1() {
    test1_format("shr", Emit::emit_shr_m64_1, |s| format!("{s}, 1"));
}

#[test]
fn test_shr_m8_cl() {
    test1_format("shr", Emit::emit_shr_m8_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_shr_m16_cl() {
    test1_format("shr", Emit::emit_shr_m16_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_shr_m32_cl() {
    test1_format("shr", Emit::emit_shr_m32_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_shr_m64_cl() {
    test1_format("shr", Emit::emit_shr_m64_cl, |s| format!("{s}, cl"));
}

#[test]
fn test_shr_mi8() {
    test2("shr", Emit::emit_shr_mi8);
}

#[test]
fn test_shr_mi16() {
    test2("shr", Emit::emit_shr_mi16);
}

#[test]
fn test_shr_mi32() {
    test2("shr", Emit::emit_shr_mi32);
}

#[test]
fn test_shr_mi64() {
    test2("shr", Emit::emit_shr_mi64);
}

#[test]
fn test_sub_al_i8() {
    test1_format("sub", Emit::emit_sub_al_i8, |s| format!("al, {s}"));
}

#[test]
fn test_sub_ax_i16() {
    test1_format("sub", Emit::emit_sub_ax_i16, |s| format!("ax, {s}"));
}

#[test]
fn test_sub_eax_i32() {
    test1_format("sub", Emit::emit_sub_eax_i32, |s| format!("eax, {s}"));
}

#[test]
fn test_sub_rax_i32() {
    test1_format("sub", Emit::emit_sub_rax_i32, |s| format!("rax, {s}"));
}

#[test]
fn test_sub_ri8() {
    test2("sub", Emit::emit_sub_ri8);
}

#[test]
fn test_sub_ri16() {
    test2("sub", Emit::emit_sub_ri16);
}

#[test]
fn test_sub_ri32() {
    test2("sub", Emit::emit_sub_ri32);
}

#[test]
fn test_sub_r64_i32() {
    test2("sub", Emit::emit_sub_r64_i32);
}

#[test]
fn test_sub_r16_i8() {
    test2("sub", Emit::emit_sub_r16_i8);
}

#[test]
fn test_sub_r32_i8() {
    test2("sub", Emit::emit_sub_r32_i8);
}

#[test]
fn test_sub_r64_i8() {
    test2("sub", Emit::emit_sub_r64_i8);
}

#[test]
fn test_sub_rr8() {
    test2_filter("sub", Emit::emit_sub_rr8, |r1, r2| {
        are_registers_compatible(r1, r2)
    });
}

#[test]
fn test_sub_rr16() {
    test2("sub", Emit::emit_sub_rr16);
}

#[test]
fn test_sub_rr32() {
    test2("sub", Emit::emit_sub_rr32);
}

#[test]
fn test_sub_rr64() {
    test2("sub", Emit::emit_sub_rr64);
}

#[test]
fn test_sub_rm8() {
    test2_filter("sub", Emit::emit_sub_rm8, |r, _| {
        r.is_encodable_with_rex()
    });
}

#[test]
fn test_sub_rm16() {
    test2("sub", Emit::emit_sub_rm16);
}

#[test]
fn test_sub_rm32() {
    test2("sub", Emit::emit_sub_rm32);
}

#[test]
fn test_sub_rm64() {
    test2("sub", Emit::emit_sub_rm64);
}

#[test]
fn test_sub_mi8() {
    test2("sub", Emit::emit_sub_mi8);
}

#[test]
fn test_sub_mi16() {
    test2("sub", Emit::emit_sub_mi16);
}

#[test]
fn test_sub_mi32() {
    test2("sub", Emit::emit_sub_mi32);
}

#[test]
fn test_sub_m64_i32() {
    test2("sub", Emit::emit_sub_m64_i32);
}

#[test]
fn test_sub_m16_i8() {
    test2("sub", Emit::emit_sub_m16_i8);
}

#[test]
fn test_sub_m32_i8() {
    test2("sub", Emit::emit_sub_m32_i8);
}

#[test]
fn test_sub_m64_i8() {
    test2("sub", Emit::emit_sub_m64_i8);
}

#[test]
fn test_sub_mr8() {
    test2_filter("sub", Emit::emit_sub_mr8, |_, r| {
        r.is_encodable_with_rex()
    });
}

#[test]
fn test_sub_mr16() {
    test2("sub", Emit::emit_sub_mr16);
}

#[test]
fn test_sub_mr32() {
    test2("sub", Emit::emit_sub_mr32);
}

#[test]
fn test_sub_mr64() {
    test2("sub", Emit::emit_sub_mr64);
}

#[test]
fn test_test_al_i8() {
    test1_format("test", Emit::emit_test_al_i8, |s| format!("al, {s}"));
}

#[test]
fn test_test_ax_i16() {
    test1_format("test", Emit::emit_test_ax_i16, |s| format!("ax, {s}"));
}

#[test]
fn test_test_eax_i32() {
    test1_format("test", Emit::emit_test_eax_i32, |s| format!("eax, {s}"));
}

#[test]
fn test_test_rax_i32() {
    test1_format("test", Emit::emit_test_rax_i32, |s| format!("rax, {s}"));
}

#[test]
fn test_test_ri8() {
    test2("test", Emit::emit_test_ri8);
}

#[test]
fn test_test_ri16() {
    test2("test", Emit::emit_test_ri16);
}

#[test]
fn test_test_ri32() {
    test2("test", Emit::emit_test_ri32);
}

#[test]
fn test_test_r64_i32() {
    test2("test", Emit::emit_test_r64_i32);
}

#[test]
fn test_test_rr8() {
    test2_filter("test", Emit::emit_test_rr8, |r1, r2| {
        are_registers_compatible(r1, r2)
    });
}

#[test]
fn test_test_rr16() {
    test2("test", Emit::emit_test_rr16);
}

#[test]
fn test_test_rr32() {
    test2("test", Emit::emit_test_rr32);
}

#[test]
fn test_test_rr64() {
    test2("test", Emit::emit_test_rr64);
}

#[test]
fn test_test_mi8() {
    test2("test", Emit::emit_test_mi8);
}

#[test]
fn test_test_mi16() {
    test2("test", Emit::emit_test_mi16);
}

#[test]
fn test_test_mi32() {
    test2("test", Emit::emit_test_mi32);
}

#[test]
fn test_test_m64_i32() {
    test2("test", Emit::emit_test_m64_i32);
}

#[test]
fn test_test_mr8() {
    test2_filter("test", Emit::emit_test_mr8, |_, r| {
        r.is_encodable_with_rex()
    });
}

#[test]
fn test_test_mr16() {
    test2("test", Emit::emit_test_mr16);
}

#[test]
fn test_test_mr32() {
    test2("test", Emit::emit_test_mr32);
}

#[test]
fn test_test_mr64() {
    test2("test", Emit::emit_test_mr64);
}

#[test]
fn test_ud2() {
    test0("ud2", Emit::emit_ud2);
}

#[test]
fn test_xchg_r16_ax() {
    test1_format_filter("xchg", Emit::emit_xchg_r16_ax,
        |s| format!("{s}, ax"),
        |r| r != Ax);
}

#[test]
fn test_xchg_r32_eax() {
    test1_format_filter("xchg", Emit::emit_xchg_r32_eax,
        |s| format!("{s}, eax"),
        |r| r != Eax);
}

#[test]
fn test_xchg_r64_rax() {
    test1_format_filter("xchg", Emit::emit_xchg_r64_rax,
        |s| format!("{s}, rax"),
        |r| r != Rax);
}

#[test]
fn test_xchg_rr8() {
    test2_filter("xchg", Emit::emit_xchg_rr8, |r1, r2| {
        are_registers_compatible(r1, r2)
    });
}

#[test]
fn test_xchg_rr16() {
    test2("xchg", Emit::emit_xchg_rr16);
}

#[test]
fn test_xchg_rr32() {
    test2("xchg", Emit::emit_xchg_rr32);
}

#[test]
fn test_xchg_rr64() {
    test2("xchg", Emit::emit_xchg_rr64);
}

#[test]
fn test_xchg_mr8() {
    test2_filter("xchg", Emit::emit_xchg_mr8, |_, r| {
        r.is_encodable_with_rex()
    });
}

#[test]
fn test_xchg_mr16() {
    test2("xchg", Emit::emit_xchg_mr16);
}

#[test]
fn test_xchg_mr32() {
    test2("xchg", Emit::emit_xchg_mr32);
}

#[test]
fn test_xchg_mr64() {
    test2("xchg", Emit::emit_xchg_mr64);
}

#[test]
fn test_xor_al_i8() {
    test1_format("xor", Emit::emit_xor_al_i8, |s| format!("al, {s}"));
}

#[test]
fn test_xor_ax_i16() {
    test1_format("xor", Emit::emit_xor_ax_i16, |s| format!("ax, {s}"));
}

#[test]
fn test_xor_eax_i32() {
    test1_format("xor", Emit::emit_xor_eax_i32, |s| format!("eax, {s}"));
}

#[test]
fn test_xor_rax_i32() {
    test1_format_filter::<u64>("xor", |e, imm| e.emit_xor_rax_i32(imm as i32),
        |s| format!("rax, {s}"),
        |imm| is_signed_nbit_integer(32, imm as i64));
}

#[test]
fn test_xor_ri8() {
    test2("xor", Emit::emit_xor_ri8);
}

#[test]
fn test_xor_ri16() {
    test2("xor", Emit::emit_xor_ri16);
}

#[test]
fn test_xor_ri32() {
    test2("xor", Emit::emit_xor_ri32);
}

#[test]
fn test_xor_r64_i32() {
    test2_filter::<_, u64>("xor", |e, r, imm| e.emit_xor_r64_i32(r, imm as i32),
        |_, imm| is_signed_nbit_integer(32, imm as i64));
}

#[test]
fn test_xor_r16_i8() {
    test2_filter::<_, u16>("xor", |e, r, imm| e.emit_xor_r16_i8(r, imm as i8),
        |_, imm| is_signed_nbit_integer(8, imm as i16));
}

#[test]
fn test_xor_r32_i8() {
    test2_filter::<_, u32>("xor", |e, r, imm| e.emit_xor_r32_i8(r, imm as i8),
        |_, imm| is_signed_nbit_integer(8, imm as i32));
}

#[test]
fn test_xor_r64_i8() {
    test2_filter::<_, u64>("xor", |e, r, imm| e.emit_xor_r64_i8(r, imm as i8),
        |_, imm| is_signed_nbit_integer(8, imm as i64));
}

#[test]
fn test_xor_rr8() {
    test2_filter("xor", Emit::emit_xor_rr8, |r1, r2| {
        are_registers_compatible(r1, r2)
    });
}

#[test]
fn test_xor_rr16() {
    test2("xor", Emit::emit_xor_rr16);
}

#[test]
fn test_xor_rr32() {
    test2("xor", Emit::emit_xor_rr32);
}

#[test]
fn test_xor_rr64() {
    test2("xor", Emit::emit_xor_rr64);
}

#[test]
fn test_xor_rm8() {
    test2_filter("xor", Emit::emit_xor_rm8, |r, _| {
        r.is_encodable_with_rex()
    });
}

#[test]
fn test_xor_rm16() {
    test2("xor", Emit::emit_xor_rm16);
}

#[test]
fn test_xor_rm32() {
    test2("xor", Emit::emit_xor_rm32);
}

#[test]
fn test_xor_rm64() {
    test2("xor", Emit::emit_xor_rm64);
}

#[test]
fn test_xor_mi8() {
    test2("xor", Emit::emit_xor_mi8);
}

#[test]
fn test_xor_mi16() {
    test2("xor", Emit::emit_xor_mi16);
}

#[test]
fn test_xor_mi32() {
    test2("xor", Emit::emit_xor_mi32);
}

#[test]
fn test_xor_m64_i32() {
    test2_filter::<_, u64>("xor", |e, m, imm| e.emit_xor_m64_i32(m, imm as i32),
        |_, imm| is_signed_nbit_integer(32, imm as i64));
}

#[test]
fn test_xor_m16_i8() {
    test2_filter::<_, u16>("xor", |e, m, imm| e.emit_xor_m16_i8(m, imm as i8),
        |_, imm| is_signed_nbit_integer(8, imm as i16));
}

#[test]
fn test_xor_m32_i8() {
    test2_filter::<_, u32>("xor", |e, m, imm| e.emit_xor_m32_i8(m, imm as i8),
        |_, imm| is_signed_nbit_integer(8, imm as i32));
}

#[test]
fn test_xor_m64_i8() {
    test2_filter::<_, u64>("xor", |e, m, imm| e.emit_xor_m64_i8(m, imm as i8),
        |_, imm| is_signed_nbit_integer(8, imm as i64));
}

#[test]
fn test_xor_mr8() {
    test2_filter("xor", Emit::emit_xor_mr8, |_, r| {
        r.is_encodable_with_rex()
    });
}

#[test]
fn test_xor_mr16() {
    test2("xor", Emit::emit_xor_mr16);
}

#[test]
fn test_xor_mr32() {
    test2("xor", Emit::emit_xor_mr32);
}

#[test]
fn test_xor_mr64() {
    test2("xor", Emit::emit_xor_mr64);
}
