use blazesym::symbolize::Input;
use blazesym::symbolize::Process;
use blazesym::symbolize::Source;
use blazesym::symbolize::Symbolizer;
use blazesym::Pid;
use core::num::NonZeroU32;
use std::cmp::min;

#[no_mangle]
#[allow(warnings)]
pub extern "C" fn symbolize(pid_nr: i32, addr: u64, buf: *mut u8, len: u32) -> i32 {
    if pid_nr == 0 {
        return -1;
    }

    let src = Source::Process(Process::new(Pid::Pid(
        NonZeroU32::new(pid_nr as u32).unwrap(),
    )));
    let symbolizer = Symbolizer::new();

    if let Ok(symbol) = symbolizer.symbolize_single(&src, Input::AbsAddr(addr)) {
        let mut symbol_name = match &symbol.as_sym() {
            Some(sym) => String::from(&*sym.name),
            None => {
                println!("cannot find symbol for pid_nr {}", pid_nr);
                String::from("empty")
            }
        };

        symbol_name = symbol_name
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("&", "&amp;");

        unsafe {
            std::ptr::copy_nonoverlapping(
                symbol_name.as_ptr(),
                buf,
                min(len as usize, symbol_name.len()),
            );
        }
        return 0;
    } else {
        let failed = "failed";
        unsafe {
            std::ptr::copy_nonoverlapping("failed".as_ptr(), buf, failed.len());
        }
        return -1;
    }
}
