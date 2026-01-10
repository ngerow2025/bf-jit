use iced_x86::code_asm::CodeAssembler;
use iced_x86::code_asm::*;
use libloading::Library;

fn main() -> Result<(), IcedError> {
    let mut program = compile_bf()?;

    let inital_code_size = 4096;

    let mut mapped_code_buf = memmap2::MmapMut::map_anon(inital_code_size).unwrap();

    // Assemble the code into the mapped buffer with the proper base address
    let mut base_address = mapped_code_buf.as_ptr() as u64;
    let mut code = program.assemble(base_address)?;

    // check the size of the assembled code
    println!("Assembled code size: {} bytes", code.len());

    // print out the assembled code in hex
    println!("Assembled code:");
    for byte in &code {
        print!("{:02x} ", byte);
    }
    println!();

    if code.len() > inital_code_size {
        println!("Warning: Assembled code size exceeds allocated buffer size!");
        println!("Reallocating buffer...");
        // Reallocate a larger buffer with the new size rounded up to the nearest page size
        let page_size = 4096;
        let new_size = code.len().div_ceil(page_size) * page_size;
        drop(mapped_code_buf);
        mapped_code_buf = memmap2::MmapMut::map_anon(new_size).unwrap();
        base_address = mapped_code_buf.as_ptr() as u64;
        code = program.assemble(base_address)?;
        println!("Reassembled code size: {} bytes", code.len());
    }

    if code.len() > mapped_code_buf.len() {
        eprintln!("Code expanded to not fit in newly allocated buffer!");
        std::process::exit(1);
    }

    // Copy the assembled code into the mapped buffer
    mapped_code_buf[..code.len()].copy_from_slice(&code);

    // Make the memory executable
    let exec_mapped_code_buf = mapped_code_buf.make_exec().unwrap();
    let exec_fn: extern "C" fn() = unsafe { std::mem::transmute(exec_mapped_code_buf.as_ptr()) };

    // Execute the JIT-compiled Brainfuck program
    exec_fn();

    println!("finished execution");

    //check

    Ok(())
}

fn compile_bf() -> Result<CodeAssembler, IcedError> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <brainfuck_file>", args[0]);
        std::process::exit(1);
    }
    let filename = &args[1];
    let contents =
        std::fs::read_to_string(filename).expect("Something went wrong reading the file");
    println!("Brainfuck code:\n{}", contents);
    let instructions: Vec<BfInstruction> = contents
        .chars()
        .filter_map(|c| match c {
            '>' => Some(BfInstruction::IncrementPtr),
            '<' => Some(BfInstruction::DecrementPtr),
            '+' => Some(BfInstruction::IncrementData),
            '-' => Some(BfInstruction::DecrementData),
            '.' => Some(BfInstruction::Output),
            ',' => Some(BfInstruction::Input),
            '[' => Some(BfInstruction::LoopStart),
            ']' => Some(BfInstruction::LoopEnd),
            _ => None,
        })
        .collect();
    println!("Parsed {} instructions.", instructions.len());
    let mut jump_table = Vec::with_capacity(instructions.len());
    let mut stack = Vec::new();
    for (i, instr) in instructions.iter().enumerate() {
        match instr {
            BfInstruction::LoopStart => {
                stack.push(i);
                jump_table.push(None);
            }
            BfInstruction::LoopEnd => {
                if let Some(start) = stack.pop() {
                    jump_table[start] = Some(i);
                    jump_table.push(Some(start));
                } else {
                    eprintln!("Unmatched ']' at instruction {}", i);
                    std::process::exit(1);
                }
            }
            _ => {
                jump_table.push(None);
            }
        }
    }
    if !stack.is_empty() {
        eprintln!("Unmatched '[' at instruction {}", stack.pop().unwrap());
        std::process::exit(1);
    }
    println!("Built jump table with {} entries.", jump_table.len());
    for (i, instr) in instructions.iter().enumerate() {
        match instr {
            BfInstruction::LoopStart => {
                if let Some(target) = jump_table[i] {
                    if target >= instructions.len() {
                        eprintln!(
                            "Invalid jump target {} for '[' at instruction {}",
                            target, i
                        );
                        std::process::exit(1);
                    } else if instructions[target] != BfInstruction::LoopEnd  {
                        eprintln!(
                            "Mismatched jump target {} for '[' at instruction {}",
                            target, i
                        );
                        std::process::exit(1);
                    }
                } else {
                    eprintln!("No jump target for '[' at instruction {}", i);
                    std::process::exit(1);
                }
            }
            BfInstruction::LoopEnd => {
                if let Some(target) = jump_table[i] {
                    if target >= instructions.len() {
                        eprintln!(
                            "Invalid jump target {} for ']' at instruction {}",
                            target, i
                        );
                        std::process::exit(1);
                    } else if instructions[target] != BfInstruction::LoopStart {
                        eprintln!(
                            "Mismatched jump target {} for ']' at instruction {}",
                            target, i
                        );
                        std::process::exit(1);
                    }
                } else {
                    eprintln!("No jump target for ']' at instruction {}", i);
                    std::process::exit(1);
                }
            }
            _ => {}
        }
    }
    println!("Jump table validated successfully.");

    //time to do a bit of manual dynamic linking
    // dynamically load the function pointer to WriteFile and ReadFile from kernel32.dll for calling from the JIT code
    // use windows_sys crate to use the functions like GetStdHandle to get the handles for stdin and stdout
    // then we can embed those handles as constants in the JIT code for use in the ReadFile and WriteFile calls

    unsafe {
        let lib = Library::new("kernel32.dll").unwrap();
        let write_file_sym: libloading::Symbol<
            unsafe extern "system" fn(
                handle: usize,
                buffer: *const u8,
                num_bytes_to_write: u32,
                num_bytes_written: *mut u32,
                overlapped: *mut u8,
            ) -> i32,
        > = lib.get(b"WriteFile").unwrap();

        let raw = write_file_sym.try_as_raw_ptr().unwrap() as usize;
    }



    let mut program = CodeAssembler::new(64)?;
    let tape_size = 30;
    //make sure to save some registers and allocate stack space for the tape
    program.push(rbx)?;
    program.sub(rsp, tape_size)?;

    //now zero out the tape memory
    //just generate like 30 instructions to zero out each byte
    for i in 0..tape_size {
        program.mov(byte_ptr(rsp + i), 0)?;
    }

    program.mov(rbx, rsp)?;
    let mut loop_stack = Vec::new();
    for (i, instr) in instructions.iter().enumerate() {
        match instr {
            BfInstruction::IncrementPtr => {
                program.inc(rbx)?; //use rbx as the data pointer
            }
            BfInstruction::DecrementPtr => {
                program.dec(rbx)?;
            }
            BfInstruction::IncrementData => {
                program.inc(byte_ptr(rbx))?;
            }
            BfInstruction::DecrementData => {
                program.dec(byte_ptr(rbx))?;
            }
            BfInstruction::Output => {
                //syscall write(1, rbx, 1)
                program.mov(rax, 1u64)?; //sys_write
                program.mov(rdi, 1u64)?; //stdout
                program.mov(rsi, rbx)?; //data pointer
                program.mov(rdx, 1u64)?; //length
                program.syscall()?;
            }
            BfInstruction::Input => {
                //syscall read(0, rbx, 1)
                program.mov(rax, 0u64)?; //sys_read
                program.mov(rdi, 0u64)?; //stdin
                program.mov(rsi, rbx)?; //data pointer
                program.mov(rdx, 1u64)?; //length
                program.syscall()?;
            }
            BfInstruction::LoopStart => {
                //compare byte at rbx with 0, if zero jump to matching LoopEnd
                program.cmp(byte_ptr(rbx), 0)?;
                let loop_end_label = program.create_label();
                let mut loop_start_label = program.create_label();
                program.je(loop_end_label)?;
                //define the label for the LoopStart
                program.set_label(&mut loop_start_label)?;
                loop_stack.push((loop_start_label, loop_end_label));
            }
            BfInstruction::LoopEnd => {
                //pop the loop labels from the stack
                if let Some((loop_start_label, mut loop_end_label)) = loop_stack.pop() {
                    //compare byte at rbx with 0, if not zero jump back to matching LoopStart
                    program.cmp(byte_ptr(rbx), 0)?;
                    program.jne(loop_start_label)?;
                    //define the label for the LoopEnd
                    program.set_label(&mut loop_end_label)?;
                } else {
                    eprintln!("Loop end without matching start at instruction {}", i);
                    std::process::exit(1);
                }
            }
        }
    }

    //now restore the registers and stack before returning
    // do the inverse of these operations:
        // program.push(rbx)?;
        // program.sub(rsp, tape_size)?;

    program.add(rsp, tape_size)?;
    program.pop(rbx)?;
    
    //now return
    program.ret()?;

    Ok(program)
}

#[derive(Debug, PartialEq, Eq)]
enum BfInstruction {
    IncrementPtr,
    DecrementPtr,
    IncrementData,
    DecrementData,
    Output,
    Input,
    LoopStart,
    LoopEnd,
}
