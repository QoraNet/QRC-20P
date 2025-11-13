use ethereum_types::U256;

fn main() {
    let amount = U256::from(1000u64);
    
    // Try method 1: no arguments
    // let bytes = amount.to_big_endian();
    
    // Try method 2: with buffer
    let mut bytes = [0u8; 32];
    amount.to_big_endian(&mut bytes);
    
    println!("{:?}", bytes);
}
