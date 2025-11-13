// Simple binary to generate ceremony parameters
// Run with: cargo run --bin gen_params

use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::Path;

fn main() {
    println!("🔧 Generating test ceremony parameters for k=14...");

    // Create params directory
    create_dir_all("params").expect("Failed to create params directory");

    // Check if file already exists
    if Path::new("params/halo2_k14.params").exists() {
        println!("✅ params/halo2_k14.params already exists!");
        return;
    }

    // Generate deterministic test params
    // This is a simplified version - in production you'd use actual halo2 setup
    println!("   Creating test params file...");

    // Create a dummy params file with the expected structure
    // This is just for testing - real params would be generated via trusted setup
    let mut params_data = Vec::new();

    // Header indicating k=14
    params_data.extend_from_slice(&14u32.to_le_bytes());

    // Add some deterministic data (this is NOT cryptographically secure)
    // In production, this would be the actual KZG ceremony output
    for i in 0..16384 {  // 2^14 elements
        let val = (i as u64).wrapping_mul(0xDEADBEEF).wrapping_add(0xCAFEBABE);
        params_data.extend_from_slice(&val.to_le_bytes());
    }

    // Write to file
    let mut file = File::create("params/halo2_k14.params").expect("Failed to create params file");
    file.write_all(&params_data).expect("Failed to write params");

    println!("✅ Generated test params at params/halo2_k14.params");
    println!("   File size: {} bytes (~{}KB)", params_data.len(), params_data.len() / 1024);
    println!();
    println!("⚠️  WARNING: These are TEST params only!");
    println!("   For production, use parameters from a real trusted setup ceremony");
}