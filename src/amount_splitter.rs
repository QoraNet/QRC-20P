//! Smart Amount Splitting for Maximum Privacy
//!
//! GUARANTEES:
//! - No amount loss (sum of chunks ALWAYS equals original)
//! - No infinite loops
//! - Thread-safe operations
//! - Deterministic verification

use ethereum_types::{Address, U256};
use rand::{Rng, thread_rng};
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::{Result, anyhow};
use chrono;

/// Amount splitter with verification
pub struct AmountSplitter {
    /// Standard denominations (like cash bills)
    standard_denoms: Vec<U256>,
    /// Splitting strategies
    strategies: Vec<SplitStrategy>,
    /// Minimum chunk size to prevent dust
    min_chunk_size: U256,
}

#[derive(Clone, Debug)]
pub enum SplitStrategy {
    /// Use standard denominations (like ATM)
    StandardDenominations,
    /// Random chunks
    RandomSplit,
    /// Power of 2 (binary split)
    BinarySplit,
    /// Fibonacci sequence
    FibonacciSplit,
}

impl AmountSplitter {
    pub fn new() -> Self {
        Self {
            // Common amounts that many people use
            standard_denoms: vec![
                U256::from(1),      // 1 QOR
                U256::from(5),
                U256::from(10),
                U256::from(50),
                U256::from(100),    // 100 QOR (very common)
                U256::from(500),
                U256::from(1000),   // 1000 QOR (round number)
                U256::from(5000),
                U256::from(10000),
            ],
            strategies: vec![
                SplitStrategy::StandardDenominations,
                SplitStrategy::RandomSplit,
                SplitStrategy::BinarySplit,
                SplitStrategy::FibonacciSplit,
            ],
            min_chunk_size: U256::from(1), // Minimum 1 QOR per chunk
        }
    }

    /// Smart split that maximizes privacy WITH VERIFICATION
    pub fn split_for_privacy(&self, amount: U256) -> Result<Vec<U256>> {
        // Validate input
        if amount == U256::zero() {
            return Err(anyhow!("Cannot split zero amount"));
        }

        // Choose random strategy to be unpredictable
        let strategy = &self.strategies[thread_rng().gen_range(0..self.strategies.len())];

        let chunks = match strategy {
            SplitStrategy::StandardDenominations => self.split_standard(amount)?,
            SplitStrategy::RandomSplit => self.split_random_safe(amount)?,
            SplitStrategy::BinarySplit => self.split_binary(amount)?,
            SplitStrategy::FibonacciSplit => self.split_fibonacci_safe(amount)?,
        };

        // CRITICAL: Verify no amount loss
        self.verify_amount_conservation(amount, &chunks)?;

        Ok(chunks)
    }

    /// CRITICAL: Verify sum of chunks equals original amount
    fn verify_amount_conservation(&self, original: U256, chunks: &[U256]) -> Result<()> {
        let mut sum = U256::zero();

        // Use checked arithmetic to detect overflow
        for &chunk in chunks {
            sum = sum.checked_add(chunk)
                .ok_or_else(|| anyhow!(
                    "Integer overflow in amount verification! Sum: {}, Chunk: {}",
                    sum, chunk
                ))?;
        }

        if sum != original {
            return Err(anyhow!(
                "Amount conservation failed! Original: {}, Sum: {}, Difference: {}",
                original,
                sum,
                if original > sum { original - sum } else { sum - original }
            ));
        }

        // Verify no zero chunks
        if chunks.iter().any(|&c| c == U256::zero()) {
            return Err(anyhow!("Zero-value chunks detected"));
        }

        Ok(())
    }

    /// Split into standard denominations (BEST for privacy)
    fn split_standard(&self, mut amount: U256) -> Result<Vec<U256>> {
        let mut result = Vec::new();

        // Use large denominations first
        for &denom in self.standard_denoms.iter().rev() {
            // Limit chunks to prevent too many small pieces
            let max_of_this_denom = 3;
            let mut count = 0;

            while amount >= denom && count < max_of_this_denom {
                result.push(denom);
                amount = amount.checked_sub(denom)
                    .ok_or_else(|| anyhow!("Underflow in denomination split"))?;
                count += 1;

                // Randomly stop using this denomination (more variety)
                if thread_rng().gen_bool(0.3) {
                    break;
                }
            }
        }

        // Add remainder as separate chunk
        if amount > U256::zero() {
            // If remainder is too small, combine with last chunk
            if amount < self.min_chunk_size && !result.is_empty() {
                let last = result.pop()
                    .ok_or_else(|| anyhow!("Internal error: result vector unexpectedly empty"))?;
                let combined = last.checked_add(amount)
                    .ok_or_else(|| anyhow!("Overflow combining small remainder"))?;
                result.push(combined);
            } else {
                result.push(amount);
            }
        }

        // Shuffle to hide order
        use rand::seq::SliceRandom;
        result.shuffle(&mut thread_rng());

        Ok(result)
    }

    /// SAFE Random split (no precision loss)
    fn split_random_safe(&self, amount: U256) -> Result<Vec<U256>> {
        let mut result = Vec::new();
        let mut remaining = amount;

        // Random number of chunks (3-10)
        let chunks = thread_rng().gen_range(3..=10);

        // Generate random split points
        for _i in 0..chunks - 1 {
            if remaining <= self.min_chunk_size {
                break;
            }

            // Safe calculation: take 10-40% but ensure we don't lose precision
            let max_chunk = remaining / 2; // Never take more than half
            if max_chunk == U256::zero() {
                break;
            }

            // FIX: Prevent precision loss for small amounts
            // Instead of (max_chunk * random_factor) / 100 which loses precision,
            // we calculate the percentage more precisely
            let chunk = if max_chunk > U256::from(100) {
                // For large amounts, use percentage-based splitting
                let random_factor = thread_rng().gen_range(10..=40); // 10-40%
                // Calculate percentage without precision loss:
                // chunk = max_chunk * random_factor / 100
                // But do division first if max_chunk is divisible by 100
                let chunk_base = max_chunk / 100;
                if chunk_base > U256::zero() {
                    // No precision loss: divide first, then multiply
                    chunk_base.saturating_mul(U256::from(random_factor))
                } else {
                    // max_chunk < 100, so just take a portion directly
                    max_chunk / U256::from(thread_rng().gen_range(2..=5))
                }
            } else if max_chunk > U256::from(1) {
                // For small amounts (1 < max_chunk <= 100), use direct division
                // to avoid precision loss from percentage calculation
                let divisor = thread_rng().gen_range(2..=4);
                max_chunk / U256::from(divisor)
            } else {
                // max_chunk == 1, take it
                U256::from(1)
            };

            // Ensure we have a valid chunk
            let chunk = chunk.max(self.min_chunk_size);

            // Only use the chunk if it doesn't exceed remaining
            if chunk <= remaining {
                result.push(chunk);
                remaining = remaining.checked_sub(chunk)
                    .ok_or_else(|| anyhow!("Underflow in random split"))?;
            }
        }

        // Add remainder - GUARANTEED no loss
        if remaining > U256::zero() {
            result.push(remaining);
        }

        // If no chunks created, just return the original amount
        if result.is_empty() {
            result.push(amount);
        }

        Ok(result)
    }

    /// Binary split (powers of 2) - SAFE
    fn split_binary(&self, amount: U256) -> Result<Vec<U256>> {
        let mut result = Vec::new();
        let mut bit = U256::from(1);
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 256; // U256 has max 256 bits

        while bit <= amount && iterations < MAX_ITERATIONS {
            if amount & bit != U256::zero() {
                result.push(bit);
            }

            // Safe bit shift with overflow check
            match bit.checked_mul(U256::from(2)) {
                Some(next_bit) => bit = next_bit,
                None => break, // Overflow, stop
            }
            iterations += 1;
        }

        // Verify sum equals original (should always pass for binary split)
        // Verify with checked arithmetic
        let mut sum = U256::zero();
        for &x in &result {
            sum = sum.checked_add(x)
                .ok_or_else(|| anyhow!("Overflow in binary split verification"))?;
        }
        if sum != amount {
            return Err(anyhow!("Binary split verification failed"));
        }

        Ok(result)
    }

    /// SAFE Fibonacci split (with overflow protection)
    fn split_fibonacci_safe(&self, amount: U256) -> Result<Vec<U256>> {
        let mut result = Vec::new();
        let mut remaining = amount;

        // Generate Fibonacci sequence up to amount
        let mut fib = vec![U256::from(1), U256::from(1)];
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 1000; // Prevent infinite loop

        while fib[fib.len() - 1] < amount && iterations < MAX_ITERATIONS {
            let prev1 = fib[fib.len() - 1];
            let prev2 = fib[fib.len() - 2];

            // Safe addition with overflow check
            match prev1.checked_add(prev2) {
                Some(next) => fib.push(next),
                None => break, // Overflow, stop generating
            }
            iterations += 1;
        }

        // Use fibonacci numbers in reverse (greedy approach)
        for &f in fib.iter().rev() {
            if f <= remaining && f >= self.min_chunk_size {
                result.push(f);
                remaining = remaining.checked_sub(f)
                    .ok_or_else(|| anyhow!("Underflow in Fibonacci split"))?;
            }
        }

        // Add remainder if any
        if remaining > U256::zero() {
            if remaining >= self.min_chunk_size {
                result.push(remaining);
            } else if !result.is_empty() {
                // Combine with last chunk if too small
                let last = result.pop()
                    .ok_or_else(|| anyhow!("Internal error: result vector unexpectedly empty"))?;
                let combined = last.checked_add(remaining)
                    .ok_or_else(|| anyhow!("Overflow combining Fibonacci remainder"))?;
                result.push(combined);
            } else {
                result.push(remaining); // Accept small amount if it's all we have
            }
        }

        Ok(result)
    }
}

/// Amount mixer - combines multiple users' amounts SAFELY
pub struct AmountMixer {
    /// Completed mixes for verification
    completed: Arc<RwLock<Vec<CompletedMix>>>,
}

#[derive(Clone, Debug)]
struct CompletedMix {
    original_total: U256,
    output_total: U256,
    timestamp: u64,
}

impl AmountMixer {
    pub fn new() -> Self {
        Self {
            completed: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Mix amounts from multiple users CONCURRENTLY (not blocking)
    pub async fn mix_amounts(&self, entries: Vec<(Address, U256)>) -> Result<Vec<(Address, U256)>> {
        // Calculate original total with overflow detection
        let mut original_total = U256::zero();
        for (_, amt) in &entries {
            original_total = original_total.checked_add(*amt)
                .ok_or_else(|| anyhow!("Overflow calculating original total"))?;
        }

        let mut all_chunks = Vec::new();
        let splitter = AmountSplitter::new();

        // Split everyone's amounts
        for (user, amount) in entries {
            let chunks = splitter.split_for_privacy(amount)?;
            for chunk in chunks {
                all_chunks.push((user, chunk));
            }
        }

        // Shuffle all chunks together
        use rand::seq::SliceRandom;
        all_chunks.shuffle(&mut thread_rng());

        // Verify total conservation with overflow detection
        let mut output_total = U256::zero();
        for (_, amt) in &all_chunks {
            output_total = output_total.checked_add(*amt)
                .ok_or_else(|| anyhow!("Overflow calculating output total"))?;
        }

        if original_total != output_total {
            return Err(anyhow!(
                "Mixing amount mismatch! Original: {}, Output: {}",
                original_total,
                output_total
            ));
        }

        // Record completion
        let completed_entry = CompletedMix {
            original_total,
            output_total,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        self.completed.write().await.push(completed_entry);

        Ok(all_chunks)
    }

    /// Process chunks with delays (NON-BLOCKING)
    pub async fn process_chunks_async(
        &self,
        chunks: Vec<(Address, U256)>,
        delay_range: (u64, u64),
    ) -> Vec<tokio::task::JoinHandle<Result<(Address, U256)>>> {
        let mut handles = Vec::new();

        for (user, chunk) in chunks {
            let delay = thread_rng().gen_range(delay_range.0..=delay_range.1);

            // Each chunk processed independently
            let handle = tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
                Ok((user, chunk))
            });

            handles.push(handle);
        }

        handles
    }

    /// Verify all mixes completed correctly
    pub async fn verify_all_mixes(&self) -> Result<()> {
        let completed = self.completed.read().await;

        for mix in completed.iter() {
            if mix.original_total != mix.output_total {
                return Err(anyhow!(
                    "Mix verification failed at timestamp {}",
                    mix.timestamp
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amount_conservation() {
        let splitter = AmountSplitter::new();

        // Test various amounts
        let test_amounts = vec![
            U256::from(1),
            U256::from(100),
            U256::from(1234),
            U256::from(999999),
        ];

        for amount in test_amounts {
            let chunks = splitter.split_for_privacy(amount).unwrap();
            // Use checked arithmetic to detect overflow
            let sum: U256 = chunks.iter().try_fold(U256::zero(), |acc, &x| {
                acc.checked_add(x).ok_or_else(|| "Integer overflow in test")
            }).expect("Overflow detected in amount verification");
            assert_eq!(sum, amount, "Amount conservation failed for {}", amount);
            assert!(!chunks.is_empty(), "No chunks generated");
            assert!(chunks.iter().all(|&c| c > U256::zero()), "Zero chunk found");
        }
    }

    #[test]
    fn test_no_precision_loss() {
        let splitter = AmountSplitter::new();

        // Test with small amounts that could lose precision
        let amount = U256::from(7); // Small prime number
        let chunks = splitter.split_for_privacy(amount).unwrap();
        // Use checked arithmetic to detect overflow
        let sum: U256 = chunks.iter().try_fold(U256::zero(), |acc, &x| {
            acc.checked_add(x).ok_or_else(|| "Integer overflow in test")
        }).expect("Overflow detected in precision test");

        assert_eq!(sum, amount, "Precision lost with small amount");
    }

    #[test]
    fn test_edge_cases_precision() {
        let splitter = AmountSplitter::new();

        // Test edge cases that previously could lose precision
        let test_cases = vec![
            U256::from(1),     // Minimum amount
            U256::from(2),     // Very small
            U256::from(3),     // Small prime
            U256::from(50),    // Would lose precision with /100
            U256::from(99),    // Just under 100
            U256::from(100),   // Exact 100
            U256::from(101),   // Just over 100
            U256::from(255),   // Byte boundary
            U256::from(256),   // Power of 2
            U256::from(1000),  // Round number
        ];

        for amount in test_cases {
            // Test with random split specifically (where the bug was)
            let strategy = SplitStrategy::RandomSplit;
            let chunks = match strategy {
                SplitStrategy::RandomSplit => splitter.split_random_safe(amount).unwrap(),
                _ => panic!("Wrong strategy"),
            };

            // Verify no precision loss
            let sum: U256 = chunks.iter().try_fold(U256::zero(), |acc, &x| {
                acc.checked_add(x).ok_or_else(|| "Integer overflow in test")
            }).expect("Overflow detected in edge case test");

            assert_eq!(sum, amount, "Precision lost for amount {}", amount);

            // Verify no zero chunks
            assert!(chunks.iter().all(|&c| c > U256::zero()),
                "Zero chunk found for amount {}", amount);

            // Verify all chunks respect minimum size
            assert!(chunks.iter().all(|&c| c >= splitter.min_chunk_size),
                "Chunk below minimum size for amount {}", amount);
        }
    }

    #[test]
    fn test_overflow_protection() {
        let splitter = AmountSplitter::new();

        // Test with maximum U256 value
        let max_amount = U256::MAX;
        let chunks = splitter.split_for_privacy(max_amount).unwrap();

        // Verify sum using checked arithmetic
        let mut sum = U256::zero();
        for &chunk in &chunks {
            sum = sum.checked_add(chunk)
                .expect("Overflow should be prevented");
        }

        assert_eq!(sum, max_amount, "Failed with maximum U256 value");
    }

    #[tokio::test]
    async fn test_mixer_conservation() {
        let mixer = AmountMixer::new();

        let entries = vec![
            (Address::random(), U256::from(1000)),
            (Address::random(), U256::from(2000)),
            (Address::random(), U256::from(3000)),
        ];

        let original_total = U256::from(6000);
        let mixed = mixer.mix_amounts(entries).await.unwrap();

        let output_total: U256 = mixed.iter()
            .try_fold(U256::zero(), |acc, (_, amt)| {
                acc.checked_add(*amt).ok_or_else(|| "Integer overflow in total calculation")
            })
            .expect("Overflow in mixer conservation test");

        assert_eq!(output_total, original_total, "Mixer lost funds!");
    }
}
