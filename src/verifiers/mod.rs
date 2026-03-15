pub mod audit;
pub mod process;

/// Verification result: Ok carries the snapshot ID; Failed carries the failure reason.
// snapshot_id / reason will be consumed by audit.rs in P2
#[allow(dead_code)]
pub enum VerificationResult {
    Ok { snapshot_id: u64 },
    Failed { reason: String, snapshot_id: u64 },
}

/// All collector outputs must implement this trait to enter the main loop
pub trait Verifiable {
    /// Return the snapshot's unique monotonic ID, used as the Storage rollback index (P2)
    #[allow(dead_code)]
    fn snapshot_id(&self) -> u64;
    /// Run data validation and return the verification result
    fn verify(&self) -> VerificationResult;
}
