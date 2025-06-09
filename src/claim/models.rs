use serde::{Deserialize,Serialize};
use alloy::{primitives::Address};

#[derive(Serialize,Deserialize,Debug)]
pub struct ClaimRequest {
    pub email: String,
    pub address: Address 
}