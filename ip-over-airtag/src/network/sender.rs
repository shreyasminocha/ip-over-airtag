use std::ops::AsyncFnMut;

use anyhow::Result;
use p224::{PublicKey, SecretKey};

use crate::accessory::TwoPartyChannel;

pub struct Sender {
    identity_private_key: SecretKey,
}

impl Sender {
    pub fn new(identity_private_key: SecretKey) -> Self {
        Self {
            identity_private_key,
        }
    }

    pub async fn transmit<F: AsyncFnMut(&[u8; 29], &[u8; 6]) -> Result<()>>(
        self,
        data: &[u8],
        recipient_identity_public_key: PublicKey,
        mut advertise: F,
    ) -> Result<usize> {
        let sender_channel = TwoPartyChannel::from_identity_keys(
            self.identity_private_key.clone(),
            recipient_identity_public_key,
        );

        let mut n = 0;
        let data_public_key_pairs = data.iter().zip(sender_channel.iter_their_keys());

        for (byte, their_public_key) in data_public_key_pairs {
            let bt_address = their_public_key.to_ble_address_bytes_be();
            let ad_data = TwoPartyChannel::generate_ad_to_transmit_data(their_public_key, byte);

            let advertising_result = advertise(&ad_data, &bt_address).await;
            if advertising_result.is_err() {
                return Err(anyhow::anyhow!("failed to send an advertisement"));
            }

            n += 1;
        }

        Ok(n)
    }

    // todo: more reliable version that waits till reports show up
}
