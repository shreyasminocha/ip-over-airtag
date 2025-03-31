use anyhow::Result;
use itertools::Itertools;
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

    pub async fn transmit<F: Fn(&[u8; 29], &[u8; 6]) -> Result<()>>(
        self,
        data: &[u8],
        recipient_identity_public_key: PublicKey,
        advertise: F,
    ) -> Result<usize> {
        let sender_channel = TwoPartyChannel::from_identity_keys(
            self.identity_private_key.clone(),
            recipient_identity_public_key,
        );

        let transmission_result: Result<Vec<_>> = data
            .iter()
            .zip(sender_channel.iter_their_keys())
            .map(|(byte, their_public_key)| {
                let bt_address = their_public_key.to_ble_address_bytes_be();
                let ad_data = TwoPartyChannel::generate_ad_to_transmit_data(their_public_key, byte);

                advertise(&ad_data, &bt_address)
            })
            .take_while_inclusive(|advertising_result| advertising_result.is_ok())
            .collect();

        transmission_result.map(|success_vector| success_vector.len())
    }

    // todo: more reliable version that waits till reports show up
}
