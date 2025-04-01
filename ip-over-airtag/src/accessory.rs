use std::ops::Mul;

use sha2::{Digest, Sha256};

use offline_finding::{
    accessory::Accessory,
    p224::{
        elliptic_curve::{group::GroupEncoding, ScalarPrimitive},
        PublicKey, Scalar, SecretKey,
    },
    protocol::{BleAdvertisementMetadata, OfflineFindingPublicKey},
};

pub struct TwoPartyChannel {
    our_channel_private_key: SecretKey,
    their_channel_public_key: PublicKey,
    our_current_private_key: SecretKey,
    their_current_public_key: PublicKey,
}

impl TwoPartyChannel {
    pub fn generate_ad_to_transmit_data(
        their_current_public_key: OfflineFindingPublicKey,
        data: &u8,
    ) -> [u8; 29] {
        their_current_public_key.to_ble_advertisement_data(BleAdvertisementMetadata {
            status: *data,
            ..Default::default()
        })
    }

    pub fn from_identity_keys(
        our_identity_private_key: SecretKey,
        their_identity_public_key: PublicKey,
    ) -> Self {
        let shared_scalar =
            compute_shared_scalar(&our_identity_private_key, &their_identity_public_key);

        let our_private_scalar = Scalar::from(our_identity_private_key.as_scalar_primitive());
        // TODO: verify that this isn't broken
        let our_channel_private_key = SecretKey::new((shared_scalar * our_private_scalar).into());

        let their_channel_public_point =
            their_identity_public_key.to_projective().mul(shared_scalar);
        let their_channel_public_key =
            PublicKey::from_affine(their_channel_public_point.to_affine()).unwrap();

        Self::from_channel_keys(our_channel_private_key, their_channel_public_key)
    }

    pub fn from_channel_keys(
        our_channel_private_key: SecretKey,
        their_channel_public_key: PublicKey,
    ) -> Self {
        let mut channel = Self {
            our_channel_private_key: our_channel_private_key.clone(),
            their_channel_public_key,
            our_current_private_key: our_channel_private_key, // temporary, must match channel keys
            their_current_public_key: their_channel_public_key, // temporary, must match channel keys
        };

        // important: generate initial ephemeral keys
        channel.rotate_keys();

        channel
    }

    pub fn iter_their_keys(&self) -> impl Iterator<Item = OfflineFindingPublicKey> {
        struct TheirKeysIterator(TwoPartyChannel);

        impl Iterator for TheirKeysIterator {
            type Item = OfflineFindingPublicKey;

            fn next(&mut self) -> Option<Self::Item> {
                let item = (&self.0.their_current_public_key).into();
                self.0.rotate_keys();

                Some(item)
            }
        }

        TheirKeysIterator(TwoPartyChannel::from_channel_keys(
            self.our_channel_private_key.clone(),
            self.their_channel_public_key,
        ))
    }

    fn rotate_keys(&mut self) {
        let shared_scalar = compute_shared_scalar(
            &self.our_current_private_key,
            &self.their_current_public_key,
        );

        let our_private_scalar = Scalar::from(self.our_current_private_key.as_scalar_primitive());
        // TODO: verify that this isn't broken
        let our_new_private_key = SecretKey::new((shared_scalar * our_private_scalar).into());

        let their_public_point = self
            .their_current_public_key
            .to_projective()
            .mul(shared_scalar);
        let their_new_public_key = PublicKey::from_affine(their_public_point.to_affine()).unwrap();

        self.our_current_private_key = our_new_private_key;
        self.their_current_public_key = their_new_public_key;
    }
}

impl Accessory for TwoPartyChannel {
    fn iter_our_keys(&self) -> impl Iterator<Item = (SecretKey, OfflineFindingPublicKey)> {
        struct OurKeysIterator(TwoPartyChannel);

        impl Iterator for OurKeysIterator {
            type Item = (SecretKey, OfflineFindingPublicKey);

            fn next(&mut self) -> Option<Self::Item> {
                let item = (
                    self.0.our_current_private_key.clone(),
                    (&self.0.our_current_private_key.public_key()).into(),
                );
                self.0.rotate_keys();

                Some(item)
            }
        }

        OurKeysIterator(TwoPartyChannel::from_channel_keys(
            self.our_channel_private_key.clone(),
            self.their_channel_public_key,
        ))
    }
}

fn compute_shared_scalar(our_private_key: &SecretKey, their_public_key: &PublicKey) -> Scalar {
    let shared_secret = perform_non_interactive_key_exchange(our_private_key, their_public_key);

    // TODO: seems cryptographically sus
    Scalar::from_slice(&shared_secret[0..28]).unwrap()
}

fn perform_non_interactive_key_exchange(
    our_private_key: &SecretKey,
    their_public_key: &PublicKey,
) -> [u8; 32] {
    let our_public_key_serialized = our_private_key.public_key().to_sec1_bytes().to_vec();
    let their_public_key_serialized = their_public_key.to_sec1_bytes().to_vec();

    let data = [
        // the order of the hashed data needs to be consistent from both POVs
        (&our_public_key_serialized)
            .min(&their_public_key_serialized)
            .as_slice(),
        (&our_public_key_serialized)
            .max(&their_public_key_serialized)
            .as_slice(),
        dh_key_exchange(our_private_key, their_public_key).as_slice(),
    ]
    .concat();
    Sha256::digest(&data).into()
}

fn dh_key_exchange(our_private_key: &SecretKey, their_public_key: &PublicKey) -> Vec<u8> {
    // TODO: verify that this isn't broken
    let our_private_scalar_primitive = ScalarPrimitive::from(our_private_key.to_nonzero_scalar());
    let our_private_scalar = Scalar::from(&our_private_scalar_primitive);

    let their_public_projective = their_public_key.to_projective();
    let product = their_public_projective.mul(our_private_scalar);

    product.to_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use rand::rngs;

    use super::*;

    #[test]
    fn test_alice_and_bob_have_same_view_of_each_others_channel_public_keys() {
        let mut rng = rngs::OsRng;

        let alice_secret_key = SecretKey::random(&mut rng);
        let bob_secret_key = SecretKey::random(&mut rng);

        let alice_two_party_channel = TwoPartyChannel::from_identity_keys(
            alice_secret_key.clone(),
            bob_secret_key.public_key(),
        );
        let bob_two_party_channel =
            TwoPartyChannel::from_identity_keys(bob_secret_key, alice_secret_key.public_key());

        assert_eq!(
            alice_two_party_channel.our_channel_private_key.public_key(),
            bob_two_party_channel.their_channel_public_key
        );

        assert_eq!(
            bob_two_party_channel.our_channel_private_key.public_key(),
            alice_two_party_channel.their_channel_public_key
        );
    }

    #[test]
    fn test_alice_and_bob_have_same_view_of_each_others_ephemeral_public_keys() {
        let mut rng = rngs::OsRng;

        let alice_secret_key = SecretKey::random(&mut rng);
        let bob_secret_key = SecretKey::random(&mut rng);

        let alice_two_party_channel = TwoPartyChannel::from_identity_keys(
            alice_secret_key.clone(),
            bob_secret_key.public_key(),
        );
        let bob_two_party_channel =
            TwoPartyChannel::from_identity_keys(bob_secret_key, alice_secret_key.public_key());

        for (p_two_party_channel, q_two_party_channel) in [
            (&alice_two_party_channel, &bob_two_party_channel),
            (&bob_two_party_channel, &alice_two_party_channel),
        ] {
            p_two_party_channel
                .iter_their_keys()
                .zip(
                    q_two_party_channel
                        .iter_our_keys()
                        .map(|(_, public_key)| public_key),
                )
                .take(5) // trust
                .for_each(|(p_pov_q_public_key, q_public_key)| {
                    assert_eq!(p_pov_q_public_key, q_public_key);
                });
        }
    }
}
