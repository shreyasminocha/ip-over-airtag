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
    let data = [
        our_private_key.public_key().to_sec1_bytes().to_vec(),
        their_public_key.to_sec1_bytes().to_vec(),
        dh_key_exchange(our_private_key, their_public_key),
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
