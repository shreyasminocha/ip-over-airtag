use std::ops::Mul;

use sha2::{Digest, Sha256};

use offline_finding::{
    accessory::Accessory,
    p224::{
        elliptic_curve::ScalarPrimitive,
        elliptic_curve::{group::GroupEncoding, rand_core::CryptoRngCore},
        PublicKey, Scalar, SecretKey,
    },
    protocol::{BleAdvertisementMetadata, OfflineFindingPublicKey},
};

pub struct TwoPartyChannel {
    #[allow(dead_code)]
    our_channel_private_key: SecretKey,
    #[allow(dead_code)]
    their_channel_public_key: PublicKey,
    our_current_private_key: SecretKey,
    their_current_public_key: PublicKey,
}

impl Accessory for TwoPartyChannel {
    /// This implementation is a bit of a formality, since we'll usually be constructing with
    /// [`Self::new`].
    fn random(csprng: &mut impl CryptoRngCore) -> Self
    where
        Self: Sized,
    {
        Self {
            our_channel_private_key: SecretKey::random(csprng),
            their_channel_public_key: SecretKey::random(csprng).public_key(),
            our_current_private_key: SecretKey::random(csprng),
            their_current_public_key: SecretKey::random(csprng).public_key(),
        }
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

    fn get_current_public_key(&self) -> OfflineFindingPublicKey {
        (&self.our_current_private_key.public_key()).into()
    }
}

impl TwoPartyChannel {
    pub fn new(our_master_private_key: SecretKey, their_master_public_key: PublicKey) -> Self {
        let shared_scalar =
            compute_shared_scalar(&our_master_private_key, &their_master_public_key);

        let our_private_scalar = Scalar::from(our_master_private_key.as_scalar_primitive());
        // TODO: verify that this isn't broken
        let channel_our_private_key = SecretKey::new((shared_scalar * our_private_scalar).into());

        let channel_their_public_point = their_master_public_key.to_projective().mul(shared_scalar);
        let channel_their_public_key =
            PublicKey::from_affine(channel_their_public_point.to_affine()).unwrap();

        let mut channel = Self {
            our_channel_private_key: channel_our_private_key.clone(),
            their_channel_public_key: channel_their_public_key,
            our_current_private_key: channel_our_private_key, // temporary, must match channel keys
            their_current_public_key: channel_their_public_key, // temporary, must match channel keys
        };

        // important: generate initial ephemeral keys
        channel.rotate_keys();

        channel
    }

    pub fn generate_ad_to_transmit_data(&mut self, data: &u8) -> [u8; 29] {
        let ad_data = OfflineFindingPublicKey::from(&self.their_current_public_key)
            .to_ble_advertisement_data(BleAdvertisementMetadata {
                status: *data,
                ..Default::default()
            });
        self.rotate_keys();

        ad_data
    }
}

fn compute_shared_scalar(our_private_key: &SecretKey, their_public_key: &PublicKey) -> Scalar {
    let shared_secret = perform_non_interactive_key_exchange(our_private_key, their_public_key);

    // TODO: seems cryptographically sus
    Scalar::from_slice(&shared_secret[0..28]).unwrap()
}

fn perform_non_interactive_key_exchange(
    master_private_key: &SecretKey,
    their_master_public_key: &PublicKey,
) -> [u8; 32] {
    let data = [
        master_private_key.public_key().to_sec1_bytes().to_vec(),
        their_master_public_key.to_sec1_bytes().to_vec(),
        dh_key_exchange(master_private_key, their_master_public_key),
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
