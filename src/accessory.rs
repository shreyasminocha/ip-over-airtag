use std::ops::Mul;

use sha2::{Digest, Sha256};

use offline_finding::{
    p224::{
        elliptic_curve::ScalarPrimitive,
        elliptic_curve::{group::GroupEncoding, rand_core::CryptoRngCore},
        PublicKey, Scalar, SecretKey,
    },
    Accessory, BleAdvertisementMetadata, OfflineFindingPublicKey,
};

pub struct TwoPartyChannel {
    our_channel_private_key: SecretKey,
    their_channel_public_key: PublicKey,
}

impl Accessory for TwoPartyChannel {
    /// This implementation is a bit of a formality, since we'll usually be constructing with
    /// [`Self::new`].
    fn random(csprng: &mut impl CryptoRngCore) -> Self
    where
        Self: Sized,
    {
        let master_private_key = SecretKey::random(csprng);

        Self {
            our_channel_private_key: master_private_key.clone(),
            their_channel_public_key: master_private_key.public_key(), // temporary, probably
        }
    }

    fn rotate_keys(&mut self) {}

    fn get_current_public_key(&self) -> OfflineFindingPublicKey {
        (&self.our_channel_private_key.public_key()).into()
    }
}

impl TwoPartyChannel {
    pub fn new(our_master_private_key: SecretKey, their_master_public_key: PublicKey) -> Self {
        let shared_scalar =
            perform_non_interactive_key_exchange(&our_master_private_key, &their_master_public_key);
        let our_private_scalar = Scalar::from(our_master_private_key.as_scalar_primitive());

        let channel_our_private_key = SecretKey::new((shared_scalar * our_private_scalar).into());

        let channel_their_public_point = their_master_public_key.to_projective().mul(shared_scalar);
        let channel_their_public_key =
            PublicKey::from_affine(channel_their_public_point.to_affine()).unwrap();

        Self {
            our_channel_private_key: channel_our_private_key,
            their_channel_public_key: channel_their_public_key,
        }
    }

    pub fn generate_ad_to_transmit_data(&mut self, data: &u8) -> [u8; 29] {
        let ad_data = OfflineFindingPublicKey::from(&self.their_channel_public_key)
            .to_ble_advertisement_data(BleAdvertisementMetadata {
                status: *data,
                ..Default::default()
            });
        self.rotate_keys();

        ad_data
    }
}

fn perform_non_interactive_key_exchange(
    master_private_key: &SecretKey,
    their_master_public_key: &PublicKey,
) -> Scalar {
    let data = [
        master_private_key.public_key().to_sec1_bytes().to_vec(),
        their_master_public_key.to_sec1_bytes().to_vec(),
        dh_key_exchange(master_private_key, their_master_public_key),
    ]
    .concat();

    let shared_secret = Sha256::digest(&data).to_vec();
    // TODO: seems cryptographically sus
    let shared_scalar = Scalar::from_slice(&shared_secret.as_slice()[0..28]).unwrap();

    shared_scalar
}

fn dh_key_exchange(our_private_key: &SecretKey, their_public_key: &PublicKey) -> Vec<u8> {
    let our_private_scalar_primitive = ScalarPrimitive::from(our_private_key.to_nonzero_scalar());
    let our_private_scalar = Scalar::from(&our_private_scalar_primitive);

    let their_public_projective = their_public_key.to_projective();
    let product = their_public_projective.mul(our_private_scalar);

    product.to_bytes().to_vec()
}
