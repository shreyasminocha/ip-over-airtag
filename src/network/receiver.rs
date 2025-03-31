use std::collections::HashMap;

use anyhow::Result;
use itertools::Itertools;
use offline_finding::{
    accessory::Accessory,
    protocol::{OfflineFindingPublicKey, ReportPayloadAsReceived},
    server::{AppleReportResponse, AppleReportsServer, RemoteAnisetteProvider},
};
use p224::{PublicKey, SecretKey};

use crate::accessory::TwoPartyChannel;

pub struct Receiver {
    identity_private_key: SecretKey,
}

impl Receiver {
    pub fn new(identity_private_key: SecretKey) -> Self {
        Self {
            identity_private_key,
        }
    }

    pub async fn receive(&self, sender_identity_public_key: PublicKey) -> Result<Vec<u8>> {
        let mut apple_reports_server =
            AppleReportsServer::new(RemoteAnisetteProvider::new("https://localhost:8080"));

        let mut data = vec![];

        let receiver_channel = TwoPartyChannel::from_identity_keys(
            self.identity_private_key.clone(),
            sender_identity_public_key,
        );

        let key_chunks = receiver_channel.iter_our_keys().chunks(256);

        for key_chunk in &key_chunks {
            let keys_and_ids: Vec<_> = key_chunk
                .map(|(private_key, public_key)| (private_key, public_key.hash()))
                .collect();

            let reports = apple_reports_server
                .fetch_and_decrypt_reports(keys_and_ids.as_ref())
                .await
                .unwrap();

            // we need to order reports by id
            let mut report_hashmap: HashMap<
                [u8; 32],
                Vec<AppleReportResponse<ReportPayloadAsReceived>>,
            > = HashMap::new();

            for report in reports {
                report_hashmap.entry(report.id()).or_default().push(report);
            }

            let status_bytes = keys_and_ids.iter().map_while(|(_, id)| {
                report_hashmap.get(id).map(|id_reports| {
                    let status_bytes = id_reports.iter().map(|r| r.payload.location.status);
                    let status_byte_groups = status_bytes.sorted().chunk_by(|&x| x);

                    status_byte_groups
                        .into_iter()
                        .map(|(key, group)| (key, group.count()))
                        .max_by_key(|&(_, count)| count)
                        .expect("at this point, we already know that there's at least one report")
                        .0
                })
            });

            data.extend(status_bytes);
        }

        Ok(data)
    }

    pub fn get_keys_for_fetching_and_decrypting(
        &self,
        sender_identity_public_key: PublicKey,
        data_length: usize,
    ) -> Vec<(SecretKey, OfflineFindingPublicKey)> {
        let receiver_channel = TwoPartyChannel::from_identity_keys(
            self.identity_private_key.clone(),
            sender_identity_public_key,
        );

        receiver_channel.iter_our_keys().take(data_length).collect()
    }
}
