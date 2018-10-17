// Copyright 2017 Parity Technologies (UK) Ltd.
// This file is part of Substrate.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.

//! Aura (Authority-round) consensus in substrate.
//!
//! Aura works by having a list of authorities A who are expected to roughly
//! agree on the current time. Time is divided up into discrete slots of t
//! seconds each. For each slot s, the author of that slot is A[s % |A|].
//!
//! The author is allowed to issue one block but not more during that slot,
//! and it will be built upon the longest valid chain that has been seen.
//!
//! Blocks from future steps will be either deferred or rejected depending on how
//! far in the future they are.

extern crate parity_codec as codec;
extern crate substrate_consensus_common as consensus_common;
extern crate substrate_client as client;
extern crate substrate_primitives as primitives;
extern crate srml_support as runtime_support;
extern crate sr_primitives as runtime_primitives;
extern crate sr_version as runtime_version;
extern crate sr_io as runtime_io;
extern crate tokio;

#[cfg(test)]
extern crate substrate_keyring as keyring;
extern crate parking_lot;

#[macro_use]
extern crate log;

extern crate futures;

use std::sync::Arc;
use std::time::Duration;

use codec::Encode;
use consensus_common::{Authorities, BlockImport, Environment, Proposer};
use client::{ChainHead, ImportBlock, BlockOrigin};
use runtime_primitives::generic::BlockId;
use runtime_primitives::traits::{Block, Header, DigestItemFor};
use primitives::{AuthorityId, ed25519};

use futures::{Stream, Future, IntoFuture};
use tokio::timer::Interval;

/// Configuration for Aura consensus.
pub struct Config {
	/// The local authority keypair. Can be none if this is just an observer.
	pub local_key: Option<Arc<ed25519::Pair>>,
	/// The slot duration in seconds.
	pub slot_duration: u64
}

/// Get slot author for given block along with authorities.
fn slot_author<B: Block, C: Authorities<B>>(slot_num: u64, client: &C, header: &B::Header)
	-> Result<Option<(AuthorityId, Vec<AuthorityId>)>, C::Error>
{
	let hash = header.hash();
	match client.authorities(&BlockId::Hash(hash)) {
		Ok(authorities) => {
			if authorities.is_empty() { return Ok(None) }

			let idx = slot_num % (authorities.len() as u64);
			assert!(idx <= usize::max_value() as u64,
				"It is impossible to have a vector with length beyond the address space; qed");

			let current_author = *authorities.get(idx as usize)
				.expect("authorities not empty; index constrained to list length;\
					 this is a valid index; qed");

			Ok(Some((current_author, authorities)))
		}
		Err(e) => Err(e)
	}
}

/// Get the slot for now.
fn slot_now(slot_duration: u64) -> Result<u64, ()> {
	use std::time::SystemTime;
	let now = SystemTime::now();
	match now.duration_since(SystemTime::UNIX_EPOCH) {
		Ok(dur) => Ok(dur.as_secs() / slot_duration),
		Err(_) => {
			warn!("Current time {:?} is before unix epoch. Something is wrong.", now);
			return Err(())
		}
	}
}

/// A digest item which is usable with aura consensus.
pub trait CompatibleDigestItem: Sized {
	/// Construct a digest item which is a slot number and a signature on the
	/// hash.
	fn aura_seal(slot_number: u64, signature: ed25519::Signature) -> Self;
}

/// Start the aura worker. This should be run in a tokio runtime.
pub fn start_aura<B, C, E, Error>(config: Config, client: Arc<C>, env: Arc<E>)
	-> impl Future<Item=(),Error=()> where
	B: Block,
	C: Authorities<B, Error=Error> + BlockImport<B, Error=Error> + ChainHead<B>,
	E: Environment<B, Error=Error>,
	E::Proposer: Proposer<B, Error=Error>,
	DigestItemFor<B>: CompatibleDigestItem,
	Error: ::std::error::Error + Send + 'static + From<::consensus_common::Error>,
{
	use futures::future::Either;

	let local_keys = config.local_key.map(|pair| (pair.public(), pair));
	let slot_duration = config.slot_duration;
	let mut last_authored_slot = 0;

	Interval::new_interval(Duration::from_secs(slot_duration))
		.filter_map(move |_| local_keys.clone()) // skip if not authoring.
		.map_err(|e|  debug!(target: "aura", "Faulty timer: {:?}", e))
		.for_each(move |(public_key, key)| {
			use futures::future;

			let slot_num = match slot_now(slot_duration) {
				Ok(n) => n,
				Err(()) => return Either::B(future::err(())),
			};

			if last_authored_slot >= slot_num { return Either::B(future::ok(())) }
			last_authored_slot = slot_num;

			let chain_head = match client.best_block_header() {
				Ok(x) => x,
				Err(e) => {
					warn!("Unable to author block in slot {}. no best block header: {:?}", slot_num, e);
					return Either::B(future::ok(()))
				}
			};

			let proposal_work = match slot_author(slot_num, &*client, &chain_head) {
				Ok(None) => return Either::B(future::ok(())),
				Ok(Some((author, authorities))) => if author.0 == public_key.0 {
					// we are the slot author. make a block and sign it.
					let proposer = match env.init(&chain_head, &authorities, key.clone()) {
						Ok(p) => p,
						Err(e) => {
							warn!("Unable to author block in slot {:?}: {:?}", slot_num, e);
							return Either::B(future::ok(()))
						}
					};

					proposer.propose().into_future()
				} else {
					return Either::B(future::ok(()));
				}
				Err(e) => {
					warn!("Unable to fetch authorities at block {:?}: {:?}", chain_head.hash(), e);
					return Either::B(future::ok(()));
				}
			};

			let block_import = client.clone();
			Either::A(proposal_work
				.map(move |b| {
					let (header, body) = b.deconstruct();
					let pre_hash = header.hash();
					let parent_hash = header.parent_hash().clone();

					// sign the pre-sealed hash of the block and then
					// add it to a digest item.
					let to_sign = (slot_num, pre_hash).encode();
					let signature = key.sign(&to_sign[..]);
					let item = <DigestItemFor<B> as CompatibleDigestItem>::aura_seal(slot_num, signature);
					let import_block = ImportBlock {
						origin: BlockOrigin::Own,
						header,
						external_justification: Vec::new(),
						post_runtime_digests: vec![item],
						body: Some(body),
						finalized: false,
						auxiliary: Vec::new(),
					};

					if let Err(e) = block_import.import_block(import_block, None) {
						warn!("Error with block built on {:?}: {:?}", parent_hash, e);
					}
				})
				.map_err(|e| warn!("Failed to construct block: {:?}", e))
			)
		})
}
