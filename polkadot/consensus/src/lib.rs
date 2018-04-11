// Copyright 2017 Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

//! Propagation and agreement of candidates.
//!
//! Authorities are split into groups by parachain, and each authority might come
//! up its own candidate for their parachain. Within groups, authorities pass around
//! their candidates and produce statements of validity.
//!
//! Any candidate that receives majority approval by the authorities in a group
//! may be subject to inclusion, unless any authorities flag that candidate as invalid.
//!
//! Wrongly flagging as invalid should be strongly disincentivized, so that in the
//! equilibrium state it is not expected to happen. Likewise with the submission
//! of invalid blocks.
//!
//! Groups themselves may be compromised by malicious authorities.

extern crate ed25519;
extern crate parking_lot;
extern crate polkadot_api;
extern crate polkadot_collator as collator;
extern crate polkadot_statement_table as table;
extern crate polkadot_primitives;
extern crate polkadot_transaction_pool as transaction_pool;
extern crate polkadot_runtime;
extern crate substrate_bft as bft;
extern crate substrate_codec as codec;
extern crate substrate_primitives as primitives;
extern crate substrate_runtime_support as runtime_support;
extern crate substrate_network;

extern crate tokio_core;
extern crate tokio_timer;
extern crate substrate_keyring;
extern crate substrate_client as client;

#[macro_use]
extern crate error_chain;

#[macro_use]
extern crate futures;

#[macro_use]
extern crate log;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use codec::Slicable;
use table::generic::Statement as GenericStatement;
use runtime_support::Hashable;
use polkadot_api::{PolkadotApi, BlockBuilder};
use polkadot_primitives::{Hash, Timestamp};
use polkadot_primitives::parachain::{Id as ParaId, Chain, DutyRoster, BlockData, Extrinsic, CandidateReceipt};
use polkadot_runtime::Block as PolkadotGenericBlock;
use primitives::block::{Block as SubstrateBlock, Header as SubstrateHeader, HeaderHash, Id as BlockId, Number as BlockNumber};
use primitives::AuthorityId;
use transaction_pool::{Ready, TransactionPool, PolkadotBlock};
use tokio_timer::{Timer, Interval, Sleep, TimerError};

use futures::prelude::*;
use parking_lot::Mutex;
use collation::{Collators, CollationFetch};
use dynamic_inclusion::DynamicInclusion;

pub use self::error::{ErrorKind, Error};
pub use self::shared_table::{SharedTable, StatementSource, StatementProducer, ProducedStatements};
pub use service::Service;

mod collation;
mod dynamic_inclusion;
mod error;
mod service;
mod shared_table;

// block size limit.
const MAX_TRANSACTIONS_SIZE: usize = 4 * 1024 * 1024;

/// A handle to a statement table router.
///
/// This is expected to be a lightweight, shared type like an `Arc`.
pub trait TableRouter: Clone {
	/// Errors when fetching data from the network.
	type Error;
	/// Future that resolves when candidate data is fetched.
	type FetchCandidate: IntoFuture<Item=BlockData,Error=Self::Error>;
	/// Future that resolves when extrinsic candidate data is fetched.
	type FetchExtrinsic: IntoFuture<Item=Extrinsic,Error=Self::Error>;

	/// Note local candidate data, making it available on the network to other validators.
	fn local_candidate_data(&self, hash: Hash, block_data: BlockData, extrinsic: Extrinsic);

	/// Fetch block data for a specific candidate.
	fn fetch_block_data(&self, candidate: &CandidateReceipt) -> Self::FetchCandidate;

	/// Fetch extrinsic data for a specific candidate.
	fn fetch_extrinsic_data(&self, candidate: &CandidateReceipt) -> Self::FetchExtrinsic;
}

/// A long-lived network which can create statement table routing instances.
pub trait Network {
	/// The table router type. This should handle importing of any statements,
	/// routing statements to peers, and driving completion of any `StatementProducers`.
	type TableRouter: TableRouter;

	/// Instantiate a table router using the given shared table.
	fn table_router(&self, table: Arc<SharedTable>) -> Self::TableRouter;
}

/// Information about a specific group.
#[derive(Debug, Clone, Default)]
pub struct GroupInfo {
	/// Authorities meant to check validity of candidates.
	pub validity_guarantors: HashSet<AuthorityId>,
	/// Authorities meant to check availability of candidate data.
	pub availability_guarantors: HashSet<AuthorityId>,
	/// Number of votes needed for validity.
	pub needed_validity: usize,
	/// Number of votes needed for availability.
	pub needed_availability: usize,
}

/// Sign a table statement against a parent hash.
/// The actual message signed is the encoded statement concatenated with the
/// parent hash.
pub fn sign_table_statement(statement: &table::Statement, key: &ed25519::Pair, parent_hash: &Hash) -> ed25519::Signature {
	use polkadot_primitives::parachain::Statement as RawStatement;

	let raw = match *statement {
		GenericStatement::Candidate(ref c) => RawStatement::Candidate(c.clone()),
		GenericStatement::Valid(h) => RawStatement::Valid(h),
		GenericStatement::Invalid(h) => RawStatement::Invalid(h),
		GenericStatement::Available(h) => RawStatement::Available(h),
	};

	let mut encoded = raw.encode();
	encoded.extend(&parent_hash.0);

	key.sign(&encoded)
}

fn make_group_info(roster: DutyRoster, authorities: &[AuthorityId], local_id: AuthorityId) -> Result<(HashMap<ParaId, GroupInfo>, LocalDuty), Error> {
	if roster.validator_duty.len() != authorities.len() {
		bail!(ErrorKind::InvalidDutyRosterLength(authorities.len(), roster.validator_duty.len()))
	}

	if roster.guarantor_duty.len() != authorities.len() {
		bail!(ErrorKind::InvalidDutyRosterLength(authorities.len(), roster.guarantor_duty.len()))
	}

	let mut local_validation = None;
	let mut map = HashMap::new();

	let duty_iter = authorities.iter().zip(&roster.validator_duty).zip(&roster.guarantor_duty);
	for ((authority, v_duty), a_duty) in duty_iter {
		if authority == &local_id {
			local_validation = Some(v_duty.clone());
		}

		match *v_duty {
			Chain::Relay => {}, // does nothing for now.
			Chain::Parachain(ref id) => {
				map.entry(id.clone()).or_insert_with(GroupInfo::default)
					.validity_guarantors
					.insert(authority.clone());
			}
		}

		match *a_duty {
			Chain::Relay => {}, // does nothing for now.
			Chain::Parachain(ref id) => {
				map.entry(id.clone()).or_insert_with(GroupInfo::default)
					.availability_guarantors
					.insert(authority.clone());
			}
		}
	}

	for live_group in map.values_mut() {
		let validity_len = live_group.validity_guarantors.len();
		let availability_len = live_group.availability_guarantors.len();

		live_group.needed_validity = validity_len / 2 + validity_len % 2;
		live_group.needed_availability = availability_len / 2 + availability_len % 2;
	}

	match local_validation {
		Some(local_validation) => {
			let local_duty = LocalDuty {
				validation: local_validation,
			};

			Ok((map, local_duty))
		}
		None => bail!(ErrorKind::NotValidator(local_id)),
	}
}

/// Polkadot proposer factory.
pub struct ProposerFactory<C, N, P> {
	/// The client instance.
	pub client: Arc<C>,
	/// The transaction pool.
	pub transaction_pool: Arc<Mutex<TransactionPool>>,
	/// The backing network handle.
	pub network: N,
	/// Parachain collators.
	pub collators: P,
	/// The timer used to schedule proposal intervals.
	pub timer: Timer,
	/// The duration after which parachain-empty blocks will be allowed.
	pub parachain_empty_duration: Duration,
}

impl<C, N, P> bft::ProposerFactory for ProposerFactory<C, N, P>
	where
		C: PolkadotApi,
		N: Network,
		P: Collators,
{
	type Proposer = Proposer<C, N::TableRouter, P>;
	type Error = Error;

	fn init(&self, parent_header: &SubstrateHeader, authorities: &[AuthorityId], sign_with: Arc<ed25519::Pair>) -> Result<Self::Proposer, Error> {
		let parent_hash = parent_header.blake2_256().into();

		let checked_id = self.client.check_id(BlockId::Hash(parent_hash))?;
		let duty_roster = self.client.duty_roster(&checked_id)?;
		let random_seed = self.client.random_seed(&checked_id)?;

		let (group_info, local_duty) = make_group_info(
			duty_roster,
			authorities,
			sign_with.public().0,
		)?;

		let n_parachains = group_info.len();
		let table = Arc::new(SharedTable::new(group_info, sign_with.clone(), parent_hash));
		let router = self.network.table_router(table.clone());
		let dynamic_inclusion = DynamicInclusion::new(
			n_parachains,
			Instant::now(),
			self.parachain_empty_duration.clone(),
		);

		Ok(Proposer {
			parent_hash,
			parent_number: parent_header.number,
			parent_id: checked_id,
			random_seed,
			local_key: sign_with,
			client: self.client.clone(),
			timer: self.timer.clone(),
			transaction_pool: self.transaction_pool.clone(),
			collators: self.collators.clone(),
			local_duty,
			dynamic_inclusion,
			table,
			router,
		})
	}
}

struct LocalDuty {
	validation: Chain,
}

/// The Polkadot proposer logic.
pub struct Proposer<C: PolkadotApi, R, P> {
	parent_hash: HeaderHash,
	parent_number: BlockNumber,
	parent_id: C::CheckedBlockId,
	random_seed: Hash,
	client: Arc<C>,
	local_key: Arc<ed25519::Pair>,
	transaction_pool: Arc<Mutex<TransactionPool>>,
	local_duty: LocalDuty,
	collators: P,
	timer: Timer,
	dynamic_inclusion: DynamicInclusion,
	table: Arc<SharedTable>,
	router: R,
}

impl<C, R, P> bft::Proposer for Proposer<C, R, P>
	where
		C: PolkadotApi,
		R: TableRouter,
		P: Collators,
{
	type Error = Error;
	type Create = CreateProposal<C, R, P>;
	type Evaluate = Result<bool, Error>;

	fn propose(&self) -> CreateProposal<C, R, P> {
		const ATTEMPT_PROPOSE_EVERY: Duration = Duration::from_millis(100);

		let enough_candidates = self.dynamic_inclusion.acceptable_in(
			Instant::now(),
			self.table.includable_count(),
		).unwrap_or_default();

		CreateProposal {
			parent_hash: self.parent_hash.clone(),
			parent_number: self.parent_number.clone(),
			parent_id: self.parent_id.clone(),
			client: self.client.clone(),
			transaction_pool: self.transaction_pool.clone(),
			collation: CollationFetch::new(
				self.local_duty.validation,
				self.parent_hash.clone(),
				self.collators.clone(),
				self.client.clone()
			),
			dynamic_inclusion: self.dynamic_inclusion.clone(),
			table: self.table.clone(),
			router: self.router.clone(),
			timing: ProposalTiming {
				timer: self.timer.clone(),
				attempt_propose: self.timer.interval(ATTEMPT_PROPOSE_EVERY),
				enough_candidates: self.timer.sleep(enough_candidates),
			}
		}
	}

	// TODO: certain kinds of errors here should lead to a misbehavior report.
	fn evaluate(&self, proposal: &SubstrateBlock) -> Result<bool, Error> {
		debug!(target: "bft", "evaluating block on top of parent ({}, {:?})", self.parent_number, self.parent_hash);
		match evaluate_proposal(proposal, &*self.client, current_timestamp(), &self.parent_hash, &self.parent_id) {
			Ok(x) => Ok(x),
			Err(e) => match *e.kind() {
				ErrorKind::PolkadotApi(polkadot_api::ErrorKind::Executor(_)) => Ok(false),
				ErrorKind::ProposalNotForPolkadot => Ok(false),
				ErrorKind::TimestampInFuture => Ok(false),
				ErrorKind::WrongParentHash(_, _) => Ok(false),
				ErrorKind::ProposalTooLarge(_) => Ok(false),
				_ => Err(e),
			}
		}
	}

	fn round_proposer(&self, round_number: usize, authorities: &[AuthorityId]) -> AuthorityId {
		use primitives::uint::U256;

		let len: U256 = authorities.len().into();
		let offset = U256::from_big_endian(&self.random_seed.0) % len;
		let offset = offset.low_u64() as usize + round_number;

		authorities[offset % authorities.len()].clone()
	}

	fn import_misbehavior(&self, misbehavior: Vec<(AuthorityId, bft::Misbehavior)>) {
		use bft::generic::Misbehavior as GenericMisbehavior;
		use primitives::bft::{MisbehaviorKind, MisbehaviorReport};
		use polkadot_runtime::{Call, Extrinsic, UncheckedExtrinsic, ConsensusCall};

		let local_id = self.local_key.public().0;
		let mut pool = self.transaction_pool.lock();
		let mut next_index = {
			let readiness_evaluator = Ready::create(self.parent_id.clone(), &*self.client);

			let cur_index = pool.pending(readiness_evaluator)
				.filter(|tx| tx.as_ref().as_ref().signed == local_id)
				.last()
				.map(|tx| Ok(tx.as_ref().as_ref().index))
				.unwrap_or_else(|| self.client.index(&self.parent_id, local_id));

			match cur_index {
				Ok(cur_index) => cur_index + 1,
				Err(e) => {
					warn!(target: "consensus", "Error computing next transaction index: {}", e);
					return;
				}
			}
		};

		for (target, misbehavior) in misbehavior {
			let report = MisbehaviorReport {
				parent_hash: self.parent_hash,
				parent_number: self.parent_number,
				target,
				misbehavior: match misbehavior {
					GenericMisbehavior::ProposeOutOfTurn(_, _, _) => continue,
					GenericMisbehavior::DoublePropose(_, _, _) => continue,
					GenericMisbehavior::DoublePrepare(round, (h1, s1), (h2, s2))
						=> MisbehaviorKind::BftDoublePrepare(round as u32, (h1, s1.signature), (h2, s2.signature)),
					GenericMisbehavior::DoubleCommit(round, (h1, s1), (h2, s2))
						=> MisbehaviorKind::BftDoubleCommit(round as u32, (h1, s1.signature), (h2, s2.signature)),
				}
			};
			let extrinsic = Extrinsic {
				signed: local_id,
				index: next_index,
				function: Call::Consensus(ConsensusCall::report_misbehavior(report)),
			};

			next_index += 1;

			let signature = self.local_key.sign(&extrinsic.encode()).into();
			let uxt = UncheckedExtrinsic { extrinsic, signature };

			pool.import(uxt).expect("locally signed extrinsic is valid; qed");
		}
	}
}

fn current_timestamp() -> Timestamp {
	use std::time;

	time::SystemTime::now().duration_since(time::UNIX_EPOCH)
		.expect("now always later than unix epoch; qed")
		.as_secs()
}

struct ProposalTiming {
	timer: Timer,
	attempt_propose: Interval,
	enough_candidates: Sleep,
}

impl ProposalTiming {
	// whether it's time to attempt a proposal.
	// should only be called within the context of a task.
	fn attempt_propose(&mut self) -> Result<bool, TimerError> {
		match self.attempt_propose.poll()? {
			Async::Ready(x) => { x.expect("timer still alive; intervals never end; qed"); Ok(true) }
			Async::NotReady => Ok({
				match self.enough_candidates.poll()? {
					Async::Ready(()) => true,
					Async::NotReady => false,
				}
			})
		}
	}

	// schedule the time when enough candidates are ready.
	fn enough_candidates_at(&mut self, duration: Duration) {
		self.enough_candidates = self.timer.sleep(duration);
	}
}

/// Future which resolves upon the creation of a proposal.
pub struct CreateProposal<C: PolkadotApi, R, P: Collators>  {
	parent_hash: HeaderHash,
	parent_number: BlockNumber,
	parent_id: C::CheckedBlockId,
	client: Arc<C>,
	transaction_pool: Arc<Mutex<TransactionPool>>,
	dynamic_inclusion: DynamicInclusion,
	collation: CollationFetch<P, C>,
	router: R,
	table: Arc<SharedTable>,
	timing: ProposalTiming,
}

impl<C, R, P> CreateProposal<C, R, P>
	where
		C: PolkadotApi,
		R: TableRouter,
		P: Collators,
{
	fn propose_with(&self, _candidates: Vec<CandidateReceipt>) -> Result<SubstrateBlock, Error> {
		debug!(target: "bft", "proposing block on top of parent ({}, {:?})", self.parent_number, self.parent_hash);

		// TODO: handle case when current timestamp behind that in state.
		let mut block_builder = self.client.build_block(
			&self.parent_id,
			current_timestamp()
		)?;

		let readiness_evaluator = Ready::create(self.parent_id.clone(), &*self.client);

		{
			let mut pool = self.transaction_pool.lock();
			let mut unqueue_invalid = Vec::new();
			let mut pending_size = 0;
			for pending in pool.pending(readiness_evaluator.clone()) {
				// skip and cull transactions which are too large.
				if pending.encoded_size() > MAX_TRANSACTIONS_SIZE {
					unqueue_invalid.push(pending.hash().clone());
					continue
				}

				if pending_size + pending.encoded_size() >= MAX_TRANSACTIONS_SIZE { break }

				match block_builder.push_extrinsic(pending.as_transaction().clone()) {
					Ok(()) => {
						pending_size += pending.encoded_size();
					}
					Err(_) => {
						unqueue_invalid.push(pending.hash().clone());
					}
				}
			}

			for tx_hash in unqueue_invalid {
				pool.remove(&tx_hash, false);
			}
		}

		let polkadot_block = block_builder.bake();
		info!("Proposing block [number: {}; extrinsics: [{}], parent_hash: {}]", polkadot_block.header.number, polkadot_block.extrinsics.len(), polkadot_block.header.parent_hash);

		let substrate_block = Slicable::decode(&mut polkadot_block.encode().as_slice())
			.expect("polkadot blocks defined to serialize to substrate blocks correctly; qed");

		assert!(evaluate_proposal(&substrate_block, &*self.client, current_timestamp(), &self.parent_hash, &self.parent_id).is_ok());

		Ok(substrate_block)
	}
}

impl<C, R, P> Future for CreateProposal<C, R, P>
	where
		C: PolkadotApi,
		R: TableRouter,
		P: Collators,
{
	type Item = SubstrateBlock;
	type Error = Error;

	fn poll(&mut self) -> Poll<SubstrateBlock, Error> {
		// 1. poll local collation future.
		match self.collation.poll() {
			Ok(Async::Ready(collation)) => {
				let hash = collation.receipt.hash();
				self.router.local_candidate_data(hash, collation.block_data, collation.extrinsic);
				self.table.sign_and_import(&self.router, GenericStatement::Valid(hash));
			}
			Ok(Async::NotReady) => {},
			Err(_) => {}, // TODO: handle this failure to collate.
		}

		// 2. try to propose if our interval or previous timer has gone off.
		let proposal = if self.timing.attempt_propose()? {
			let included = self.table.includable_count();
			match self.dynamic_inclusion.acceptable_in(Instant::now(), included) {
				Some(sleep_for) => {
					self.timing.enough_candidates_at(sleep_for);
					None
				}
				None => {
					self.table.with_proposal(|proposed_set| {
							Some(proposed_set.into_iter().cloned().collect())
					})
				}
			}
		} else {
			None
		};

		Ok(match proposal {
			Some(p) => Async::Ready(self.propose_with(p)?),
			None => Async::NotReady,
		})
	}
}

fn evaluate_proposal<C: PolkadotApi>(
	proposal: &SubstrateBlock,
	client: &C,
	now: Timestamp,
	parent_hash: &HeaderHash,
	parent_id: &C::CheckedBlockId,
) -> Result<bool, Error> {
	const MAX_TIMESTAMP_DRIFT: Timestamp = 4;

	let encoded = Slicable::encode(proposal);
	let proposal = PolkadotGenericBlock::decode(&mut &encoded[..])
		.and_then(|b| PolkadotBlock::from(b).ok())
		.ok_or_else(|| ErrorKind::ProposalNotForPolkadot)?;

	let transactions_size = proposal.extrinsics.iter().fold(0, |a, tx| {
		a + Slicable::encode(tx).len()
	});

	if transactions_size > MAX_TRANSACTIONS_SIZE {
		bail!(ErrorKind::ProposalTooLarge(transactions_size))
	}

	if proposal.header.parent_hash != *parent_hash {
		bail!(ErrorKind::WrongParentHash(*parent_hash, proposal.header.parent_hash));
	}

	// no need to check number because
	// a) we assume the parent is valid.
	// b) the runtime checks that `proposal.parent_hash` == `block_hash(proposal.number - 1)`

	let block_timestamp = proposal.timestamp();

	// TODO: just defer using `tokio_timer` to delay prepare vote.
	if block_timestamp > now + MAX_TIMESTAMP_DRIFT {
		bail!(ErrorKind::TimestampInFuture)
	}

	// execute the block.
	client.evaluate_block(parent_id, proposal.into())?;
	Ok(true)
}