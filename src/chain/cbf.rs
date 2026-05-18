// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bdk_chain::indexer::keychain_txout::KeychainTxOutIndex;
use bdk_wallet::KeychainKind;
use bip157::chain::{BlockHeaderChanges, ChainState};
use bip157::error::FetchBlockError;
use bip157::{
	BlockHash, Builder, Client, Event, HashCheckpoint, Info, Node as CbfNode, Requester,
	TrustedPeer, Warning,
};
use bitcoin::constants::SUBSIDY_HALVING_INTERVAL;
use bitcoin::{Amount, FeeRate, Network, Script, ScriptBuf, Transaction, Txid};
use electrum_client::ElectrumApi;
use lightning::chain::{Listen, WatchedOutput};
use lightning::util::ser::Writeable;
use tokio::sync::mpsc;

use super::{FeeSourceConfig, WalletSyncStatus};
use crate::config::{CbfSyncConfig, Config};
use crate::error::Error;
use crate::fee_estimator::{
	apply_post_estimation_adjustments, get_all_conf_targets, get_num_block_defaults_for_target,
	OnchainFeeEstimator,
};
use crate::io::utils::update_and_persist_node_metrics;
use crate::logger::{log_bytes, log_debug, log_error, log_info, log_trace, LdkLogger, Logger};
use crate::runtime::Runtime;
use crate::types::{ChainMonitor, ChannelManager, DynStore, Sweeper, Wallet};
use crate::NodeMetrics;

/// Minimum fee rate: 1 sat/vB = 250 sat/kWU. Used as a floor for computed fee rates.
const MIN_FEERATE_SAT_PER_KWU: u64 = 250;

/// Number of recent blocks to look back for per-target fee rate estimation.
const FEE_RATE_LOOKBACK_BLOCKS: usize = 6;

/// Capacity of the per-block fee-rate cache. Sized at 2× the lookback so a tip
/// advance of up to `FEE_RATE_LOOKBACK_BLOCKS` only ever incurs that many
/// fresh `get_block` round trips, regardless of how many cycles ran before.
const BLOCK_FEE_CACHE_CAPACITY: usize = FEE_RATE_LOOKBACK_BLOCKS * 2;

/// Number of blocks to walk back from a component's persisted best block height
/// for reorg safety when computing the incremental scan skip height.
/// Matches bdk-kyoto's `IMPOSSIBLE_REORG_DEPTH`.
const REORG_SAFETY_BLOCKS: u32 = 7;

/// Maximum consecutive restart attempts before giving up.
const MAX_RESTART_RETRIES: u32 = 5;

/// Initial backoff delay for restart retries (doubles each attempt).
const INITIAL_BACKOFF_MS: u64 = 500;

/// The fee estimation back-end used by the CBF chain source.
enum FeeSource {
	/// Derive fee rates from the coinbase reward of recent blocks.
	///
	/// Provides a per-target rate using percentile selection across multiple blocks.
	/// Less accurate than a mempool-aware source but requires no extra connectivity.
	Cbf,
	/// Delegate fee estimation to an Esplora HTTP server.
	Esplora { client: esplora_client::AsyncClient },
	/// Delegate fee estimation to an Electrum server.
	///
	/// A fresh connection is opened for each estimation cycle because `ElectrumClient`
	/// is not `Sync`.
	Electrum { server_url: String },
}

pub(super) struct CbfChainSource {
	/// Peer addresses for sourcing compact block filters via P2P.
	peers: Vec<String>,
	/// User-provided sync configuration (timeouts, background sync intervals).
	pub(super) sync_config: CbfSyncConfig,
	/// Fee estimation back-end.
	fee_source: FeeSource,
	/// Tracks whether the bip157 node is running and holds the command handle.
	cbf_runtime_status: Arc<Mutex<CbfRuntimeStatus>>,
	/// Stable sender into which `start()` forwards every kyoto `Event`, regardless of
	/// how many times the kyoto node has been rebuilt by the restart loop.
	event_tx: Arc<mpsc::UnboundedSender<Event>>,
	/// Paired receiver, taken by `continuously_sync_wallets` on first call.
	event_rx: Mutex<Option<mpsc::UnboundedReceiver<Event>>>,
	/// Scripts registered by LDK's Filter trait for lightning channel monitoring.
	registered_scripts: Mutex<HashSet<ScriptBuf>>,
	/// Deduplicates concurrent `sync_wallets` callers in the push-native sync model.
	/// First caller starts the wait; subsequent callers piggyback on the same result.
	wallet_polling_status: Mutex<WalletSyncStatus>,
	/// Fired by the kyoto event loop after each `FiltersSynced`, so `sync_wallets`
	/// can re-check listener tips against the wait target.
	sync_progress_notify: Arc<tokio::sync::Notify>,
	/// Shared fee rate estimator, updated by this chain source.
	fee_estimator: Arc<OnchainFeeEstimator>,
	/// Cache of per-block fee rates so that, when the tip advances by N blocks,
	/// the next refresh fetches only N new blocks rather than the full lookback.
	/// FIFO bounded by [`BLOCK_FEE_CACHE_CAPACITY`]; eviction follows insertion order,
	/// which matches the tip-backward walk pattern.
	block_fee_cache: Mutex<VecDeque<(BlockHash, FeeRate)>>,
	/// Persistent key-value store for node metrics.
	kv_store: Arc<DynStore>,
	/// Node configuration (network, storage path, etc.).
	config: Arc<Config>,
	/// Logger instance.
	logger: Arc<Logger>,
	/// Shared node metrics (sync timestamps, etc.).
	node_metrics: Arc<RwLock<NodeMetrics>>,
}

enum CbfRuntimeStatus {
	Started { requester: Requester },
	Stopped,
}

/// Fan-out target for `Listen` callbacks driven by the kyoto event loop.
/// Mirrors the bitcoind chain source's `ChainListener`.
pub(crate) struct ChainListener {
	pub(crate) onchain_wallet: Arc<Wallet>,
	pub(crate) channel_manager: Arc<ChannelManager>,
	pub(crate) chain_monitor: Arc<ChainMonitor>,
	pub(crate) output_sweeper: Arc<Sweeper>,
}

impl Listen for ChainListener {
	fn filtered_block_connected(
		&self, header: &bitcoin::block::Header,
		txdata: &lightning::chain::transaction::TransactionData, height: u32,
	) {
		self.onchain_wallet.filtered_block_connected(header, txdata, height);
		self.channel_manager.filtered_block_connected(header, txdata, height);
		self.chain_monitor.filtered_block_connected(header, txdata, height);
		self.output_sweeper.filtered_block_connected(header, txdata, height);
	}

	fn block_connected(&self, block: &bitcoin::Block, height: u32) {
		self.onchain_wallet.block_connected(block, height);
		self.channel_manager.block_connected(block, height);
		self.chain_monitor.block_connected(block, height);
		self.output_sweeper.block_connected(block, height);
	}

	fn blocks_disconnected(&self, fork_point_block: lightning::chain::BestBlock) {
		self.onchain_wallet.blocks_disconnected(fork_point_block);
		self.channel_manager.blocks_disconnected(fork_point_block);
		self.chain_monitor.blocks_disconnected(fork_point_block);
		self.output_sweeper.blocks_disconnected(fork_point_block);
	}
}

impl CbfChainSource {
	pub(crate) fn new(
		peers: Vec<String>, sync_config: CbfSyncConfig, fee_source_config: Option<FeeSourceConfig>,
		fee_estimator: Arc<OnchainFeeEstimator>, kv_store: Arc<DynStore>, config: Arc<Config>,
		logger: Arc<Logger>, node_metrics: Arc<RwLock<NodeMetrics>>,
	) -> Result<Self, Error> {
		let fee_source = match fee_source_config {
			Some(FeeSourceConfig::Esplora(server_url)) => {
				let timeout = sync_config.timeouts_config.per_request_timeout_secs;
				let mut builder = esplora_client::Builder::new(&server_url);
				builder = builder.timeout(timeout as u64);
				let client = builder.build_async().map_err(|e| {
					log_error!(logger, "Failed to build esplora client: {}", e);
					Error::ConnectionFailed
				})?;
				FeeSource::Esplora { client }
			},
			Some(FeeSourceConfig::Electrum(server_url)) => FeeSource::Electrum { server_url },
			None => FeeSource::Cbf,
		};

		let cbf_runtime_status = Arc::new(Mutex::new(CbfRuntimeStatus::Stopped));
		let (event_tx, event_rx) = mpsc::unbounded_channel();
		let event_tx = Arc::new(event_tx);
		let event_rx = Mutex::new(Some(event_rx));
		let registered_scripts = Mutex::new(HashSet::new());
		let wallet_polling_status = Mutex::new(WalletSyncStatus::Completed);
		let sync_progress_notify = Arc::new(tokio::sync::Notify::new());
		let block_fee_cache = Mutex::new(VecDeque::with_capacity(BLOCK_FEE_CACHE_CAPACITY));
		Ok(Self {
			peers,
			sync_config,
			fee_source,
			cbf_runtime_status,
			event_tx,
			event_rx,
			registered_scripts,
			wallet_polling_status,
			sync_progress_notify,
			fee_estimator,
			block_fee_cache,
			kv_store,
			config,
			logger,
			node_metrics,
		})
	}

	/// Build a new bip157 node and client from the current configuration.
	///
	/// Takes all required parameters explicitly so it can be called from an
	/// `async move` block without borrowing `self`.
	fn build_cbf_node(
		peers: &[String], sync_config: &CbfSyncConfig, config: &Config,
		wallet: Option<&Arc<Wallet>>, logger: &Logger,
	) -> (CbfNode, Client) {
		let network = config.network;

		let mut builder = Builder::new(network);

		// Configure data directory under the node's storage path.
		let data_dir = std::path::PathBuf::from(&config.storage_dir_path).join("bip157_data");
		builder = builder.data_dir(data_dir);

		// Add configured peers.
		let trusted_peers: Vec<TrustedPeer> = peers
			.iter()
			.filter_map(|peer_str| {
				peer_str.parse::<SocketAddr>().ok().map(TrustedPeer::from_socket_addr)
			})
			.collect();
		if !trusted_peers.is_empty() {
			builder = builder.add_peers(trusted_peers);
		}

		// Require multiple peers to agree on filter headers before accepting them,
		// as recommended by BIP 157 to mitigate malicious peer attacks.
		builder = builder.required_peers(sync_config.required_peers);

		// Request witness data so segwit transactions include full witnesses,
		// required for Lightning channel operations.
		builder = builder.fetch_witness_data();

		// Set peer response timeout from user configuration (default: 30s).
		builder = builder.response_timeout(Duration::from_secs(sync_config.response_timeout_secs));

		// If we have a wallet reference, derive a chain_state checkpoint so the
		// bip157 node can skip already-synced headers on restart.
		if let Some(wallet) = wallet {
			let cp = wallet.latest_checkpoint();
			let target_height = cp.height().saturating_sub(REORG_SAFETY_BLOCKS);
			// Walk the checkpoint chain back to the target height.
			let mut cursor = cp;
			while cursor.height() > target_height {
				match cursor.prev() {
					Some(prev) => cursor = prev,
					None => break,
				}
			}
			if cursor.height() > 0 {
				let header_cp = HashCheckpoint::new(cursor.height(), cursor.hash());
				builder = builder.chain_state(ChainState::Checkpoint(header_cp));
				log_debug!(
					logger,
					"CBF builder: resuming from checkpoint height={}, hash={}",
					cursor.height(),
					cursor.hash(),
				);
			}
		}

		builder.build()
	}

	/// Start the bip157 node and spawn background tasks for event processing.
	///
	/// The node runs inside a restart loop: if `node.run()` returns an error,
	/// the loop rebuilds the node, swaps the requester, and respawns channel
	/// processing tasks — up to [`MAX_RESTART_RETRIES`] consecutive failures
	/// with exponential backoff starting at [`INITIAL_BACKOFF_MS`].
	pub(crate) fn start(&self, runtime: Arc<Runtime>, onchain_wallet: Arc<Wallet>) {
		let mut status = self.cbf_runtime_status.lock().expect("lock");
		if matches!(*status, CbfRuntimeStatus::Started { .. }) {
			debug_assert!(false, "We shouldn't call start if we're already started");
			return;
		}

		let (node, client) = Self::build_cbf_node(
			&self.peers,
			&self.sync_config,
			&self.config,
			Some(&onchain_wallet),
			&self.logger,
		);

		let Client { requester, info_rx, warn_rx, event_rx } = client;

		*status = CbfRuntimeStatus::Started { requester };
		drop(status);

		log_info!(self.logger, "CBF chain source started.");

		// Clone all Arc references needed by the restart loop so the async
		// block is 'static (no borrows of `self`).
		let restart_status = Arc::clone(&self.cbf_runtime_status);
		let restart_logger = Arc::clone(&self.logger);
		let restart_event_tx = Arc::clone(&self.event_tx);
		let restart_peers = self.peers.clone();
		let restart_sync_config = self.sync_config.clone();
		let restart_config = Arc::clone(&self.config);
		let restart_wallet = Arc::clone(&onchain_wallet);

		runtime.spawn_background_task(async move {
			let mut current_node = node;
			let mut current_info_rx = info_rx;
			let mut current_warn_rx = warn_rx;
			let mut current_event_rx = event_rx;
			let mut retries = 0u32;
			let mut backoff_ms = INITIAL_BACKOFF_MS;

			loop {
				// Spawn channel processing tasks for this iteration.
				let info_handle = tokio::spawn(Self::process_info_messages(
					current_info_rx,
					Arc::clone(&restart_logger),
				));
				let warn_handle = tokio::spawn(Self::process_warn_messages(
					current_warn_rx,
					Arc::clone(&restart_logger),
				));
				// Forward every kyoto event into the stable channel consumed by
				// `continuously_sync_wallets`. On restart, we abort this task and
				// spawn a fresh forwarder for the new event_rx — the stable channel
				// at the other end is unaffected.
				let forward_event_tx = Arc::clone(&restart_event_tx);
				let event_handle = tokio::spawn(async move {
					while let Some(event) = current_event_rx.recv().await {
						if forward_event_tx.send(event).is_err() {
							break;
						}
					}
				});

				// Run the node until it exits.
				match current_node.run().await {
					Ok(()) => {
						log_info!(restart_logger, "CBF node shut down cleanly.");
						break;
					},
					Err(e) => {
						retries += 1;
						if retries > MAX_RESTART_RETRIES {
							log_error!(
								restart_logger,
								"CBF node failed {} times, giving up: {:?}",
								retries,
								e,
							);
							*restart_status.lock().expect("lock") = CbfRuntimeStatus::Stopped;
							break;
						}
						log_error!(
							restart_logger,
							"CBF node exited with error (attempt {}/{}): {:?}. \
							 Restarting in {}ms.",
							retries,
							MAX_RESTART_RETRIES,
							e,
							backoff_ms,
						);

						tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
						backoff_ms = backoff_ms.saturating_mul(2);

						// Abort old channel processing tasks.
						info_handle.abort();
						warn_handle.abort();
						event_handle.abort();

						// Rebuild the node from scratch.
						let (new_node, new_client) = Self::build_cbf_node(
							&restart_peers,
							&restart_sync_config,
							&restart_config,
							Some(&restart_wallet),
							&restart_logger,
						);
						let Client {
							requester: new_requester,
							info_rx: new_info_rx,
							warn_rx: new_warn_rx,
							event_rx: new_event_rx,
						} = new_client;

						// Publish the new requester only if stop() did not fire during the
						// backoff sleep. Otherwise the rebuilt node would outlive stop().
						{
							let mut status = restart_status.lock().expect("lock");
							if matches!(*status, CbfRuntimeStatus::Stopped) {
								let _ = new_requester.shutdown();
								log_info!(
									restart_logger,
									"CBF restart aborted: stop() called during backoff."
								);
								break;
							}
							*status = CbfRuntimeStatus::Started { requester: new_requester };
						}

						current_node = new_node;
						current_info_rx = new_info_rx;
						current_warn_rx = new_warn_rx;
						current_event_rx = new_event_rx;
					},
				}
			}
		});
	}

	/// Shut down the bip157 node and stop all background tasks.
	pub(crate) fn stop(&self) {
		let mut status = self.cbf_runtime_status.lock().expect("lock");
		match &*status {
			CbfRuntimeStatus::Started { requester } => {
				let _ = requester.shutdown();
				log_info!(self.logger, "CBF chain source stopped.");
			},
			CbfRuntimeStatus::Stopped => {},
		}
		*status = CbfRuntimeStatus::Stopped;
	}

	pub(super) async fn continuously_sync_wallets(
		&self, mut stop_sync_receiver: tokio::sync::watch::Receiver<()>,
		onchain_wallet: Arc<Wallet>, channel_manager: Arc<ChannelManager>,
		chain_monitor: Arc<ChainMonitor>, output_sweeper: Arc<Sweeper>,
	) {
		let listener = ChainListener {
			onchain_wallet,
			channel_manager: Arc::clone(&channel_manager),
			chain_monitor,
			output_sweeper,
		};

		let mut event_rx = match self.event_rx.lock().expect("lock").take() {
			Some(rx) => rx,
			None => {
				debug_assert!(false, "continuously_sync_wallets called concurrently");
				log_error!(self.logger, "CBF event receiver already taken — sync loop will not run.");
				return;
			},
		};

		// Set up an optional periodic fee-rate update. With `background_sync_config: None`
		// (manual-sync-only mode used by the test suite), we skip the periodic ticker —
		// `Node::sync_wallets` triggers `update_fee_rate_estimates` on demand instead.
		// When configured, the interval matches the user's setting (minimum 10s to avoid
		// hammering kyoto's block_queue: each refresh fetches `FEE_RATE_LOOKBACK_BLOCKS`
		// blocks over P2P via `requester.average_fee_rate`).
		let mut fee_rate_update_interval =
			self.sync_config.background_sync_config.as_ref().map(|cfg| {
				let secs = cfg.fee_rate_cache_update_interval_secs.max(10);
				let mut i = tokio::time::interval(Duration::from_secs(secs));
				i.reset();
				i.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
				i
			});
		let mut last_fee_update_tip = None;

		log_info!(self.logger, "Starting CBF event-driven sync loop.");

		loop {
			tokio::select! {
				biased;
				_ = stop_sync_receiver.changed() => {
					log_trace!(self.logger, "Stopping CBF sync loop.");
					break;
				}
				event = event_rx.recv() => {
					match event {
						Some(event) => self.dispatch_event(event, &listener).await,
						None => {
							log_error!(self.logger, "CBF event stream closed; exiting sync loop.");
							break;
						},
					}
				}
				_ = async {
					match fee_rate_update_interval.as_mut() {
						Some(interval) => { interval.tick().await; },
						None => std::future::pending::<()>().await,
					}
				} => {
					let current_tip = channel_manager.current_best_block().block_hash;
					if last_fee_update_tip != Some(current_tip) {
						if self.update_fee_rate_estimates().await.is_ok() {
							last_fee_update_tip = Some(current_tip);
						}
					}
				}
			}
		}

		// Restore the receiver so that a subsequent `continuously_sync_wallets` call on
		// the same `CbfChainSource` (e.g. `Node::start()` after `Node::stop()`) can pick
		// up where we left off rather than bailing out on a `None` receiver.
		*self.event_rx.lock().expect("lock") = Some(event_rx);
	}

	/// Apply a single kyoto event to the listener fan-out.
	async fn dispatch_event(&self, event: Event, listener: &ChainListener) {
		match event {
			Event::IndexedFilter(filter) => {
				let height = filter.height();
				let block_hash = filter.block_hash();

				let scripts = self.combined_scripts(&listener.onchain_wallet);
				let matches = !scripts.is_empty() && filter.contains_any(scripts.iter());

				let requester = match self.requester() {
					Ok(r) => r,
					Err(_) => return,
				};
				let per_request_timeout = Duration::from_secs(
					self.sync_config.timeouts_config.per_request_timeout_secs.into(),
				);

				if matches {
					let block = match tokio::time::timeout(
						per_request_timeout,
						requester.get_block(block_hash),
					)
					.await
					{
						Ok(Ok(indexed_block)) => indexed_block.block,
						Ok(Err(e)) => {
							log_error!(
								self.logger,
								"CBF: failed to fetch matched block {}: {:?}",
								block_hash,
								e
							);
							return;
						},
						Err(_) => {
							log_error!(
								self.logger,
								"CBF: timed out fetching matched block {}",
								block_hash
							);
							return;
						},
					};
					let txdata: Vec<(usize, &Transaction)> =
						block.txdata.iter().enumerate().collect();
					listener.filtered_block_connected(&block.header, &txdata, height);
					log_trace!(
						self.logger,
						"CBF: applied matched block at height {}",
						height
					);
				} else {
					let header = match requester.get_header(height).await {
						Ok(Some(indexed_header)) => indexed_header.header,
						Ok(None) => {
							log_error!(
								self.logger,
								"CBF: header not found in local chain for height {}",
								height
							);
							return;
						},
						Err(e) => {
							log_error!(
								self.logger,
								"CBF: failed to look up header at height {}: {:?}",
								height,
								e
							);
							return;
						},
					};
					listener.filtered_block_connected(&header, &[], height);
				}
			},
			Event::ChainUpdate(BlockHeaderChanges::Reorganized { accepted, reorganized }) => {
				// Kyoto sorts `reorganized` ascending by height, so `first()` is the
				// lowest reorganized block and the fork point is one below it.
				if let Some(first_reorg) = reorganized.first() {
					let fork_point = lightning::chain::BestBlock::new(
						first_reorg.header.prev_blockhash,
						first_reorg.height.saturating_sub(1),
					);
					log_debug!(
						self.logger,
						"CBF reorg: rolling listeners back to fork point at height {} ({} reorganized, {} accepted)",
						fork_point.height,
						reorganized.len(),
						accepted.len(),
					);
					listener.blocks_disconnected(fork_point);
					// The `accepted` headers will arrive as subsequent IndexedFilter
					// events; `dispatch_event` will re-extend the chain via the
					// matched / non-matched paths.
				} else {
					debug_assert!(false, "Reorganized event with empty `reorganized` list");
				}
			},
			Event::ChainUpdate(BlockHeaderChanges::Connected(header)) => {
				log_trace!(self.logger, "CBF block connected at height {}", header.height);
			},
			Event::ChainUpdate(BlockHeaderChanges::ForkAdded(header)) => {
				log_trace!(self.logger, "CBF fork observed at height {}", header.height);
			},
			Event::FiltersSynced(sync_update) => {
				let tip = sync_update.tip();
				log_info!(
					self.logger,
					"CBF filters synced to tip: height={}, hash={}",
					tip.height,
					tip.hash,
				);
				let unix_time_secs_opt =
					SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
				update_and_persist_node_metrics(
					&self.node_metrics,
					&*self.kv_store,
					&*self.logger,
					|m| {
						m.latest_onchain_wallet_sync_timestamp = unix_time_secs_opt;
						m.latest_lightning_wallet_sync_timestamp = unix_time_secs_opt;
					},
				)
				.unwrap_or_else(|e| {
					log_error!(self.logger, "Failed to persist node metrics: {}", e);
				});
				self.sync_progress_notify.notify_waiters();
			},
		}
	}

	/// Build the union of LDK-registered scripts and BDK keychain scripts to match
	/// each incoming filter against.
	fn combined_scripts(&self, onchain_wallet: &Wallet) -> Vec<ScriptBuf> {
		let mut scripts: Vec<ScriptBuf> = peek_keychain_scripts(&onchain_wallet.spk_index_clone());
		scripts.extend(self.registered_scripts.lock().expect("lock").iter().cloned());
		scripts
	}

	async fn process_info_messages(mut info_rx: mpsc::Receiver<Info>, logger: Arc<Logger>) {
		while let Some(info) = info_rx.recv().await {
			log_debug!(logger, "CBF node info: {}", info);
		}
	}

	async fn process_warn_messages(
		mut warn_rx: mpsc::UnboundedReceiver<Warning>, logger: Arc<Logger>,
	) {
		while let Some(warning) = warn_rx.recv().await {
			log_debug!(logger, "CBF node warning: {}", warning);
		}
	}

	fn requester(&self) -> Result<Requester, Error> {
		let status = self.cbf_runtime_status.lock().expect("lock");
		match &*status {
			CbfRuntimeStatus::Started { requester } if requester.is_running() => {
				Ok(requester.clone())
			},
			CbfRuntimeStatus::Started { .. } => {
				log_error!(
					self.logger,
					"CBF node is not running; sync will fail until restart completes."
				);
				Err(Error::ConnectionFailed)
			},
			CbfRuntimeStatus::Stopped => {
				debug_assert!(
					false,
					"We should have started the chain source before using the requester"
				);
				Err(Error::ConnectionFailed)
			},
		}
	}

	/// Register a transaction script for Lightning channel monitoring.
	pub(crate) fn register_tx(&self, _txid: &Txid, script_pubkey: &Script) {
		self.registered_scripts.lock().expect("lock").insert(script_pubkey.to_owned());
	}

	/// Register a watched output script for Lightning channel monitoring.
	pub(crate) fn register_output(&self, output: WatchedOutput) {
		self.registered_scripts.lock().expect("lock").insert(output.script_pubkey.clone());
	}

    ///This function is an artefact of the public contract. With CBF push model (kyoto receives
    ///block => propagates updates) we just need to be sure that we have processes all blocks up to
    ///kyoto's tip, we have no other way to sync.
	pub(crate) async fn sync_wallets(
		&self, onchain_wallet: Arc<Wallet>, channel_manager: Arc<ChannelManager>,
	) -> Result<(), Error> {
		let receiver_res = {
			let mut status_lock = self.wallet_polling_status.lock().expect("lock");
			status_lock.register_or_subscribe_pending_sync()
		};
		if let Some(mut sync_receiver) = receiver_res {
			log_debug!(self.logger, "CBF wallet sync already in progress, waiting.");
			return sync_receiver.recv().await.map_err(|e| {
				debug_assert!(false, "Failed to receive wallet sync result: {:?}", e);
				log_error!(self.logger, "Failed to receive wallet sync result: {:?}", e);
				Error::WalletOperationFailed
			})?;
		}

		let res = async {
			let requester = self.requester()?;
			let now = Instant::now();

			// Snapshot the current network tip; we'll wait until the event loop has driven
			// both listeners to at least this height.
			let target = requester.chain_tip().await.map_err(|e| {
				log_error!(self.logger, "Failed to fetch CBF chain tip: {:?}", e);
				Error::WalletOperationFailed
			})?;
			let target_height = target.height;

			let timeout = Duration::from_secs(
				self.sync_config.timeouts_config.onchain_wallet_sync_timeout_secs,
			);
			let notify = Arc::clone(&self.sync_progress_notify);
			let wait = async {
				loop {
					// Arm the notify *before* checking the predicate to avoid missing a
					// wakeup that fires between the check and the await.
					let notified = notify.notified();
					tokio::pin!(notified);

					let bdk_height = onchain_wallet.latest_checkpoint().height();
					let ldk_height = channel_manager.current_best_block().height;
					if bdk_height >= target_height && ldk_height >= target_height {
						return Ok::<(), Error>(());
					}
					notified.await;
				}
			};

			match tokio::time::timeout(timeout, wait).await {
				Ok(res) => res?,
				Err(_) => {
					log_error!(
						self.logger,
						"Sync of CBF wallets timed out waiting for tip {} (BDK at {}, LDK at {})",
						target_height,
						onchain_wallet.latest_checkpoint().height(),
						channel_manager.current_best_block().height,
					);
					return Err(Error::WalletOperationTimeout);
				},
			}

			log_debug!(
				self.logger,
				"Sync of CBF wallets caught up to height {} in {}ms.",
				target_height,
				now.elapsed().as_millis()
			);

			// Stamp both wallet timestamps on every successful sync so observers (notably
			// `wait_for_cbf_sync` in tests) see progress even when nothing changed and
			// `FiltersSynced` didn't fire during this call.
			let unix_time_secs_opt =
				SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
			update_and_persist_node_metrics(
				&self.node_metrics,
				&*self.kv_store,
				&*self.logger,
				|m| {
					m.latest_onchain_wallet_sync_timestamp = unix_time_secs_opt;
					m.latest_lightning_wallet_sync_timestamp = unix_time_secs_opt;
				},
			)?;
			Ok(())
		}
		.await;

		self.wallet_polling_status.lock().expect("lock").propagate_result_to_subscribers(res);

		res
	}

	pub(crate) async fn update_fee_rate_estimates(&self) -> Result<(), Error> {
		let new_fee_rate_cache = match &self.fee_source {
			FeeSource::Cbf => self.fee_rate_cache_from_cbf().await?,
			FeeSource::Esplora { client } => Some(self.fee_rate_cache_from_esplora(client).await?),
			FeeSource::Electrum { server_url } => {
				Some(self.fee_rate_cache_from_electrum(server_url).await?)
			},
		};

		let Some(new_fee_rate_cache) = new_fee_rate_cache else {
			return Ok(());
		};

		self.fee_estimator.set_fee_rate_cache(new_fee_rate_cache);

		update_node_metrics_timestamp(
			&self.node_metrics,
			&*self.kv_store,
			&*self.logger,
			|m, t| {
				m.latest_fee_rate_cache_update_timestamp = t;
			},
		)?;

		Ok(())
	}

	/// Derive per-target fee rates from recent blocks' coinbase outputs.
	///
	/// Returns `Ok(None)` when the chain is too short to sample `FEE_RATE_LOOKBACK_BLOCKS`
	/// blocks (e.g. kyoto has not yet synced past the genesis region).
	async fn fee_rate_cache_from_cbf(
		&self,
	) -> Result<Option<HashMap<crate::fee_estimator::ConfirmationTarget, FeeRate>>, Error> {
		let requester = self.requester()?;

		let timeout = Duration::from_secs(
			self.sync_config.timeouts_config.fee_rate_cache_update_timeout_secs,
		);
		let fetch_start = Instant::now();

		// Ask kyoto for its current chain tip rather than maintaining a mirrored
		// cache: the returned hash is always fresh (post-reorg, post-restart),
		// so no defensive invalidation is needed below.
		let tip = match tokio::time::timeout(timeout, requester.chain_tip()).await {
			Ok(Ok(tip)) => tip,
			Ok(Err(e)) => {
				log_debug!(
					self.logger,
					"Failed to fetch CBF chain tip for fee estimation: {:?}",
					e,
				);
				return Ok(None);
			},
			Err(e) => {
				log_error!(self.logger, "Timed out fetching CBF chain tip: {}", e);
				return Err(Error::FeerateEstimationUpdateTimeout);
			},
		};

		if (tip.height as usize) < FEE_RATE_LOOKBACK_BLOCKS {
			log_debug!(
				self.logger,
				"CBF chain tip at height {} is below the {}-block lookback window, \
				 skipping fee estimation.",
				tip.height,
				FEE_RATE_LOOKBACK_BLOCKS,
			);
			return Ok(None);
		}

		let now = Instant::now();

		// Sample the last N blocks for per-target estimation. We walk by height
		// (decrementing a counter) rather than by `prev_blockhash` so that cache
		// hits don't have to read any data out of the cached block — the hash for
		// the next height comes from kyoto's local header chain via `get_header`.
		let mut block_fee_rates: Vec<FeeRate> = Vec::with_capacity(FEE_RATE_LOOKBACK_BLOCKS);
		let mut cache_hits = 0usize;

		for offset in 0..FEE_RATE_LOOKBACK_BLOCKS {
			let Some(height) = tip.height.checked_sub(offset as u32) else { break };

			// Map height → hash via kyoto's local header chain (no P2P round trip).
			let current_hash = match requester.get_header(height).await {
				Ok(Some(indexed_header)) => indexed_header.header.block_hash(),
				Ok(None) => {
					log_debug!(
						self.logger,
						"CBF header at height {} not yet in local chain; \
						 skipping fee estimation cycle.",
						height,
					);
					return Ok(None);
				},
				Err(e) => {
					log_error!(
						self.logger,
						"Failed to look up header at height {}: {:?}",
						height,
						e
					);
					return Err(Error::FeerateEstimationUpdateFailed);
				},
			};

			// Cache lookup: linear scan over a small ring buffer (≤ BLOCK_FEE_CACHE_CAPACITY).
			let cached = self.block_fee_cache.lock().expect("lock").iter().find_map(|(h, r)| {
				if *h == current_hash {
					Some(*r)
				} else {
					None
				}
			});
			if let Some(fee_rate) = cached {
				cache_hits += 1;
				block_fee_rates.push(fee_rate);
				continue;
			}

			// Cache miss: fetch the full block over P2P and compute the fee rate.
			let remaining_timeout = timeout.saturating_sub(fetch_start.elapsed());
			if remaining_timeout.is_zero() {
				log_error!(self.logger, "Updating fee rate estimates timed out.");
				return Err(Error::FeerateEstimationUpdateTimeout);
			}

			let indexed_block =
				match tokio::time::timeout(remaining_timeout, requester.get_block(current_hash))
					.await
				{
					Ok(Ok(indexed_block)) => indexed_block,
					Ok(Err(FetchBlockError::UnknownHash)) => {
						// Kyoto doesn't know this block yet (e.g. startup before
						// filter sync, or hash is at/below the resume checkpoint).
						// Skip this cycle and try again later.
						log_debug!(
							self.logger,
							"CBF node does not yet have block {} for fee estimation; \
							 skipping until sync progresses.",
							current_hash,
						);
						return Ok(None);
					},
					Ok(Err(e)) => {
						log_error!(
							self.logger,
							"Failed to fetch block for fee estimation: {:?}",
							e
						);
						return Err(Error::FeerateEstimationUpdateFailed);
					},
					Err(e) => {
						log_error!(self.logger, "Updating fee rate estimates timed out: {}", e);
						return Err(Error::FeerateEstimationUpdateTimeout);
					},
				};

			let block = &indexed_block.block;
			let weight_kwu = block.weight().to_kwu_floor();

			// Compute fee rate: (coinbase_output - subsidy) / weight.
			// For blocks with zero weight (e.g. coinbase-only in regtest), use the floor rate.
			let fee_rate_sat_per_kwu = if weight_kwu == 0 {
				MIN_FEERATE_SAT_PER_KWU
			} else {
				let subsidy = block_subsidy(height);
				let revenue = block
					.txdata
					.first()
					.map(|tx| tx.output.iter().map(|o| o.value).sum())
					.unwrap_or(Amount::ZERO);
				let block_fees = revenue.checked_sub(subsidy).unwrap_or(Amount::ZERO);

				if block_fees == Amount::ZERO && self.config.network == Network::Bitcoin {
					log_error!(
						self.logger,
						"Failed to retrieve fee rate estimates: zero block fees are disallowed on Mainnet.",
					);
					return Err(Error::FeerateEstimationUpdateFailed);
				}

				(block_fees.to_sat() / weight_kwu).max(MIN_FEERATE_SAT_PER_KWU)
			};

			let fee_rate = FeeRate::from_sat_per_kwu(fee_rate_sat_per_kwu);

			// Insert into the cache, evicting the oldest entry if at capacity.
			{
				let mut cache = self.block_fee_cache.lock().expect("lock");
				if cache.len() == BLOCK_FEE_CACHE_CAPACITY {
					cache.pop_front();
				}
				cache.push_back((current_hash, fee_rate));
			}

			block_fee_rates.push(fee_rate);
		}

		if block_fee_rates.is_empty() {
			log_error!(self.logger, "No blocks available for fee rate estimation.");
			return Err(Error::FeerateEstimationUpdateFailed);
		}

		block_fee_rates.sort();

		let confirmation_targets = get_all_conf_targets();
		let mut new_fee_rate_cache = HashMap::with_capacity(confirmation_targets.len());

		for target in confirmation_targets {
			let num_blocks = get_num_block_defaults_for_target(target);
			let base_fee_rate = select_fee_rate_for_target(&block_fee_rates, num_blocks);
			let adjusted_fee_rate = apply_post_estimation_adjustments(target, base_fee_rate);
			new_fee_rate_cache.insert(target, adjusted_fee_rate);

			log_trace!(
				self.logger,
				"Fee rate estimation updated for {:?}: {} sats/kwu",
				target,
				adjusted_fee_rate.to_sat_per_kwu(),
			);
		}

		log_debug!(
			self.logger,
			"CBF fee rate estimation finished in {}ms ({} blocks sampled, {} cache hits).",
			now.elapsed().as_millis(),
			block_fee_rates.len(),
			cache_hits,
		);

		Ok(Some(new_fee_rate_cache))
	}

	/// Fetch per-target fee rates from an Esplora server.
	async fn fee_rate_cache_from_esplora(
		&self, client: &esplora_client::AsyncClient,
	) -> Result<HashMap<crate::fee_estimator::ConfirmationTarget, FeeRate>, Error> {
		let timeout = Duration::from_secs(
			self.sync_config.timeouts_config.fee_rate_cache_update_timeout_secs,
		);
		let estimates = tokio::time::timeout(timeout, client.get_fee_estimates())
			.await
			.map_err(|e| {
				log_error!(self.logger, "Updating fee rate estimates timed out: {}", e);
				Error::FeerateEstimationUpdateTimeout
			})?
			.map_err(|e| {
				log_error!(self.logger, "Failed to retrieve fee rate estimates: {}", e);
				Error::FeerateEstimationUpdateFailed
			})?;

		if estimates.is_empty() && self.config.network == Network::Bitcoin {
			log_error!(
				self.logger,
				"Failed to retrieve fee rate estimates: empty estimates are disallowed on Mainnet.",
			);
			return Err(Error::FeerateEstimationUpdateFailed);
		}

		let confirmation_targets = get_all_conf_targets();
		let mut new_fee_rate_cache = HashMap::with_capacity(confirmation_targets.len());
		for target in confirmation_targets {
			let num_blocks = get_num_block_defaults_for_target(target);
			let converted_estimate_sat_vb =
				esplora_client::convert_fee_rate(num_blocks, estimates.clone())
					.map_or(1.0, |converted| converted.max(1.0));
			let fee_rate = FeeRate::from_sat_per_kwu((converted_estimate_sat_vb * 250.0) as u64);
			let adjusted_fee_rate = apply_post_estimation_adjustments(target, fee_rate);
			new_fee_rate_cache.insert(target, adjusted_fee_rate);

			log_trace!(
				self.logger,
				"Fee rate estimation updated for {:?}: {} sats/kwu",
				target,
				adjusted_fee_rate.to_sat_per_kwu(),
			);
		}
		Ok(new_fee_rate_cache)
	}

	/// Fetch per-target fee rates from an Electrum server.
	///
	/// Opens a fresh connection for each call because `ElectrumClient` is not `Sync`.
	async fn fee_rate_cache_from_electrum(
		&self, server_url: &str,
	) -> Result<HashMap<crate::fee_estimator::ConfirmationTarget, FeeRate>, Error> {
		let server_url = server_url.to_owned();
		let confirmation_targets = get_all_conf_targets();
		let per_request_timeout = self.sync_config.timeouts_config.per_request_timeout_secs;

		let raw_estimates: Vec<serde_json::Value> = tokio::time::timeout(
			Duration::from_secs(
				self.sync_config.timeouts_config.fee_rate_cache_update_timeout_secs,
			),
			tokio::task::spawn_blocking(move || {
				let electrum_config = electrum_client::ConfigBuilder::new()
					.retry(3)
					.timeout(Some(per_request_timeout))
					.build();
				let client = electrum_client::Client::from_config(&server_url, electrum_config)
					.map_err(|_| Error::FeerateEstimationUpdateFailed)?;
				let mut batch = electrum_client::Batch::default();
				for target in confirmation_targets {
					batch.estimate_fee(get_num_block_defaults_for_target(target));
				}
				client.batch_call(&batch).map_err(|_| Error::FeerateEstimationUpdateFailed)
			}),
		)
		.await
		.map_err(|e| {
			log_error!(self.logger, "Updating fee rate estimates timed out: {}", e);
			Error::FeerateEstimationUpdateTimeout
		})?
		.map_err(|_| Error::FeerateEstimationUpdateFailed)? // JoinError
		?; // inner Result

		let confirmation_targets = get_all_conf_targets();

		if raw_estimates.len() != confirmation_targets.len()
			&& self.config.network == Network::Bitcoin
		{
			log_error!(
				self.logger,
				"Failed to retrieve fee rate estimates: Electrum server didn't return all expected results.",
			);
			return Err(Error::FeerateEstimationUpdateFailed);
		}

		let mut new_fee_rate_cache = HashMap::with_capacity(confirmation_targets.len());
		for (target, raw_rate) in confirmation_targets.into_iter().zip(raw_estimates.into_iter()) {
			// Electrum returns BTC/KvB; fall back to 1 sat/vb (= 0.00001 BTC/KvB) on failure.
			let fee_rate_btc_per_kvb =
				raw_rate.as_f64().map_or(0.00001_f64, |v: f64| v.max(0.00001));
			// Convert BTC/KvB → sat/kwu: multiply by 25_000_000 (= 10^8 / 4).
			let fee_rate =
				FeeRate::from_sat_per_kwu((fee_rate_btc_per_kvb * 25_000_000.0).round() as u64);
			let adjusted_fee_rate = apply_post_estimation_adjustments(target, fee_rate);
			new_fee_rate_cache.insert(target, adjusted_fee_rate);

			log_trace!(
				self.logger,
				"Fee rate estimation updated for {:?}: {} sats/kwu",
				target,
				adjusted_fee_rate.to_sat_per_kwu(),
			);
		}
		Ok(new_fee_rate_cache)
	}

	/// Broadcast a package of transactions via the P2P network.
	pub(crate) async fn process_broadcast_package(&self, package: Vec<Transaction>) {
		let Ok(requester) = self.requester() else { return };

		for tx in package {
			let txid = tx.compute_txid();
			let tx_bytes = tx.encode();
			let timeout_fut = tokio::time::timeout(
				Duration::from_secs(self.sync_config.timeouts_config.tx_broadcast_timeout_secs),
				requester.submit_package(tx),
			);
			match timeout_fut.await {
				Ok(res) => match res {
					Ok(wtxid) => {
						log_trace!(
							self.logger,
							"Successfully broadcast transaction {} (wtxid: {})",
							txid,
							wtxid
						);
					},
					Err(e) => {
						log_error!(
							self.logger,
							"Failed to broadcast transaction {}: {:?}",
							txid,
							e
						);
						log_trace!(
							self.logger,
							"Failed broadcast transaction bytes: {}",
							log_bytes!(tx_bytes)
						);
					},
				},
				Err(e) => {
					log_error!(
						self.logger,
						"Failed to broadcast transaction due to timeout {}: {}",
						txid,
						e
					);
					log_trace!(
						self.logger,
						"Failed broadcast transaction bytes: {}",
						log_bytes!(tx_bytes)
					);
				},
			}
		}
	}
}

/// SPKs to scan for on-chain wallet sync: every revealed key plus the configured
/// lookahead window per keychain. Mirrors bdk-kyoto's `UpdateBuilder::peek_scripts`.
fn peek_keychain_scripts(index: &KeychainTxOutIndex<KeychainKind>) -> Vec<ScriptBuf> {
	let mut scripts = Vec::new();
	let last_revealed = index.last_revealed_indices();
	let lookahead = index.lookahead();
	for keychain in [KeychainKind::External, KeychainKind::Internal] {
		let Some(spk_iter) = index.unbounded_spk_iter(keychain) else { continue };
		let frontier = last_revealed.get(&keychain).copied().unwrap_or(0);
		let bound = (frontier + lookahead) as usize;
		scripts.extend(spk_iter.take(bound).map(|(_, spk)| spk));
	}
	scripts
}

/// Record the current timestamp in a `NodeMetrics` field and persist the metrics.
fn update_node_metrics_timestamp(
	node_metrics: &RwLock<NodeMetrics>, kv_store: &DynStore, logger: &Logger,
	setter: impl FnOnce(&mut NodeMetrics, Option<u64>),
) -> Result<(), Error> {
	let unix_time_secs_opt = SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
	update_and_persist_node_metrics(node_metrics, kv_store, logger, |metrics| {
		setter(metrics, unix_time_secs_opt);
	})
}

/// Compute the block subsidy (mining reward before fees) at the given block height.
fn block_subsidy(height: u32) -> Amount {
	let halvings = height / SUBSIDY_HALVING_INTERVAL;
	if halvings >= 64 {
		return Amount::ZERO;
	}
	let base = Amount::ONE_BTC.to_sat() * 50;
	Amount::from_sat(base >> halvings)
}

/// Select a fee rate from sorted block fee rates based on confirmation urgency.
///
/// For urgent targets (1 block), uses the highest observed fee rate.
/// For medium targets (2-6 blocks), uses the 75th percentile.
/// For standard targets (7-12 blocks), uses the median.
/// For low-urgency targets (13+ blocks), uses the 25th percentile.
fn select_fee_rate_for_target(sorted_rates: &[FeeRate], num_blocks: usize) -> FeeRate {
	if sorted_rates.is_empty() {
		return FeeRate::from_sat_per_kwu(MIN_FEERATE_SAT_PER_KWU);
	}

	let len = sorted_rates.len();
	let idx = if num_blocks <= 1 {
		len - 1
	} else if num_blocks <= 6 {
		(len * 3) / 4
	} else if num_blocks <= 12 {
		len / 2
	} else {
		len / 4
	};

	sorted_rates[idx.min(len - 1)]
}

#[cfg(test)]
mod tests {
	use bitcoin::constants::SUBSIDY_HALVING_INTERVAL;
	use bitcoin::{Amount, FeeRate};

	use super::{block_subsidy, select_fee_rate_for_target, MIN_FEERATE_SAT_PER_KWU};
	use crate::fee_estimator::{
		apply_post_estimation_adjustments, get_all_conf_targets, get_num_block_defaults_for_target,
	};

	#[test]
	fn select_fee_rate_empty_returns_floor() {
		let rate = select_fee_rate_for_target(&[], 1);
		assert_eq!(rate, FeeRate::from_sat_per_kwu(MIN_FEERATE_SAT_PER_KWU));
	}

	#[test]
	fn select_fee_rate_single_element_returns_it_for_all_buckets() {
		let rates = [FeeRate::from_sat_per_kwu(5000)];
		// Every urgency bucket should return the single available rate.
		for num_blocks in [1, 3, 6, 12, 144, 1008] {
			let rate = select_fee_rate_for_target(&rates, num_blocks);
			assert_eq!(
				rate,
				FeeRate::from_sat_per_kwu(5000),
				"num_blocks={} should return the only available rate",
				num_blocks,
			);
		}
	}

	#[test]
	fn select_fee_rate_picks_correct_percentile() {
		// 6 sorted rates: indices 0..5
		let rates: [FeeRate; 6] = [100, 200, 300, 400, 500, 600].map(FeeRate::from_sat_per_kwu);
		// 1-block (most urgent): highest → index 5 → 600
		assert_eq!(select_fee_rate_for_target(&rates, 1), FeeRate::from_sat_per_kwu(600));
		// 6-block (medium): 75th percentile → (6*3)/4 = 4 → 500
		assert_eq!(select_fee_rate_for_target(&rates, 6), FeeRate::from_sat_per_kwu(500));
		// 12-block (standard): median → 6/2 = 3 → 400
		assert_eq!(select_fee_rate_for_target(&rates, 12), FeeRate::from_sat_per_kwu(400));
		// 144-block (low): 25th percentile → 6/4 = 1 → 200
		assert_eq!(select_fee_rate_for_target(&rates, 144), FeeRate::from_sat_per_kwu(200));
	}

	#[test]
	fn select_fee_rate_monotonic_urgency() {
		// More urgent targets should never produce lower rates than less urgent ones.
		let rates: [FeeRate; 6] = [250, 500, 1000, 2000, 4000, 8000].map(FeeRate::from_sat_per_kwu);
		let urgent = select_fee_rate_for_target(&rates, 1);
		let medium = select_fee_rate_for_target(&rates, 6);
		let standard = select_fee_rate_for_target(&rates, 12);
		let low = select_fee_rate_for_target(&rates, 144);

		assert!(
			urgent >= medium,
			"urgent ({}) >= medium ({})",
			urgent.to_sat_per_kwu(),
			medium.to_sat_per_kwu()
		);
		assert!(
			medium >= standard,
			"medium ({}) >= standard ({})",
			medium.to_sat_per_kwu(),
			standard.to_sat_per_kwu()
		);
		assert!(
			standard >= low,
			"standard ({}) >= low ({})",
			standard.to_sat_per_kwu(),
			low.to_sat_per_kwu()
		);
	}

	#[test]
	fn uniform_rates_match_naive_single_rate() {
		// When all blocks have the same fee rate (like the old single-block
		// approach), every target should select that same base rate. This
		// proves the optimized multi-block approach is backwards-compatible.

		let uniform_rate = 3000u64;
		let rates = [FeeRate::from_sat_per_kwu(uniform_rate); 6];
		for target in get_all_conf_targets() {
			let num_blocks = get_num_block_defaults_for_target(target);
			let optimized = select_fee_rate_for_target(&rates, num_blocks);
			let naive = FeeRate::from_sat_per_kwu(uniform_rate);
			assert_eq!(
				optimized, naive,
				"For target {:?} (num_blocks={}), optimized rate should match naive single-rate",
				target, num_blocks,
			);

			// Also verify the post-estimation adjustments produce the same
			// result for both approaches.
			let adjusted_optimized = apply_post_estimation_adjustments(target, optimized);
			let adjusted_naive = apply_post_estimation_adjustments(target, naive);
			assert_eq!(adjusted_optimized, adjusted_naive);
		}
	}

	#[test]
	fn block_subsidy_genesis() {
		assert_eq!(block_subsidy(0), Amount::from_sat(50 * 100_000_000));
	}

	#[test]
	fn block_subsidy_first_halving() {
		assert_eq!(block_subsidy(SUBSIDY_HALVING_INTERVAL), Amount::from_sat(25 * 100_000_000));
	}

	#[test]
	fn block_subsidy_second_halving() {
		assert_eq!(block_subsidy(SUBSIDY_HALVING_INTERVAL * 2), Amount::from_sat(1_250_000_000));
	}

	#[test]
	fn block_subsidy_exhausted_after_64_halvings() {
		assert_eq!(block_subsidy(SUBSIDY_HALVING_INTERVAL * 64), Amount::ZERO);
		assert_eq!(block_subsidy(SUBSIDY_HALVING_INTERVAL * 100), Amount::ZERO);
	}

	#[test]
	fn select_fee_rate_two_elements() {
		let rates: [FeeRate; 2] = [1000, 5000].map(FeeRate::from_sat_per_kwu);
		// 1-block: index 1 (highest) → 5000
		assert_eq!(select_fee_rate_for_target(&rates, 1), FeeRate::from_sat_per_kwu(5000));
		// 6-block: (2*3)/4 = 1 → 5000
		assert_eq!(select_fee_rate_for_target(&rates, 6), FeeRate::from_sat_per_kwu(5000));
		// 12-block: 2/2 = 1 → 5000
		assert_eq!(select_fee_rate_for_target(&rates, 12), FeeRate::from_sat_per_kwu(5000));
		// 144-block: 2/4 = 0 → 1000
		assert_eq!(select_fee_rate_for_target(&rates, 144), FeeRate::from_sat_per_kwu(1000));
	}

	#[test]
	fn select_fee_rate_all_targets_use_valid_indices() {
		for size in 1..=6 {
			let rates: Vec<FeeRate> =
				(1..=size).map(|i| FeeRate::from_sat_per_kwu(i as u64 * 1000)).collect();
			for target in get_all_conf_targets() {
				let num_blocks = get_num_block_defaults_for_target(target);
				let _ = select_fee_rate_for_target(&rates, num_blocks);
			}
		}
	}

	/// Test that checkpoint building from `recent_history` handles reorgs.
	///
	/// Scenario: wallet synced to height 103. A 3-block reorg replaces blocks
	/// 101-103 with new ones (same tip height). `recent_history` returns
	/// {94..=103} (last 10 blocks ending at tip) with new hashes at 101-103.
	///
	/// The checkpoint must reflect the reorged chain: new hashes at 101-103,
	/// pre-reorg blocks at ≤100 preserved.
	#[test]
	fn checkpoint_building_handles_reorg() {
		use bdk_chain::local_chain::LocalChain;
		use bdk_chain::{BlockId, CheckPoint};
		use bitcoin::BlockHash;
		use std::collections::BTreeMap;

		fn hash(seed: u32) -> BlockHash {
			use bitcoin::hashes::{sha256d, Hash, HashEngine};
			let mut engine = sha256d::Hash::engine();
			engine.input(&seed.to_le_bytes());
			BlockHash::from_raw_hash(sha256d::Hash::from_engine(engine))
		}

		let genesis = BlockId { height: 0, hash: hash(0) };

		// Wallet checkpoint: 0 → 100 → 101 → 102 → 103
		let wallet_cp = CheckPoint::from_block_ids([
			genesis,
			BlockId { height: 100, hash: hash(100) },
			BlockId { height: 101, hash: hash(101) },
			BlockId { height: 102, hash: hash(102) },
			BlockId { height: 103, hash: hash(103) },
		])
		.unwrap();

		// recent_history after reorg: 94-103, heights 101-103 have NEW hashes.
		let recent_history: BTreeMap<u32, BlockHash> = (94..=103)
			.map(|h| {
				let seed = if (101..=103).contains(&h) { h + 1000 } else { h };
				(h, hash(seed))
			})
			.collect();

		// Build checkpoint using the same logic as sync_onchain_wallet.
		let mut cp = wallet_cp;
		for (height, block_hash) in &recent_history {
			let block_id = BlockId { height: *height, hash: *block_hash };
			cp = cp.insert(block_id);
		}

		// Reorged blocks must have the NEW hashes.
		assert_eq!(cp.height(), 103);
		assert_eq!(
			cp.get(101).expect("height 101 must exist").hash(),
			hash(1101),
			"block 101 must have the reorged hash"
		);
		assert_eq!(cp.get(102).expect("height 102 must exist").hash(), hash(1102));
		assert_eq!(cp.get(103).expect("height 103 must exist").hash(), hash(1103));

		// Pre-reorg blocks are preserved.
		assert_eq!(cp.get(100).expect("height 100 must exist").hash(), hash(100));

		// The checkpoint must connect cleanly to a LocalChain.
		let (mut chain, _) = LocalChain::from_genesis_hash(genesis.hash);
		chain.apply_update(cp).expect("checkpoint must connect to chain");
	}
}
