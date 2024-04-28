use reth_interfaces::{
    blockchain_tree::{
        error::{BlockchainTreeError, CanonicalError, InsertBlockError},
        BlockValidationKind, BlockchainTreeEngine, BlockchainTreeViewer, CanonicalOutcome,
        InsertPayloadOk,
    },
    provider::ProviderError,
    RethResult,
};
use reth_primitives::{
    BlockHash, BlockNumHash, BlockNumber, Receipt, SealedBlock, SealedBlockWithSenders,
    SealedHeader,
};
use reth_provider::{
    BlockchainTreePendingStateProvider, BundleStateDataProvider, CanonStateNotificationSender,
    CanonStateNotifications, CanonStateSubscriptions,
};
use std::collections::{BTreeMap, HashSet};

/// A BlockchainTree that does nothing.
///
/// Caution: this is only intended for testing purposes, or for wiring components together.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct NoopBlockchainTree {
    /// Broadcast channel for canon state changes notifications.
    pub canon_state_notification_sender: Option<CanonStateNotificationSender>,
}

impl BlockchainTreeEngine for NoopBlockchainTree {
    fn buffer_block(&self, _block: SealedBlockWithSenders) -> Result<(), InsertBlockError> {
        Ok(())
    }

    fn insert_block(
        &self,
        block: SealedBlockWithSenders,
        _validation_kind: BlockValidationKind,
    ) -> Result<InsertPayloadOk, InsertBlockError> {
        Err(InsertBlockError::tree_error(
            BlockchainTreeError::BlockHashNotFoundInChain { block_hash: block.hash() },
            block.block,
        ))
    }

    fn finalize_block(&self, _finalized_block: BlockNumber) {}

    fn connect_buffered_blocks_to_canonical_hashes_and_finalize(
        &self,
        _last_finalized_block: BlockNumber,
    ) -> RethResult<()> {
        Ok(())
    }

    fn connect_buffered_blocks_to_canonical_hashes(&self) -> RethResult<()> {
        Ok(())
    }

    fn make_canonical(&self, block_hash: BlockHash) -> Result<CanonicalOutcome, CanonicalError> {
        Err(BlockchainTreeError::BlockHashNotFoundInChain { block_hash }.into())
    }
}

impl BlockchainTreeViewer for NoopBlockchainTree {
    fn blocks(&self) -> BTreeMap<BlockNumber, HashSet<BlockHash>> {
        Default::default()
    }

    fn header_by_hash(&self, _hash: BlockHash) -> Option<SealedHeader> {
        None
    }

    fn block_by_hash(&self, _hash: BlockHash) -> Option<SealedBlock> {
        None
    }

    fn block_with_senders_by_hash(&self, _hash: BlockHash) -> Option<SealedBlockWithSenders> {
        None
    }

    fn buffered_block_by_hash(&self, _block_hash: BlockHash) -> Option<SealedBlock> {
        None
    }

    fn buffered_header_by_hash(&self, _block_hash: BlockHash) -> Option<SealedHeader> {
        None
    }

    fn canonical_blocks(&self) -> BTreeMap<BlockNumber, BlockHash> {
        Default::default()
    }

    fn is_canonical(&self, _block_hash: BlockHash) -> Result<bool, ProviderError> {
        Ok(false)
    }

    fn lowest_buffered_ancestor(&self, _hash: BlockHash) -> Option<SealedBlockWithSenders> {
        None
    }

    fn canonical_tip(&self) -> BlockNumHash {
        Default::default()
    }

    fn pending_blocks(&self) -> (BlockNumber, Vec<BlockHash>) {
        (0, vec![])
    }

    fn pending_block_num_hash(&self) -> Option<BlockNumHash> {
        None
    }

    fn pending_block_and_receipts(&self) -> Option<(SealedBlock, Vec<Receipt>)> {
        None
    }

    fn receipts_by_block_hash(&self, _block_hash: BlockHash) -> Option<Vec<Receipt>> {
        None
    }
}

impl BlockchainTreePendingStateProvider for NoopBlockchainTree {
    fn find_pending_state_provider(
        &self,
        _block_hash: BlockHash,
    ) -> Option<Box<dyn BundleStateDataProvider>> {
        None
    }
}

impl CanonStateSubscriptions for NoopBlockchainTree {
    fn subscribe_to_canonical_state(&self) -> CanonStateNotifications {
        self.canon_state_notification_sender
            .as_ref()
            .map(|sender| sender.subscribe())
            .unwrap_or_else(|| CanonStateNotificationSender::new(1).subscribe())
    }
}
