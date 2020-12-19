#!/usr/bin/env python3
# Copyright (c) 2017-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that the mempool ensures transaction delivery by periodically sending
to peers until a GETDATA is received."""

import time

from test_framework.p2p import P2PTxInvStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


MAX_INITIAL_BROADCAST_DELAY = 15 * 60 # 15 minutes in seconds

class MempoolUnbroadcastTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def run_test(self):
        # Add enough mature utxos to the wallet so that all txs spend confirmed coins
        self.wallet = MiniWallet(self.nodes[0])
        self.wallet.generate(3)
        self.nodes[0].generate(100)

        self.test_broadcast()
        self.test_txn_removal()

    def test_broadcast(self):
        self.log.info("Test that mempool reattempts delivery of locally submitted transaction")
        node = self.nodes[0]
        self.disconnect_nodes(0, 1)

        self.log.info("Generate transactions that only node 0 knows about")
        # generate a wallet txn
        wallet_tx_hsh = self.wallet.send_self_transfer(from_node=node)["txid"]

        # generate a txn using sendrawtransaction
        rpc_tx_hsh = self.wallet.send_self_transfer(from_node=node)["txid"]

        # check transactions are in unbroadcast using rpc
        mempoolinfo = node.getmempoolinfo()
        assert_equal(mempoolinfo['unbroadcastcount'], 2)
        mempool = node.getrawmempool(True)
        assert(len(list(filter(lambda tx: mempool[tx]['unbroadcast'] == True, mempool))) == len(mempool))

        # check that second node doesn't have these two txns
        mempool = set(self.nodes[1].getrawmempool())
        assert(mempool.isdisjoint(set([rpc_tx_hsh, wallet_tx_hsh])))

        # ensure that unbroadcast txs are persisted to mempool.dat
        self.restart_node(0)

        self.log.info("Reconnect nodes & check if they are sent to node 1")
        self.connect_nodes(0, 1)

        # fast forward into the future & ensure that the second node has the txns
        node.mockscheduler(MAX_INITIAL_BROADCAST_DELAY)
        self.sync_mempools(timeout=30)
        mempool = set(self.nodes[1].getrawmempool())
        assert(set([rpc_tx_hsh, wallet_tx_hsh]).issubset(mempool))

        # check that transactions are no longer in first node's unbroadcast set
        mempool = node.getrawmempool(True)
        assert(len(list(filter(lambda tx: mempool[tx]['unbroadcast'] == False, mempool))) == len(mempool))

        self.log.info("Add another connection & ensure transactions aren't broadcast again")

        conn = node.add_p2p_connection(P2PTxInvStore())
        node.mockscheduler(MAX_INITIAL_BROADCAST_DELAY)
        time.sleep(2) # allow sufficient time for possibility of broadcast
        assert_equal(len(conn.get_invs()), 0)

        self.disconnect_nodes(0, 1)
        node.disconnect_p2ps()

    def test_txn_removal(self):
        self.log.info("Test that transactions removed from mempool are removed from unbroadcast set")
        # since the node doesn't have any connections, it will not receive
        # any GETDATAs & thus the transaction will remain in the unbroadcast set.
        txhsh = self.wallet.send_self_transfer(from_node=self.nodes[0])["txid"]

        # check transaction was removed from unbroadcast set due to presence in a block
        removal_reason = "Removed {} from set of unbroadcast txns before confirmation that txn was sent out".format(txhsh)
        with self.nodes[0].assert_debug_log([removal_reason]):
            node.generate(1)

if __name__ == "__main__":
    MempoolUnbroadcastTest().main()
