# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
CC = "/root/MoneroUSD-clean/monero/src/cryptonote_core/"
# glue .h
gh = CC + "pqpool_transition_glue.h"; g = open(gh).read()
if "reserve_yield_coinbase_spend_prove" not in g:
    anc = "bool reserve_yield_note_tree_root(const unsigned char *note_cms, size_t note_cms_len, size_t depth, unsigned char *out_root);"
    if g.count(anc) != 1: print("FATAL gh anchor x%d" % g.count(anc)); sys.exit(1)
    g = g.replace(anc, anc + '''
// CRY-6d-wallet: build a reserve-yield coinbase-note SPEND bundle (the wallet's prove entry point).
bool reserve_yield_coinbase_spend_prove(const unsigned char *sk, const unsigned char *rho, const unsigned char *rcm,
                                        uint64_t value, uint32_t asset, const unsigned char *cmt_notes, size_t cmt_notes_len,
                                        size_t leaf_index, size_t cmt_depth, const unsigned char *out_pk, uint64_t fee,
                                        uint64_t chain_id, size_t imt_depth, std::vector<uint8_t> &bundle_out);''', 1)
    open(gh, "w").write(g); print("glue.h: prove bridge decl added")
else: print("glue.h prove bridge present; skip")
# glue .cpp
gc = CC + "pqpool_transition_glue.cpp"; c = open(gc).read()
if "reserve_yield_coinbase_spend_prove" not in c:
    anc = "bool reserve_yield_note_tree_root(const unsigned char *note_cms, size_t note_cms_len, size_t depth, unsigned char *out_root) {"
    if c.count(anc) != 1: print("FATAL gc anchor x%d" % c.count(anc)); sys.exit(1)
    IMPL = '''// CRY-6d-wallet: build a coinbase-note spend bundle. Bundle is a ~2.8MB STARK; grow the buffer on demand.
bool reserve_yield_coinbase_spend_prove(const unsigned char *sk, const unsigned char *rho, const unsigned char *rcm,
                                        uint64_t value, uint32_t asset, const unsigned char *cmt_notes, size_t cmt_notes_len,
                                        size_t leaf_index, size_t cmt_depth, const unsigned char *out_pk, uint64_t fee,
                                        uint64_t chain_id, size_t imt_depth, std::vector<uint8_t> &bundle_out) {
#if defined(MONEROUSD_HAVE_PQPOOL_FFI)
  std::vector<uint8_t> buf(4u * 1024u * 1024u);
  size_t out_len = 0;
  int r = ::pqpool_reserve_yield_coinbase_spend_prove(sk, rho, rcm, value, asset, cmt_notes, cmt_notes_len, leaf_index,
                                                      cmt_depth, out_pk, fee, chain_id, imt_depth, buf.data(), buf.size(), &out_len);
  if (r == -2 && out_len > buf.size()) {
    buf.resize(out_len);
    r = ::pqpool_reserve_yield_coinbase_spend_prove(sk, rho, rcm, value, asset, cmt_notes, cmt_notes_len, leaf_index,
                                                    cmt_depth, out_pk, fee, chain_id, imt_depth, buf.data(), buf.size(), &out_len);
  }
  if (r != 1) return false;
  bundle_out.assign(buf.begin(), buf.begin() + out_len);
  return true;
#else
  (void)sk;(void)rho;(void)rcm;(void)value;(void)asset;(void)cmt_notes;(void)cmt_notes_len;(void)leaf_index;
  (void)cmt_depth;(void)out_pk;(void)fee;(void)chain_id;(void)imt_depth;(void)bundle_out; return false;
#endif
}

'''
    c = c.replace(anc, IMPL + anc, 1); open(gc, "w").write(c); print("glue.cpp: prove bridge impl added")
else: print("glue.cpp prove bridge present; skip")
print("DONE")
