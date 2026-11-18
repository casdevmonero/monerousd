// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// CRY-6c smoke: the note tree built in Rust is circuit-compatible (a spend verifies against its root),
// and the root/path FFIs are deterministic + consistent.
#include <cstdio>
#include <cstring>
#include <vector>
extern "C" {
#include "pqpool_ffi.h"
}
int main() {
  int st = pqpool_reserve_yield_tree_spend_selftest();   // build tree -> path -> spend verifies
  printf("tree->spend selftest = %d (1=spend against tree root verifies)\n", st);

  // Build a small tree of 5 note_cms (each 32B, here just distinct patterns) at depth 4; get root + a path.
  const size_t depth = 4, count = 5;
  std::vector<unsigned char> cms(count * 32, 0);
  for (size_t i = 0; i < count; i++) { cms[i*32] = (unsigned char)(i + 1); cms[i*32 + 1] = 0xAB; }
  unsigned char root[32], root2[32], sibs[4*32];
  int rr = pqpool_ry_note_tree_root(cms.data(), cms.size(), depth, root, 32);
  int rr2 = pqpool_ry_note_tree_root(cms.data(), cms.size(), depth, root2, 32);
  int pr = pqpool_ry_note_tree_path(cms.data(), cms.size(), depth, 2, sibs, depth*32);
  int root_nz = 0; for (int i = 0; i < 32; i++) if (root[i]) root_nz = 1;
  int deterministic = (memcmp(root, root2, 32) == 0);
  printf("root=%d(nz=%d,det=%d) path=%d  root=%02x%02x.. sib0=%02x%02x..\n",
         rr, root_nz, deterministic, pr, root[0], root[1], sibs[0], sibs[1]);

  int ok = (st == 1) && (rr == 1) && (rr2 == 1) && (pr == 1) && root_nz && deterministic;
  printf("TREE_%s\n", ok ? "OK" : "FAIL");
  return ok ? 0 : 1;
}
