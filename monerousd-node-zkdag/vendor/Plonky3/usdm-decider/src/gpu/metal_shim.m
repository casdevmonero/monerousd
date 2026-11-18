// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
// ⭐ SPEED G1 (lane speed4, 2026-11-12, docs/SPEED-MAX-PROGRAM-20261112.md §8) — the Metal PLUMBING for the prover's GPU
// kernels, and nothing else: create the device once, compile the kernel source the Rust side hands over (the source
// lives in `gpu_grind.rs`, so the prover's source digest covers it), dispatch, wait, copy out. Every value it returns
// is checked on the CPU by the caller before it is used (a grind witness by `check_witness`; a permutation by the
// pins against the CPU permutation). No secret ever reaches this file: a grind's inputs are the public transcript.
#import <Metal/Metal.h>
#import <Foundation/Foundation.h>
#include <stdint.h>
#include <dispatch/dispatch.h>

static id<MTLDevice> g_dev = nil;
static id<MTLCommandQueue> g_queue = nil;
static id<MTLComputePipelineState> g_grind = nil;
static id<MTLComputePipelineState> g_perm = nil;
static id<MTLComputePipelineState> g_leaves = nil;   // SPEED G2: one sponge per committed row
static id<MTLComputePipelineState> g_compress = nil; // SPEED G2: one 2-to-1 compression per parent
static id<MTLComputePipelineState> g_bitrev = nil;   // SPEED G3: the transform's row reversal
static id<MTLComputePipelineState> g_rowscale = nil; // SPEED G3: a per-row scale (coset shift, 1/h)
static id<MTLComputePipelineState> g_dit = nil;      // SPEED G3: one butterfly stage
static int g_ready = 0; // 1 ready, -1 unavailable

// Compile the kernels once. Returns 1 when the GPU is ready, 0 when it is not (no device, or the source did not
// compile: the caller then never asks again and the CPU does the work).
int musd_gpu_init(const char *source) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        @autoreleasepool {
            g_dev = MTLCreateSystemDefaultDevice();
            if (g_dev == nil) { g_ready = -1; return; }
            NSError *err = nil;
            NSString *src = [NSString stringWithUTF8String:source];
            id<MTLLibrary> lib = [g_dev newLibraryWithSource:src options:nil error:&err];
            if (lib == nil) { NSLog(@"[gpu] kernel source did not compile: %@", err); g_ready = -1; return; }
            id<MTLFunction> fg = [lib newFunctionWithName:@"grind16"];
            id<MTLFunction> fp = [lib newFunctionWithName:@"perm16"];
            id<MTLFunction> fl = [lib newFunctionWithName:@"leaves16"];
            id<MTLFunction> fc = [lib newFunctionWithName:@"compress16"];
            id<MTLFunction> fb = [lib newFunctionWithName:@"bitrev16"];
            id<MTLFunction> fs = [lib newFunctionWithName:@"rowscale16"];
            id<MTLFunction> fd = [lib newFunctionWithName:@"dit16"];
            if (fg == nil || fp == nil || fl == nil || fc == nil || fb == nil || fs == nil || fd == nil) { g_ready = -1; return; }
            g_bitrev = [g_dev newComputePipelineStateWithFunction:fb error:&err];
            g_rowscale = [g_dev newComputePipelineStateWithFunction:fs error:&err];
            g_dit = [g_dev newComputePipelineStateWithFunction:fd error:&err];
            if (g_bitrev == nil || g_rowscale == nil || g_dit == nil) { g_ready = -1; return; }
            g_grind = [g_dev newComputePipelineStateWithFunction:fg error:&err];
            g_perm = [g_dev newComputePipelineStateWithFunction:fp error:&err];
            g_leaves = [g_dev newComputePipelineStateWithFunction:fl error:&err];
            g_compress = [g_dev newComputePipelineStateWithFunction:fc error:&err];
            g_queue = [g_dev newCommandQueue];
            g_ready = (g_grind != nil && g_perm != nil && g_leaves != nil && g_compress != nil && g_queue != nil) ? 1 : -1;
        }
    });
    return g_ready == 1;
}

static void run(id<MTLComputePipelineState> pso, NSArray<id<MTLBuffer>> *bufs, uint32_t threads) {
    id<MTLCommandBuffer> cb = [g_queue commandBuffer];
    id<MTLComputeCommandEncoder> enc = [cb computeCommandEncoder];
    [enc setComputePipelineState:pso];
    for (NSUInteger i = 0; i < bufs.count; i++) [enc setBuffer:bufs[i] offset:0 atIndex:i];
    NSUInteger tg = MIN(pso.maxTotalThreadsPerThreadgroup, (NSUInteger)256);
    [enc dispatchThreads:MTLSizeMake(threads, 1, 1) threadsPerThreadgroup:MTLSizeMake(tg, 1, 1)];
    [enc endEncoding];
    [cb commit];
    [cb waitUntilCompleted];
}

// One grind chunk: candidates [start, start + count). `consts` = 164 Montgomery words (external initial 4x16,
// external terminal 4x16, internal 20, diagonal 16), `base` = 16 Montgomery words, `params` = {witness_idx, out_idx,
// mask, start}. Writes the smallest hit to *out_min (0xFFFFFFFF when none). Returns 1 on success, 0 when not ready.
int musd_gpu_grind16(const uint32_t *consts, const uint32_t *base, const uint32_t *params, uint32_t count,
                     uint32_t *out_min) {
    if (g_ready != 1 || count == 0) return 0;
    @autoreleasepool {
        uint32_t init = 0xFFFFFFFFu;
        id<MTLBuffer> bc = [g_dev newBufferWithBytes:consts length:164 * 4 options:MTLResourceStorageModeShared];
        id<MTLBuffer> bb = [g_dev newBufferWithBytes:base length:16 * 4 options:MTLResourceStorageModeShared];
        id<MTLBuffer> bp = [g_dev newBufferWithBytes:params length:4 * 4 options:MTLResourceStorageModeShared];
        id<MTLBuffer> bo = [g_dev newBufferWithBytes:&init length:4 options:MTLResourceStorageModeShared];
        if (!bc || !bb || !bp || !bo) return 0;
        run(g_grind, @[bc, bb, bp, bo], count);
        *out_min = *(uint32_t *)bo.contents;
    }
    return 1;
}

// SPEED G2: the leaf digests of `nrows` rows of `width` Montgomery words each (row-major): one 8-word digest per row
// into `out` (8·nrows words). Returns 1 on success, 0 when not ready.
int musd_gpu_leaves16(const uint32_t *consts, const uint32_t *rows, uint32_t nrows, uint32_t width, uint32_t *out) {
    if (g_ready != 1 || nrows == 0 || width == 0) return 0;
    @autoreleasepool {
        uint32_t w = width;
        id<MTLBuffer> bc = [g_dev newBufferWithBytes:consts length:164 * 4 options:MTLResourceStorageModeShared];
        id<MTLBuffer> br = [g_dev newBufferWithBytes:rows length:(NSUInteger)nrows * width * 4 options:MTLResourceStorageModeShared];
        id<MTLBuffer> bw = [g_dev newBufferWithBytes:&w length:4 options:MTLResourceStorageModeShared];
        id<MTLBuffer> bo = [g_dev newBufferWithLength:(NSUInteger)nrows * 32 options:MTLResourceStorageModeShared];
        if (!bc || !br || !bw || !bo) return 0;
        run(g_leaves, @[bc, br, bw, bo], nrows);
        memcpy(out, bo.contents, (size_t)nrows * 32);
    }
    return 1;
}

// SPEED G2: `out_len` parents, parent i = compress(children 2i, 2i+1) when step = 2, or compress(child i, default) when
// step = 1; digests are 8 Montgomery words. Returns 1 on success, 0 when not ready.
int musd_gpu_compress16(const uint32_t *consts, const uint32_t *prev, uint32_t prev_len, uint32_t out_len, uint32_t step,
                        uint32_t *out) {
    if (g_ready != 1 || out_len == 0 || (step != 1 && step != 2)) return 0;
    @autoreleasepool {
        uint32_t s = step;
        id<MTLBuffer> bc = [g_dev newBufferWithBytes:consts length:164 * 4 options:MTLResourceStorageModeShared];
        id<MTLBuffer> bp = [g_dev newBufferWithBytes:prev length:(NSUInteger)prev_len * 32 options:MTLResourceStorageModeShared];
        id<MTLBuffer> bs = [g_dev newBufferWithBytes:&s length:4 options:MTLResourceStorageModeShared];
        id<MTLBuffer> bo = [g_dev newBufferWithLength:(NSUInteger)out_len * 32 options:MTLResourceStorageModeShared];
        if (!bc || !bp || !bs || !bo) return 0;
        run(g_compress, @[bc, bp, bs, bo], out_len);
        memcpy(out, bo.contents, (size_t)out_len * 32);
    }
    return 1;
}

static void encode(id<MTLCommandBuffer> cb, id<MTLComputePipelineState> pso, NSArray<id<MTLBuffer>> *bufs,
                   const uint32_t *params, uint32_t threads) {
    id<MTLComputeCommandEncoder> enc = [cb computeCommandEncoder];
    [enc setComputePipelineState:pso];
    for (NSUInteger i = 0; i < bufs.count; i++) [enc setBuffer:bufs[i] offset:0 atIndex:i];
    [enc setBytes:params length:4 * 4 atIndex:bufs.count];
    NSUInteger tg = MIN(pso.maxTotalThreadsPerThreadgroup, (NSUInteger)256);
    [enc dispatchThreads:MTLSizeMake(threads, 1, 1) threadsPerThreadgroup:MTLSizeMake(tg, 1, 1)];
    [enc endEncoding]; // one encoder per step: the buffers are tracked, so each step sees the one before it
}

// SPEED G3: the transform of every column of the h × w row-major Montgomery matrix `data`, in place: optional row
// pre-scale `prescale[r]` (h words, or NULL), the row reversal, then log2(h) butterfly stages with twiddles
// `tw[x] = root^x` (h/2 words). Natural order out. Returns 1 on success, 0 when not ready.
int musd_gpu_ntt16(uint32_t *data, uint32_t h, uint32_t w, const uint32_t *tw, const uint32_t *prescale) {
    if (g_ready != 1 || h < 2 || (h & (h - 1)) != 0 || w == 0) return 0;
    uint32_t logh = 0;
    while ((1u << logh) < h) logh++;
    @autoreleasepool {
        NSUInteger bytes = (NSUInteger)h * w * 4;
        id<MTLBuffer> a = [g_dev newBufferWithBytes:data length:bytes options:MTLResourceStorageModeShared];
        id<MTLBuffer> b = [g_dev newBufferWithLength:bytes options:MTLResourceStorageModeShared];
        id<MTLBuffer> t = [g_dev newBufferWithBytes:tw length:(NSUInteger)(h / 2) * 4 options:MTLResourceStorageModeShared];
        if (!a || !b || !t) return 0;
        id<MTLCommandBuffer> cb = [g_queue commandBuffer];
        if (prescale != NULL) {
            id<MTLBuffer> s = [g_dev newBufferWithBytes:prescale length:(NSUInteger)h * 4 options:MTLResourceStorageModeShared];
            if (!s) return 0;
            uint32_t p[4] = {h, w, logh, 0};
            encode(cb, g_rowscale, @[a, s], p, h * w);
        }
        uint32_t pb[4] = {h, w, logh, 0};
        encode(cb, g_bitrev, @[a, b], pb, h * w);
        for (uint32_t m = 1; m < h; m <<= 1) {
            uint32_t pd[4] = {h, w, logh, m};
            encode(cb, g_dit, @[b, t], pd, (h / 2) * w);
        }
        [cb commit];
        [cb waitUntilCompleted];
        if (cb.status != MTLCommandBufferStatusCompleted) return 0;
        memcpy(data, b.contents, bytes);
    }
    return 1;
}

// n permutations of 16-word Montgomery states, in place (the pins compare them with the CPU permutation).
int musd_gpu_perm16(const uint32_t *consts, uint32_t *states, uint32_t n) {
    if (g_ready != 1 || n == 0) return 0;
    @autoreleasepool {
        id<MTLBuffer> bc = [g_dev newBufferWithBytes:consts length:164 * 4 options:MTLResourceStorageModeShared];
        id<MTLBuffer> bs = [g_dev newBufferWithBytes:states length:(NSUInteger)n * 64 options:MTLResourceStorageModeShared];
        if (!bc || !bs) return 0;
        run(g_perm, @[bc, bs], n);
        memcpy(states, bs.contents, (size_t)n * 64);
    }
    return 1;
}
