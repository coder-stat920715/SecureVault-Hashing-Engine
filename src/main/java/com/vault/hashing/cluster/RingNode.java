package com.vault.hashing.cluster;

/** Anything that can be placed on a {@link ConsistentHashRing}. */
public interface RingNode {

    /** Stable, unique identity of the physical node; virtual node positions are derived from it. */
    String ringKey();
}
