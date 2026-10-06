package com.vault.hashing.cluster;

/** A (simulated) worker that processes document jobs. */
public record WorkerNode(String id, String address) implements RingNode {

    @Override
    public String ringKey() {
        return id;
    }
}
