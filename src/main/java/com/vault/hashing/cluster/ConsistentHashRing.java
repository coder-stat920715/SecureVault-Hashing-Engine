package com.vault.hashing.cluster;

import com.vault.hashing.common.VaultExceptions.NoWorkerAvailableException;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.ToLongFunction;

/**
 * Consistent hash ring with virtual nodes (use case 6).
 *
 * <p><b>Idea.</b> Keys and nodes are hashed onto the same circular 64-bit space. A key belongs to the first node
 * position found clockwise from the key's own position. Because ownership depends only on neighbouring positions,
 * adding or removing a node only affects the keys in the arcs adjacent to its positions: roughly {@code 1/N} of
 * all keys move, versus nearly all keys with {@code hash(key) % N}.
 *
 * <p><b>Virtual nodes.</b> Each physical node is placed at many pseudo-random positions (default 100). With a
 * single position per node the arcs would be wildly uneven; with ~100 the law of large numbers evens the load
 * out, and a departing node's keys are spread over <em>all</em> remaining nodes instead of dumping onto one
 * neighbour.
 *
 * <p>Thread-safe: lookups share a read lock, membership changes take the write lock.
 *
 * @param <T> physical node type
 */
public class ConsistentHashRing<T extends RingNode> {

    private static final double TWO_POW_64 = 18_446_744_073_709_551_616.0;

    private final int virtualNodesPerNode;
    private final ToLongFunction<String> hashFunction;
    private final TreeMap<Long, T> ring = new TreeMap<>();
    private final Map<String, T> physicalNodes = new LinkedHashMap<>();
    private final ReadWriteLock lock = new ReentrantReadWriteLock();

    public ConsistentHashRing(int virtualNodesPerNode, ToLongFunction<String> hashFunction) {
        if (virtualNodesPerNode < 1) {
            throw new IllegalArgumentException("virtualNodesPerNode must be >= 1");
        }
        this.virtualNodesPerNode = virtualNodesPerNode;
        this.hashFunction = Objects.requireNonNull(hashFunction, "hashFunction");
    }

    /** @return true if the node was added, false if a node with the same key is already on the ring */
    public boolean addNode(T node) {
        Objects.requireNonNull(node, "node");
        String key = node.ringKey();
        lock.writeLock().lock();
        try {
            if (physicalNodes.containsKey(key)) {
                return false;
            }
            physicalNodes.put(key, node);
            for (int i = 0; i < virtualNodesPerNode; i++) {
                String label = key + "#VN" + i;
                long position = hashFunction.applyAsLong(label);
                int attempt = 0;
                while (ring.containsKey(position)) { // astronomically rare 64-bit collision: probe deterministically
                    position = hashFunction.applyAsLong(label + "|" + (++attempt));
                }
                ring.put(position, node);
            }
            return true;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** @return true if the node was on the ring and has been removed together with all its virtual nodes */
    public boolean removeNode(T node) {
        Objects.requireNonNull(node, "node");
        return removeNodeById(node.ringKey());
    }

    public boolean removeNodeById(String nodeKey) {
        lock.writeLock().lock();
        try {
            if (physicalNodes.remove(nodeKey) == null) {
                return false;
            }
            ring.values().removeIf(n -> n.ringKey().equals(nodeKey));
            return true;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Finds the node responsible for the key: the first virtual node at or after the key's position,
     * wrapping around to the lowest position when the key hashes past the last one.
     *
     * @throws NoWorkerAvailableException when the ring is empty
     */
    public T getNode(String key) {
        Objects.requireNonNull(key, "key");
        lock.readLock().lock();
        try {
            if (ring.isEmpty()) {
                throw new NoWorkerAvailableException("No worker nodes are registered on the ring");
            }
            Map.Entry<Long, T> entry = ring.ceilingEntry(hashFunction.applyAsLong(key));
            return (entry != null ? entry : ring.firstEntry()).getValue();
        } finally {
            lock.readLock().unlock();
        }
    }

    /** The key's position on the ring (treat as an unsigned 64-bit value when displaying). */
    public long position(String key) {
        return hashFunction.applyAsLong(key);
    }

    /** Snapshot of the physical nodes in insertion order. */
    public List<T> nodes() {
        lock.readLock().lock();
        try {
            return List.copyOf(physicalNodes.values());
        } finally {
            lock.readLock().unlock();
        }
    }

    public int size() {
        lock.readLock().lock();
        try {
            return physicalNodes.size();
        } finally {
            lock.readLock().unlock();
        }
    }

    public int virtualNodeCount() {
        lock.readLock().lock();
        try {
            return ring.size();
        } finally {
            lock.readLock().unlock();
        }
    }

    public int getVirtualNodesPerNode() {
        return virtualNodesPerNode;
    }

    /**
     * Exact share of the hash space owned by each physical node (values sum to 1.0), computed from arc lengths
     * rather than sampling. Useful to judge how well virtual nodes balance the ring.
     */
    public Map<String, Double> ownership() {
        lock.readLock().lock();
        try {
            Map<String, Double> shares = new LinkedHashMap<>();
            if (ring.isEmpty()) {
                return shares;
            }
            if (physicalNodes.size() == 1) {
                shares.put(physicalNodes.keySet().iterator().next(), 1.0);
                return shares;
            }
            long previous = ring.lastKey();
            for (Map.Entry<Long, T> entry : ring.entrySet()) {
                long arc = entry.getKey() - previous; // wraps modulo 2^64, exactly what the circle needs
                shares.merge(entry.getValue().ringKey(), unsignedToDouble(arc) / TWO_POW_64, Double::sum);
                previous = entry.getKey();
            }
            return shares;
        } finally {
            lock.readLock().unlock();
        }
    }

    private static double unsignedToDouble(long value) {
        double d = (double) (value >>> 1) * 2.0;
        return (value & 1L) != 0 ? d + 1.0 : d;
    }
}
