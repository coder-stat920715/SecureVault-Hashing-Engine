package com.vault.hashing.cluster;

import com.vault.hashing.common.VaultExceptions.NoWorkerAvailableException;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConsistentHashRingTest {

    private static final int KEYS = 20_000;

    private static ConsistentHashRing<WorkerNode> ringWith(String... ids) {
        ConsistentHashRing<WorkerNode> ring = new ConsistentHashRing<>(100, RingHashFunctions.md5());
        for (String id : ids) {
            ring.addNode(new WorkerNode(id, id + ":9000"));
        }
        return ring;
    }

    private static Map<String, String> assignAll(ConsistentHashRing<WorkerNode> ring) {
        Map<String, String> assignment = new HashMap<>();
        for (int i = 0; i < KEYS; i++) {
            assignment.put("doc-" + i, ring.getNode("doc-" + i).id());
        }
        return assignment;
    }

    @Test
    void emptyRingRejectsLookups() {
        assertThrows(NoWorkerAvailableException.class, () -> ringWith().getNode("x"));
    }

    @Test
    void routingIsDeterministic() {
        ConsistentHashRing<WorkerNode> ring = ringWith("a", "b", "c");
        assertEquals(ring.getNode("doc-42"), ring.getNode("doc-42"));
    }

    @Test
    void duplicateNodeIsIgnored() {
        ConsistentHashRing<WorkerNode> ring = ringWith("a");
        assertFalse(ring.addNode(new WorkerNode("a", "other:1")));
        assertEquals(100, ring.virtualNodeCount());
    }

    @Test
    void addingNodeOnlyMovesKeysToTheNewNode() {
        ConsistentHashRing<WorkerNode> ring = ringWith("a", "b", "c");
        Map<String, String> before = assignAll(ring);
        ring.addNode(new WorkerNode("d", "d:9000"));
        Map<String, String> after = assignAll(ring);

        int moved = 0;
        for (String key : before.keySet()) {
            if (!before.get(key).equals(after.get(key))) {
                moved++;
                assertEquals("d", after.get(key), "keys may only move to the new node");
            }
        }
        double fraction = (double) moved / KEYS;
        assertTrue(fraction > 0.15 && fraction < 0.35, "expected ~25% to move but was " + fraction);
    }

    @Test
    void removingNodeOnlyMovesItsOwnKeys() {
        ConsistentHashRing<WorkerNode> ring = ringWith("a", "b", "c", "d");
        Map<String, String> before = assignAll(ring);
        assertTrue(ring.removeNodeById("b"));
        Map<String, String> after = assignAll(ring);

        for (String key : before.keySet()) {
            if (!before.get(key).equals("b")) {
                assertEquals(before.get(key), after.get(key), "keys of surviving nodes must not move");
            } else {
                assertFalse(after.get(key).equals("b"));
            }
        }
    }

    @Test
    void ownershipSumsToOneAndIsRoughlyBalanced() {
        ConsistentHashRing<WorkerNode> ring = ringWith("a", "b", "c", "d");
        Map<String, Double> shares = ring.ownership();
        assertEquals(1.0, shares.values().stream().mapToDouble(Double::doubleValue).sum(), 1e-9);
        shares.values().forEach(s -> assertTrue(s > 0.15 && s < 0.35, "unbalanced share " + s));
    }
}
