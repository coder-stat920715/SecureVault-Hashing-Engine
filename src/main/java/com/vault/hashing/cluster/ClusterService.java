package com.vault.hashing.cluster;

import com.vault.hashing.cluster.ClusterDtos.DistributionReport;
import com.vault.hashing.cluster.ClusterDtos.MembershipChangeReport;
import com.vault.hashing.cluster.ClusterDtos.NodeLoad;
import com.vault.hashing.cluster.ClusterDtos.RouteResult;
import com.vault.hashing.common.VaultExceptions.ConflictException;
import com.vault.hashing.common.VaultExceptions.NoWorkerAvailableException;
import com.vault.hashing.common.VaultExceptions.ResourceNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Routing, load-balance metrics and membership changes on top of the {@link ConsistentHashRing}. */
@Service
@RequiredArgsConstructor
public class ClusterService {

    private static final int MOVEMENT_SAMPLE = 10_000;
    private static final int MAX_DISTRIBUTION_SAMPLE = 500_000;

    private final ConsistentHashRing<WorkerNode> ring;

    public RouteResult route(String documentId) {
        WorkerNode node = ring.getNode(documentId);
        return new RouteResult(documentId, String.format("%016x", ring.position(documentId)), node, ring.size());
    }

    public List<WorkerNode> nodes() {
        return ring.nodes();
    }

    /** Routes {@code sampleSize} synthetic document ids and reports how evenly they land on the nodes. */
    public DistributionReport distribution(int requestedSample) {
        int sample = Math.min(Math.max(requestedSample, 1), MAX_DISTRIBUTION_SAMPLE);
        List<WorkerNode> nodes = ring.nodes();
        if (nodes.isEmpty()) {
            throw new NoWorkerAvailableException("No worker nodes are registered on the ring");
        }

        Map<String, Integer> counts = new HashMap<>();
        nodes.forEach(n -> counts.put(n.id(), 0));
        for (int i = 0; i < sample; i++) {
            counts.merge(ring.getNode("doc-" + i).id(), 1, Integer::sum);
        }

        Map<String, Double> ownership = ring.ownership();
        double mean = (double) sample / nodes.size();
        List<NodeLoad> loads = nodes.stream().map(n -> {
            int c = counts.getOrDefault(n.id(), 0);
            return new NodeLoad(n.id(), n.address(), c, round(100.0 * c / sample),
                    round(100.0 * ownership.getOrDefault(n.id(), 0.0)));
        }).toList();

        double variance = loads.stream().mapToDouble(l -> Math.pow(l.assignedKeys() - mean, 2)).average().orElse(0);
        int max = loads.stream().mapToInt(NodeLoad::assignedKeys).max().orElse(0);
        int min = loads.stream().mapToInt(NodeLoad::assignedKeys).min().orElse(0);

        return new DistributionReport(nodes.size(), ring.getVirtualNodesPerNode(), ring.virtualNodeCount(), sample,
                round(100.0 / nodes.size()), round(100.0 * Math.sqrt(variance) / mean),
                round(max / mean), round(min / mean), loads);
    }

    public synchronized MembershipChangeReport addNode(String id, String address) {
        int before = ring.size();
        String[] assignmentsBefore = snapshot();
        if (!ring.addNode(new WorkerNode(id, address))) {
            throw new ConflictException("Worker node already exists: " + id);
        }
        return report("ADD", id, before, ring.size(), assignmentsBefore, snapshot(), before + 1.0);
    }

    public synchronized MembershipChangeReport removeNode(String id) {
        int before = ring.size();
        String[] assignmentsBefore = snapshot();
        if (!ring.removeNodeById(id)) {
            throw new ResourceNotFoundException("Worker node not found: " + id);
        }
        return report("REMOVE", id, before, ring.size(), assignmentsBefore, snapshot(), (double) before);
    }

    // ----------------------------------------------------------------- helpers

    private String[] snapshot() {
        if (ring.size() == 0) {
            return null;
        }
        String[] assignment = new String[MOVEMENT_SAMPLE];
        for (int i = 0; i < MOVEMENT_SAMPLE; i++) {
            assignment[i] = ring.getNode("doc-" + i).id();
        }
        return assignment;
    }

    private MembershipChangeReport report(String operation, String nodeId, int nodesBefore, int nodesAfter,
                                          String[] before, String[] after, double expectedDivisor) {
        if (before == null || after == null) {
            return new MembershipChangeReport(operation, nodeId, nodesBefore, nodesAfter, MOVEMENT_SAMPLE,
                    null, null, null, null, null);
        }
        int movedRing = 0;
        int movedModulo = 0;
        for (int i = 0; i < MOVEMENT_SAMPLE; i++) {
            if (!before[i].equals(after[i])) {
                movedRing++;
            }
            long position = ring.position("doc-" + i);
            if (Math.floorMod(position, (long) nodesBefore) != Math.floorMod(position, (long) nodesAfter)) {
                movedModulo++;
            }
        }
        return new MembershipChangeReport(operation, nodeId, nodesBefore, nodesAfter, MOVEMENT_SAMPLE,
                movedRing, round(100.0 * movedRing / MOVEMENT_SAMPLE), round(100.0 / expectedDivisor),
                movedModulo, round(100.0 * movedModulo / MOVEMENT_SAMPLE));
    }

    private static double round(double value) {
        return Math.round(value * 100.0) / 100.0;
    }
}
