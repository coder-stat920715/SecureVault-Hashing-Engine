package com.vault.hashing.cluster;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.List;

/** Payloads of the cluster simulator API. */
public final class ClusterDtos {

    private ClusterDtos() {
    }

    public record AddNodeRequest(
            @NotBlank @Pattern(regexp = "^[A-Za-z0-9._-]{1,64}$", message = "1-64 chars: letters, digits, '.', '_' or '-'")
            String id,
            @NotBlank @Size(max = 255) String address) {
    }

    public record RouteResult(String documentId, String ringPositionHex, WorkerNode node, int physicalNodes) {
    }

    public record NodeLoad(String nodeId, String address, int assignedKeys, double sharePercent,
                           double ringOwnershipPercent) {
    }

    public record DistributionReport(int physicalNodes, int virtualNodesPerNode, int totalVirtualNodes,
                                     int sampleSize, double idealSharePercent, double coefficientOfVariationPercent,
                                     double maxLoadOverMean, double minLoadOverMean, List<NodeLoad> nodes) {
    }

    /**
     * Effect of a membership change, measured on a fixed sample of keys and compared with what naive
     * {@code hash % N} placement would have moved. Fields are null when not computable (e.g. empty ring).
     */
    public record MembershipChangeReport(String operation, String nodeId, int nodesBefore, int nodesAfter,
                                         int sampleSize, Integer keysMovedByRing, Double movedPercentByRing,
                                         Double expectedMovedPercent, Integer keysMovedByModulo,
                                         Double movedPercentByModulo) {
    }
}
