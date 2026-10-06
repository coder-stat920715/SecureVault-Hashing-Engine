package com.vault.hashing.controller;

import com.vault.hashing.cluster.ClusterDtos.AddNodeRequest;
import com.vault.hashing.cluster.ClusterDtos.DistributionReport;
import com.vault.hashing.cluster.ClusterDtos.MembershipChangeReport;
import com.vault.hashing.cluster.ClusterDtos.RouteResult;
import com.vault.hashing.cluster.ClusterService;
import com.vault.hashing.cluster.WorkerNode;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Use case 6: consistent-hashing cluster simulator. Node add/remove is open to any authenticated user because
 * this is a teaching simulator; restrict it to an admin role in a real deployment.
 */
@RestController
@RequestMapping("/api/cluster")
@RequiredArgsConstructor
public class ClusterController {

    private final ClusterService clusterService;

    @GetMapping("/route-document/{documentId}")
    public RouteResult route(@PathVariable String documentId) {
        return clusterService.route(documentId);
    }

    @GetMapping("/node-distribution")
    public DistributionReport distribution(@RequestParam(defaultValue = "10000") int sampleSize) {
        return clusterService.distribution(sampleSize);
    }

    @GetMapping("/nodes")
    public List<WorkerNode> nodes() {
        return clusterService.nodes();
    }

    @PostMapping("/nodes")
    public ResponseEntity<MembershipChangeReport> addNode(@Valid @RequestBody AddNodeRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(clusterService.addNode(request.id(), request.address()));
    }

    @DeleteMapping("/nodes/{nodeId}")
    public MembershipChangeReport removeNode(@PathVariable String nodeId) {
        return clusterService.removeNode(nodeId);
    }
}
