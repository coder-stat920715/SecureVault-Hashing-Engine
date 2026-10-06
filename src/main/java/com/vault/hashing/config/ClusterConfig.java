package com.vault.hashing.config;

import com.vault.hashing.cluster.ConsistentHashRing;
import com.vault.hashing.cluster.RingHashFunctions;
import com.vault.hashing.cluster.WorkerNode;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.function.ToLongFunction;

@Configuration
public class ClusterConfig {

    /** The single ring instance shared by the cluster simulator, pre-populated with the configured workers. */
    @Bean
    public ConsistentHashRing<WorkerNode> workerRing(VaultProperties properties) {
        VaultProperties.Cluster cfg = properties.getCluster();
        ToLongFunction<String> hash = switch (cfg.getHashFunction()) {
            case MD5 -> RingHashFunctions.md5();
            case MURMUR3 -> RingHashFunctions.murmur3();
        };
        ConsistentHashRing<WorkerNode> ring = new ConsistentHashRing<>(cfg.getVirtualNodes(), hash);
        int index = 1;
        for (String id : cfg.getInitialNodes()) {
            ring.addNode(new WorkerNode(id.trim(), "10.0.0." + index + ":9000"));
            index++;
        }
        return ring;
    }
}
