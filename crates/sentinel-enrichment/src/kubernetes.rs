use dashmap::DashMap;
use std::collections::HashMap;

/// Kubernetes metadata for a pod
#[derive(Debug, Clone)]
pub struct PodMetadata {
    pub name: String,
    pub namespace: String,
    pub deployment: Option<String>,
    pub service: Option<String>,
    pub labels: HashMap<String, String>,
}

/// Kubernetes metadata enricher
pub struct KubernetesEnricher {
    cache: DashMap<String, PodMetadata>,
}

impl KubernetesEnricher {
    /// Create a new enricher
    pub fn new() -> Self {
        Self { cache: DashMap::new() }
    }

    /// Enrich an IP address with Kubernetes metadata
    pub fn enrich(&self, ip: &str) -> Option<PodMetadata> {
        self.cache.get(ip).map(|r| r.value().clone())
    }

    /// Update cache with new pod metadata
    pub fn update(&self, ip: String, metadata: PodMetadata) {
        self.cache.insert(ip, metadata);
    }

    /// Get cache size
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}

impl Default for KubernetesEnricher {
    fn default() -> Self {
        Self::new()
    }
}
