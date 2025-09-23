use std::{error::Error, fmt::Debug, hash::Hash, sync::Arc};

use futures03::Future;
use metrics::counter;
use mini_moka::sync::Cache;
use tracing::{instrument, trace, Level};
use tycho_common::traits::MemorySize;

pub struct RpcCache<R, V> {
    name: String,
    cache: Arc<Cache<R, Arc<tokio::sync::Mutex<Option<V>>>>>,
}

type Weigher<R, V> =
    Box<dyn Fn(&R, &Arc<tokio::sync::Mutex<Option<V>>>) -> u32 + Send + Sync + 'static>;

pub struct RpcCacheBuilder<R, V> {
    name: String,
    capacity: u64,
    ttl: u64,
    weigher: Option<Weigher<R, V>>,
}

impl<R, V> RpcCacheBuilder<R, V>
where
    R: Clone + Hash + Eq + Send + Sync + Debug + 'static,
    V: Clone + Send + Sync + 'static,
{
    pub fn new(name: &str, capacity: u64, ttl: u64) -> Self {
        Self { name: name.to_string(), capacity, ttl, weigher: None }
    }

    /// Convenience method for values that implement MemorySize
    pub fn with_memory_size(mut self) -> Self
    where
        V: MemorySize,
    {
        self.weigher = Some(Box::new(|_key, value_wrapper| {
            if let Ok(guard) = value_wrapper.try_lock() {
                if let Some(value) = guard.as_ref() {
                    return value
                        .memory_size()
                        .try_into()
                        .unwrap_or(u32::MAX); // We stay conservative if it overflows u32
                }
            }
            // Conservative size if we can't lock or there's no value
            u32::MAX
        }));
        self
    }

    pub fn build(self) -> RpcCache<R, V> {
        let mut cache_builder = Cache::builder()
            .time_to_live(std::time::Duration::from_secs(self.ttl))
            .max_capacity(self.capacity);

        if let Some(weigher) = self.weigher {
            cache_builder = cache_builder.weigher(weigher);
        }

        let cache = Arc::new(cache_builder.build());
        RpcCache { name: self.name, cache }
    }
}

impl<R, V> RpcCache<R, V>
where
    R: Clone + Hash + Eq + Send + Sync + Debug + 'static,
    V: Clone + Send + Sync + 'static,
{
    pub fn new(name: &str, capacity: u64, ttl: u64) -> Self {
        let cache = Arc::new(
            Cache::builder()
                .max_capacity(capacity)
                .time_to_live(std::time::Duration::from_secs(ttl))
                .build(),
        );
        Self { name: name.to_string(), cache }
    }

    pub fn builder(name: &str, capacity: u64, ttl: u64) -> RpcCacheBuilder<R, V> {
        RpcCacheBuilder::new(name, capacity, ttl)
    }

    #[instrument(
        name = "rpc.cache.get",
        level = Level::TRACE,
        fields(miss, should_cache, size, resource = self.name),
        skip(self, fallback))
    ]
    pub async fn get<
        'a,
        E: Error,
        Fut: Future<Output = Result<(V, bool), E>> + Send + 'a,
        F: Fn(R) -> Fut + Send + Sync,
    >(
        &'a self,
        request: R,
        fallback: F,
    ) -> Result<V, E> {
        tracing::Span::current().record("size", self.cache.entry_count());
        // Check the cache for a cached response
        if let Some(inflight_val) = self.cache.get(&request) {
            // the value is present or is being written to
            // If the values is None, we likely hit a should_cache = false entry while in-flight,
            //  so we simply behave as if it was a cache miss.
            if let Some(res) = inflight_val.lock().await.clone() {
                tracing::Span::current().record("miss", false);
                trace!("CacheHit");
                counter!("rpc_cache_hits", "cache" => self.name.clone()).increment(1);

                return Ok(res);
            }
        }

        // the value has never been written
        tracing::Span::current().record("miss", true);
        trace!("CacheMiss");
        counter!("rpc_cache_misses", "cache" => self.name.clone()).increment(1);

        let lock = Arc::new(tokio::sync::Mutex::new(None));
        let mut guard = lock.lock().await;
        // We insert a None value here to indicate that this request is in flight.
        //  In some cases this None value may leak to the reading part above, e.g.
        //  if the fallback failed or if the value is not safe to be cached.
        self.cache
            .insert(request.clone(), lock.clone());
        let (response, should_cache) = (fallback)(request.clone())
            .await
            .inspect_err(|_| {
                // invalidate the cache if the fallback errors
                self.cache.invalidate(&request);
                trace!("FallbackFailure");
            })?;

        // PERF: unnecessary lock if we don't cache the value, could be improved
        //  if `should_cache` value can be determined beforehand.
        if should_cache {
            tracing::Span::current().record("should_cache", true);
            *guard = Some(response.clone());
            trace!("EntrySaved")
        } else {
            self.cache.invalidate(&request);
        }
        Ok(response)
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use futures03::future::try_join_all;
    use tokio::sync::Mutex;

    use crate::services::{cache::RpcCache, rpc::RpcError};

    #[test_log::test(tokio::test)]
    async fn test_sequential_access() {
        let access_counter = Arc::new(Mutex::new(0));
        let cache = RpcCache::<String, i32>::new("test", 100, 3600);

        cache
            .get("k0".to_string(), |_| async { increment_counter(access_counter.clone()).await })
            .await
            .unwrap();

        cache
            .get("k0".to_string(), |_| async { increment_counter(access_counter.clone()).await })
            .await
            .unwrap();

        let v = *access_counter.lock().await;
        assert_eq!(v, 1);
    }

    async fn increment_counter(access_counter: Arc<Mutex<i32>>) -> Result<(i32, bool), RpcError> {
        let mut guard = access_counter.lock().await;
        *guard += 1;
        Ok((1, true))
    }

    #[test_log::test(tokio::test)]
    async fn test_parallel_access() {
        let access_counter = Arc::new(Mutex::new(0));
        let cache = RpcCache::<String, i32>::new("test", 100, 3600);
        let tasks: Vec<_> = (0..10)
            .map(|_| {
                cache.get("k0".to_string(), |_| async {
                    increment_counter(access_counter.clone()).await
                })
            })
            .collect();

        try_join_all(tasks)
            .await
            .expect("a task failed");

        let v = *access_counter.lock().await;
        assert_eq!(v, 1);
    }

    async fn increment_counter_unsafe_value(
        access_counter: Arc<Mutex<i32>>,
    ) -> Result<(i32, bool), RpcError> {
        let mut guard = access_counter.lock().await;
        *guard += 1;
        Ok((1, false))
    }

    #[test_log::test(tokio::test)]
    async fn test_parallel_access_unsafe_cache() {
        let access_counter = Arc::new(Mutex::new(0));
        let cache = RpcCache::<usize, i32>::new("test", 100, 3600);
        let tasks: Vec<_> = (0..10)
            .map(|i| {
                cache.get(i % 2, |_| async {
                    increment_counter_unsafe_value(access_counter.clone()).await
                })
            })
            .collect();

        try_join_all(tasks)
            .await
            .expect("a task failed");

        let v = *access_counter.lock().await;
        assert_eq!(v, 10);
    }
}
