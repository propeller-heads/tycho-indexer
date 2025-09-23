use std::time::Duration;

#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum RetryConfiguration {
    Constant(ConstantRetryConfiguration),
    Exponential(ExponentialRetryConfiguration),
}

impl RetryConfiguration {
    pub fn constant(max_attempts: u64, cooldown: Duration) -> Self {
        RetryConfiguration::Constant(ConstantRetryConfiguration { max_attempts, cooldown })
    }

    pub fn exponential(
        initial_interval: Duration,
        randomization_factor: f64,
        multiplier: f64,
        max_interval: Duration,
        max_elapsed_time: Option<Duration>,
    ) -> Self {
        RetryConfiguration::Exponential(ExponentialRetryConfiguration::new(
            initial_interval,
            randomization_factor,
            multiplier,
            max_interval,
            max_elapsed_time,
        ))
    }
}

#[derive(Clone, Debug)]
pub struct ConstantRetryConfiguration {
    max_attempts: u64,
    cooldown: Duration,
}

impl ConstantRetryConfiguration {
    pub fn max_attempts(&self) -> u64 {
        self.max_attempts
    }

    pub fn cooldown(&self) -> Duration {
        self.cooldown
    }
}

#[derive(Clone, Debug)]
pub struct ExponentialRetryConfiguration {
    initial_interval: Duration,
    randomization_factor: f64,
    multiplier: f64,
    max_interval: Duration,
    max_elapsed_time: Option<Duration>,
}

impl ExponentialRetryConfiguration {
    pub fn new(
        initial_interval: Duration,
        randomization_factor: f64,
        multiplier: f64,
        max_interval: Duration,
        max_elapsed_time: Option<Duration>,
    ) -> Self {
        Self { initial_interval, randomization_factor, multiplier, max_interval, max_elapsed_time }
    }
    pub fn initial_interval(&self) -> Duration {
        self.initial_interval
    }

    pub fn randomization_factor(&self) -> f64 {
        self.randomization_factor
    }

    pub fn multiplier(&self) -> f64 {
        self.multiplier
    }

    pub fn max_interval(&self) -> Duration {
        self.max_interval
    }

    pub fn max_elapsed_time(&self) -> Option<Duration> {
        self.max_elapsed_time
    }
}
