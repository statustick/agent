//! The agent's configuration from its settings.
use statustick_checks::proxy::{proxy_for, read_proxy_settings};

use crate::settings::{Env, Settings, env_value, machine_settings, read_settings};

pub struct Config {
    pub settings: Settings,
    /// Null without the runner files (outside the image) or with BROWSER_CONCURRENCY=0.
    pub browser: Option<crate::browser::BrowserSupport>,
    pub proxy: Option<url::Url>,
    pub machine_settings: Vec<&'static str>,
}

/// Throws with a message for the operator when a setting is wrong.
pub fn read_config(env: &Env) -> Result<Config, String> {
    let settings = read_settings(env)?;
    let proxy_settings = read_proxy_settings(|name| env_value(env, name).map(str::to_string))?;
    let base = url::Url::parse(&settings.url).map_err(|_| "STATUSTICK_URL is not a valid URL".to_string())?;
    let proxy = proxy_for(&base, &proxy_settings);
    let browser = crate::browser::browser_support(env, std::path::Path::new(crate::browser::RUNNER_DIR))?;
    Ok(Config { settings, browser, proxy, machine_settings: machine_settings(env) })
}
