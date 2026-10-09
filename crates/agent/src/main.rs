//! The StatusTick agent as one static binary: settings, protocol, offline buffer, relay, discovery, metrics, browser
//! checks and `doctor`, with the checks of the `statustick-checks` crate. Browser checks
//! need the image's Chromium and Playwright runner (`/runner`); without them the agent reports no browser support.
mod agent;
mod browser;
mod buffer;
mod client;
mod config;
mod database;
#[cfg(test)]
mod docs;
mod doctor;
mod jobs;
mod kubernetes;
mod machine;
mod metrics;
mod relay;
mod schema;
mod servers;
mod settings;

use std::sync::Arc;

use statustick_checks::targets::{TargetPolicy, parse_allow_list, set_target_policy};

use crate::buffer::Log;
use crate::settings::{Env, env_value, process_env};

pub const VERSION: &str = env!("AGENT_VERSION");

fn cannot_start(message: &str) -> ! {
    eprintln!("StatusTick agent cannot start: {message}");
    std::process::exit(1);
}

fn listen_error(error: &std::io::Error) -> String {
    format!("listen {}: {}", statustick_checks::util::io_code(error), error.kind().to_string().to_lowercase())
}

async fn doctor(args: &[String], env: &Env) -> ! {
    let options = match doctor::parse_args(args) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("{message}\n{}", doctor::USAGE);
            std::process::exit(2);
        }
    };
    match parse_allow_list(env_value(env, "STATUSTICK_ALLOW").unwrap_or(""), "STATUSTICK_ALLOW") {
        Ok(allow) => set_target_policy(TargetPolicy { internal: true, allow }),
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    }
    let (passed, text) = doctor::run_doctor(&options, env).await;
    println!("{text}");
    std::process::exit(if passed { 0 } else { 1 });
}

#[tokio::main]
async fn main() {
    let started_at = statustick_checks::util::now_iso();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let env = process_env();
    if args.first().map(String::as_str) == Some("doctor") {
        doctor(&args[1..], &env).await;
    }
    let config = config::read_config(&env).unwrap_or_else(|message| cannot_start(&message));
    let kubernetes = if config.settings.discovery {
        Some(
            kubernetes::KubernetesApi::in_cluster(env_value(&env, "KUBERNETES_SERVICE_HOST"), env_value(&env, "KUBERNETES_SERVICE_PORT"))
                .unwrap_or_else(|message| cannot_start(&message)),
        )
    } else {
        None
    };
    set_target_policy(TargetPolicy { internal: true, allow: config.settings.allow.clone() });
    let log: Log = Arc::new(|line: &str| println!("{line}"));
    let install = config.settings.install.clone();
    let machine_env = env.clone();
    let machine = Box::new(move || {
        let probe =
            machine::Probe { root: "/".into(), total_memory: machine::total_memory(), parallelism: machine::parallelism(), started_at: started_at.clone() };
        machine::read_machine(install.as_deref(), &machine_env, &probe)
    });
    let settings = config.settings.clone();
    let browser = match &config.browser {
        None => None,
        Some(support) => {
            let browsers = env_value(&env, "PLAYWRIGHT_BROWSERS_PATH").unwrap_or("").to_string();
            let (sandbox, line) = browser::sandbox(&settings.browser_isolation, &browsers).await.unwrap_or_else(|message| cannot_start(&message));
            if let Some(line) = line {
                log(&line);
            }
            Some((support.clone(), sandbox))
        }
    };
    let agent = agent::Agent::new(config, log.clone(), machine, browser);

    if let Some(api) = kubernetes {
        let namespaces = Some(settings.discovery_namespaces.clone()).filter(|names| !names.is_empty());
        let changed_agent = agent.clone();
        let discovery = kubernetes::KubernetesDiscovery::new(api, namespaces, Arc::new(move || changed_agent.discovery_soon()), log.clone());
        let desired = discovery.clone();
        agent.use_discovery(Arc::new(move || desired.desired()));
        discovery.start();
    }
    if let Some(port) = settings.health_port {
        let listener = match servers::bind_any(port) {
            Ok(listener) => listener,
            Err(_) => servers::bind("0.0.0.0", port).await.unwrap_or_else(|error| cannot_start(&format!("health port {port}: {}", listen_error(&error)))),
        };
        tokio::spawn(servers::serve(listener, servers::health_router(agent.clone()), None));
    }
    if let Some(port) = settings.metrics_port {
        let host = settings.metrics_host.clone();
        let listener = servers::bind(&host, port).await.unwrap_or_else(|error| cannot_start(&format!("metrics port {host}:{port}: {}", listen_error(&error))));
        tokio::spawn(servers::serve(listener, servers::metrics_router(agent.clone()), None));
    }
    if let Some(port) = settings.relay_port {
        let host = settings.relay_host.clone();
        let listener =
            servers::bind(&host, port).await.unwrap_or_else(|error| cannot_start(&format!("heartbeat relay {host}:{port}: {}", listen_error(&error))));
        let relay_agent = agent.clone();
        let relay: relay::Relay = Arc::new(move |ping_id: &str, kind: &str, run: Option<&str>| relay_agent.relay_ping(ping_id, kind, run));
        tokio::spawn(servers::serve(listener, relay::relay_router(relay), Some(servers::RELAY_MAX_CONNECTIONS)));
    }

    let stopping = agent.clone();
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut interrupt = signal(SignalKind::interrupt()).expect("SIGINT handler");
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
        stopping.stop().await;
        std::process::exit(0);
    });
    agent.run().await;
    std::future::pending::<()>().await;
}
