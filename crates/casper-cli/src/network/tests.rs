use clap::Parser;

use super::*;

#[test]
fn networks_without_unused_endpoints_can_be_selected_and_saved() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    fs::write(
        &path,
        r#"
active = "minimal"

[storage]
type = "keyring"

[networks.minimal]
chain_name = "minimal-chain"
sse = "https://minimal.invalid/events"
rpc = "https://minimal.invalid/rpc"

[networks.empty]
chain_name = "empty-chain"
rest = ""
sse = "https://empty.invalid/events"
rpc = "https://empty.invalid/rpc"
binary_port = ""
"#,
    )
    .unwrap();
    let context = ConfigContext::new(path.clone(), ConfigInitOptions::default());
    handle(
        &context,
        NetworkArgs {
            command: NetworkCommand::List,
        },
    )
    .unwrap();
    for name in ["empty", "minimal"] {
        let cli = crate::Cli::try_parse_from(["casper-cli", "network", "use", name]).unwrap();
        let crate::Command::Network(args) = cli.command else {
            panic!("expected network command")
        };
        handle(&context, args).unwrap();
        assert_eq!(
            active_network_rpc(&context).unwrap(),
            (name.into(), format!("https://{name}.invalid/rpc"))
        );
        assert_eq!(
            active_network_chain_name(&context).unwrap(),
            format!("{name}-chain")
        );
    }
    // Switching networks must not synthesize unused endpoints when resaving.
    let saved: toml::Value = toml::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let networks = &saved["networks"];
    assert!(networks["minimal"].get("rest").is_none());
    assert!(networks["minimal"].get("binary_port").is_none());
    assert_eq!(networks["empty"]["rest"].as_str(), Some(""));
    assert_eq!(networks["empty"]["binary_port"].as_str(), Some(""));
}
