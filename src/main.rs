// https://tools.ietf.org/rfc/rfc5128.txt
// https://blog.csdn.net/bytxl/article/details/44344855

use flexi_logger::*;
use hbb_common::{bail, config::RENDEZVOUS_PORT, ResultType};
use hbbs::{common::*, *};

const RMEM: usize = 0;

fn main() -> ResultType<()> {
    let _logger = Logger::try_with_env_or_str("info")?
        .log_to_stdout()
        .format(opt_format)
        .write_mode(WriteMode::Async)
        .start()?;
    let args = format!(
        "-c --config=[FILE] +takes_value 'Sets a custom config file'
        -b, --bind=[IP] 'Sets the IP address to bind to (default: all interfaces)'
        -p, --port=[NUMBER(default={RENDEZVOUS_PORT})] 'Sets the listening port'
        -s, --serial=[NUMBER(default=0)] '[DEPRECATED] Sets configure update serial number'
        -R, --rendezvous-servers=[HOSTS] '[DEPRECATED] Sets rendezvous servers, separated by comma'
        -u, --software-url=[URL] '[DEPRECATED] Sets download url of RustDesk software of newest version'
        -r, --relay-servers=[HOST] 'Sets the default relay servers, separated by comma'
        -M, --rmem=[NUMBER(default={RMEM})] 'Sets UDP recv buffer size, set system rmem_max first, e.g., sudo sysctl -w net.core.rmem_max=52428800. vi /etc/sysctl.conf, net.core.rmem_max=52428800, sudo sysctl –p'
        , --mask=[MASK] '[DEPRECATED] Determine if the connection comes from LAN, e.g. 192.168.0.0/16'
        -k, --key=[KEY] 'Only allow the client with the same key'
        , --auth-api-url=[URL] 'Base URL of the auth API. Setting it turns connection authorization on'
        , --auth-api-secret=[SECRET] 'Shared secret sent as x-hbbs-secret. Must differ from --key'
        , --auth-required=[Y/N] 'Force authorization on or off (default: on when --auth-api-url is set)'
        , --auth-fail-open=[Y/N(default=N)] 'UNSUPPORTED. Broker connections when the auth API is unreachable'
        , --auth-timeout-ms=[NUMBER(default=300)] 'How long to wait for an authorization decision'
        , --auth-cache-ttl-ms=[NUMBER(default=5000)] 'How long a positive decision may be reused'
        , --broker-verify=[Y/N(default=Y)] 'Require a punch/relay response to come from the peer hbbs actually brokered'
        , --broker-strict-ip=[Y/N(default=N)] 'Also require that response to arrive from the registered IP of that peer. Breaks dual-stack and CGNAT peers'
        , --breakglass-pubkey=[BASE64] 'Ed25519 public key that signs break-glass capabilities. Setting it arms the emergency path'
        , --breakglass-max-ttl-sec=[NUMBER(default=14400)] 'Refuse a capability valid for longer than this'
        , --breakglass-rate-per-minute=[NUMBER(default=10)] 'Break-glass verification attempts allowed per source IP per minute'
        , --breakglass-audit-log=[FILE] 'Local append-only record of every break-glass use, written and fsynced before the connection is allowed'
        , --breakglass-audit-required=[Y/N(default=Y)] 'Refuse a break-glass use that cannot be written to that file'
        , --breakglass-reconcile-sec=[NUMBER(default=60)] 'How often to replay unacknowledged break-glass records to the auth API'",
    );
    init_args(&args, "hbbs", "RustDesk ID/Rendezvous Server");
    // Read and validated before anything binds a port. A misconfiguration here
    // would otherwise surface as a fleet that cannot connect, with the reason
    // visible only per-connection — so it is a boot-time refusal instead
    // (T3.1, decision D1).
    let auth_config = auth::AuthConfig::from_args()?;
    auth_config.log();
    // T3.8. Read here for the same reason, though nothing in it can fail: an
    // operator who typed `BROKER_STRICT_IP` wants to see it echoed at boot, and
    // the one line it logs is the only place the resolved value is visible.
    let broker_config = broker::BrokerConfig::from_args()?;
    broker_config.log();
    let port = get_arg_or("port", RENDEZVOUS_PORT.to_string()).parse::<i32>()?;
    if port < 3 {
        bail!("Invalid port");
    }
    let bind_addr = parse_bind_address(&get_arg("bind"))?;
    let rmem = get_arg("rmem").parse::<usize>().unwrap_or(RMEM);
    let serial: i32 = get_arg("serial").parse().unwrap_or(0);
    crate::common::check_software_update();
    RendezvousServer::start_with_bind(
        bind_addr,
        port,
        serial,
        &get_arg_or("key", "-".to_owned()),
        rmem,
        auth_config,
        broker_config,
    )?;
    Ok(())
}
