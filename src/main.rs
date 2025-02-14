use clap::{Error, Parser, error::ErrorKind};
use default_net::Interface;
use default_net::ip::IpNet;
use default_net::ip::Ipv4Net;
use default_net::ip::Ipv6Net;
use ipnetwork::IpNetwork;
use itertools::join;
use std::{
    net::IpAddr,
    str::FromStr,
    sync::{Arc, OnceLock},
    time::{Duration, SystemTime},
};
use tokio::{net::TcpStream, task::JoinSet};

const DEFAULT_PORTS: [u16; 2] = [80, 443];
const TIMEOUT_DELAY: u64 = 500;
const MIN_PREFIX: u8 = 24;

#[derive(Parser)]
#[command(about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = TIMEOUT_DELAY)]
    timeout: u64,
    #[arg(long, default_value_t = false)]
    exclude_gateway: bool,
    #[arg(short, long, default_values_t = DEFAULT_PORTS, value_delimiter = ',')]
    ports: Vec<u16>,
    #[arg(value_parser = from_str_to_ipnet)]
    ip: Option<IpNet>,
}

#[tokio::main]
async fn main() {
    let now = SystemTime::now();
    let args = Args::parse();

    let Some(IpAddr::V4(local_ip)) = default_net::interface::get_local_ipaddr() else {
        return;
    };

    println!("IP: {}", local_ip);
    let (interface, ipnet) = match args.ip {
        Some(ip) => find_local_if_ip(ip).unwrap_or((find_local_if().expect("error").0, ip)),
        None => find_local_if().expect("error"),
    };
    let network =
        IpNetwork::new(ipnet.addr(), ipnet.prefix_len()).expect("incorrect ip or netmask");
    let gateway = interface.gateway.as_ref().map(|gateway| gateway.ip_addr);
    let hosts_count = {
        let mut count = u128::from(network.size());
        if let Some(gateway) = gateway {
            println!("Gateway IP: {gateway:?}");
            count -= (args.exclude_gateway && network.contains(gateway)) as u128;
        }
        count
    };

    println!();
    println!("Broadcast IP: {}", ipnet.broadcast());
    println!("Prefix Length: {}", ipnet.prefix_len());
    println!("Number of hosts: {}", hosts_count);
    println!();
    println!(
        "Scanning hosts in the network: {}/{}",
        ipnet.network(),
        ipnet.prefix_len(),
    );
    println!("Scanning for ports: {}", join(args.ports.iter(), ", "));
    println!();

    let ports = Arc::new(args.ports);
    let mut set = JoinSet::<Option<()>>::new();

    let addresses = network
        .iter()
        .filter(|ipaddr| *ipaddr != local_ip)
        .filter(|ipaddr| {
            !args.exclude_gateway
                || interface
                    .gateway
                    .as_ref()
                    .is_none_or(|gate| gate.ip_addr != *ipaddr)
        });

    static PRINTED: OnceLock<()> = OnceLock::new();
    for ipaddr in addresses {
        let ports = ports.clone();
        set.spawn(async move {
            let ports = ping_ports(ipaddr, &ports, args.timeout).await;
            if ports.is_empty() {
                return None;
            }
            if PRINTED.get().is_none() {
                let _ = PRINTED.set(());
                println!("Search results:");
            }

            println!(
                "Open ports on {ipaddr}{}: {}",
                gateway
                    .filter(|gateway| *gateway == ipaddr)
                    .map_or("", |_| " [Default Gateway]"),
                ports
                    .iter()
                    .map(|port| port.to_string())
                    .collect::<Vec<String>>()
                    .join(", "),
            );
            Some(())
        });
    }

    let mut responses: u32 = 0;
    while let Some(Ok(success)) = set.join_next().await {
        responses += success.map_or(0, |_| 1);
    }

    println!();
    println!("Scan complete:");
    println!("Total hosts scanned: {}", hosts_count);
    println!("Hosts responding: {}", responses);
    println!(
        "Total time taken: {:.2?} secs",
        now.elapsed().unwrap().as_secs_f64()
    );
}

async fn ping_ports(ip: IpAddr, ports: &[u16], timeout: u64) -> Box<[u16]> {
    let mut set = JoinSet::<Option<u16>>::new();
    for port in ports.iter().copied() {
        set.spawn(async move {
            if ping_port(ip, port, timeout).await {
                return Some(port);
            }
            None
        });
    }

    let mut ports: Vec<u16> = Vec::new();
    while let Some(Ok(option)) = set.join_next().await {
        let Some(port) = option else {
            continue;
        };
        ports.push(port);
    }
    ports.into_boxed_slice()
}

async fn ping_port(ip: IpAddr, port: u16, timeout: u64) -> bool {
    matches!(
        tokio::time::timeout(
            Duration::from_millis(timeout),
            TcpStream::connect((ip, port)),
        )
        .await,
        Ok(Ok(_))
    )
}

fn find_local_if() -> Result<(default_net::interface::Interface, IpNet), String> {
    let interface = default_net::interface::get_default_interface()?;
    let ip = default_net::interface::get_local_ipaddr().ok_or("couldn't find ip")?;

    match ip {
        IpAddr::V4(ip) => interface
            .ipv4
            .iter()
            .copied()
            .find(|addr| addr.addr == ip)
            .map(|addr| IpNet::V4(addr))
            .map(|addr| (interface, addr))
            .ok_or("couldn't find ip".to_string()),
        IpAddr::V6(ip) => interface
            .ipv6
            .iter()
            .copied()
            .find(|addr| addr.addr == ip)
            .map(|addr| IpNet::V6(addr))
            .map(|addr| (interface, addr))
            .ok_or("couldn't find ip".to_string()),
    }
}

fn find_local_if_ip(ipnet: IpNet) -> Result<(default_net::interface::Interface, IpNet), String> {
    let interfaces = default_net::interface::get_interfaces();
    match ipnet {
        IpNet::V4(ip) => interfaces
            .into_iter()
            .find_map(|interface| contains_net(interface, ip))
            .map(|(interface, ipnet)| (interface, IpNet::V4(ipnet)))
            .ok_or(format!("couldn't find interface for ip: {ip}")),
        IpNet::V6(ip) => interfaces
            .into_iter()
            .find_map(|interface| contains_net_v6(interface, ip))
            .map(|(interface, ipnet)| (interface, IpNet::V6(ipnet)))
            .ok_or(format!("couldn't find interface for ip: {ip}")),
    }
}

fn from_str_to_ipnet(str: &str) -> Result<IpNet, String> {
    let invalid_value = || Error::new(ErrorKind::InvalidValue).to_string();

    let mut splits = str.split('/');
    let (Some(before), after, None) = (splits.next(), splits.next(), splits.next()) else {
        let err = clap::Error::new(ErrorKind::Format);
        return Err(err.to_string());
    };

    let ip = IpAddr::from_str(before).map_err(|_| invalid_value())?;
    let prefix = after
        .map(u8::from_str)
        .unwrap_or(Ok(32))
        .map_err(|err| err.to_string())?;

    Ok(IpNet::new(ip, std::cmp::max(prefix, MIN_PREFIX)))
}

fn contains_net(interface: Interface, ipnet: Ipv4Net) -> Option<(Interface, Ipv4Net)> {
    interface
        .ipv4
        .iter()
        .copied()
        .find(|addr| {
            let iter1 = {
                let mut iter = addr.addr.octets().into_iter().rev();
                iter.next();
                iter
            };
            let iter2 = {
                let mut iter = ipnet.addr.octets().into_iter().rev();
                iter.next();
                iter
            };

            iter1.zip(iter2).all(|(a, b)| a == b)
        })
        .map(|_| (interface, ipnet))
}
fn contains_net_v6(interface: Interface, ipnet: Ipv6Net) -> Option<(Interface, Ipv6Net)> {
    interface
        .ipv6
        .iter()
        .copied()
        .find(|addr| {
            let iter1 = {
                let mut iter = addr.addr.octets().into_iter().rev();
                iter.next();
                iter
            };
            let iter2 = {
                let mut iter = ipnet.addr.octets().into_iter().rev();
                iter.next();
                iter
            };

            iter1.zip(iter2).all(|(a, b)| a == b)
        })
        .map(|_| (interface, ipnet))
}
