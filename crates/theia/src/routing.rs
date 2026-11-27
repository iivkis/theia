//! Shared route matching primitives for server and client.
//! No DNS, transport, file I/O or implicit bypass occurs in this module.
pub(crate) mod carrier_socket;
pub(crate) mod client_state;
#[cfg(target_os = "linux")]
pub mod dns_attribution;
pub(crate) mod dpi;
pub(crate) mod exchange;
pub(crate) mod flow;
pub mod geodata;
#[cfg(target_os = "linux")]
pub mod linux_attribution;
#[cfg(all(target_os = "linux", feature = "linux-ebpf-lab"))]
pub mod linux_bpf_loader;
#[cfg(target_os = "linux")]
pub mod linux_carrier;
#[cfg(target_os = "linux")]
pub mod linux_events;
#[cfg(target_os = "linux")]
pub mod linux_ingress;
#[cfg(target_os = "linux")]
pub mod linux_rules;
#[cfg(target_os = "linux")]
pub mod nfqueue;
pub mod packet;
pub mod packet_modify;
#[cfg(any(target_os = "windows", test))]
pub mod windivert;
mod settings;
pub mod snapshot;
#[cfg(any(target_os = "windows", test))]
mod wfp_context;
#[cfg(any(target_os = "windows", test))]
pub(crate) mod wfp_datagram;
#[cfg(target_os = "windows")]
pub mod wfp_ingress;
#[cfg(target_os = "windows")]
pub mod wfp_udp;
pub use settings::Settings;

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub const GEOSITE_URL: &str =
    "https://github.com/XTLS/Xray-rules-dat/releases/latest/download/geosite.dat";
pub const GEOIP_URL: &str =
    "https://github.com/XTLS/Xray-rules-dat/releases/latest/download/geoip-lite.dat";
const MAX_DAT: usize = 256 * 1024 * 1024;
const MAX_RULES: usize = 1024;
const MAX_SELECTORS: usize = 8192;
const MAX_ENTRIES: usize = 2_000_000;
const MAX_REGEXES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    #[serde(rename = "direct_via_client")]
    Direct,
    #[serde(rename = "blackhole")]
    Blocked,
    #[serde(rename = "proxy_via_server")]
    Allowed,
    #[serde(rename = "direct_via_client_anti_dpi")]
    DirectDpi,
}

/// Actual engine action, independent of the configured rule name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketAction {
    Pass,
    Modify,
    Redirect,
    Drop,
}

/// Missing evidence is not the same as a proven absent attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence<T> {
    Known(T),
    Absent,
    Unknown,
}

/// The ordered policy may need more evidence before any egress is authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    Matched(Action),
    Default,
    Unresolved,
}

impl Classification {
    pub fn action(self) -> Option<Action> {
        match self {
            Self::Matched(action) => Some(action),
            Self::Default => Some(Action::Allowed),
            Self::Unresolved => None,
        }
    }
}

impl Action {
    /// Canonical v1 routing names shared by config, snapshots and UI.
    pub const ALL: [Self; 4] = [Self::Allowed, Self::Direct, Self::Blocked, Self::DirectDpi];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Direct => "direct_via_client",
            Self::Blocked => "blackhole",
            Self::Allowed => "proxy_via_server",
            Self::DirectDpi => "direct_via_client_anti_dpi",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|action| action.name() == name)
    }

    pub fn packet_action(self) -> PacketAction {
        match self {
            Self::Direct => PacketAction::Pass,
            Self::DirectDpi => PacketAction::Modify,
            Self::Allowed => PacketAction::Redirect,
            Self::Blocked => PacketAction::Drop,
        }
    }

    /// Server fallback is allowed only for a route that explicitly permits it.
    pub(crate) fn permits_server_egress(self) -> bool {
        matches!(self, Self::Allowed | Self::DirectDpi)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    pub action: Action,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applications: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingError {
    InvalidRule,
    InvalidDomain,
    InvalidIp,
    InvalidApplication,
    InvalidCategory,
    MissingCategory,
    InvalidDat,
    Limit,
}

impl std::fmt::Display for RoutingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "routing: {self:?}")
    }
}
impl std::error::Error for RoutingError {}

pub(crate) fn domain_name(value: &str) -> Result<String, RoutingError> {
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty()
        || value.len() > 253
        || value.parse::<IpAddr>().is_ok()
        || !value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(RoutingError::InvalidDomain);
    }
    Ok(value.to_ascii_lowercase())
}

fn category(value: &str) -> Result<String, RoutingError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
    {
        return Err(RoutingError::InvalidCategory);
    }
    Ok(value.to_ascii_uppercase())
}

#[derive(Debug, Clone, Copy)]
struct Cidr {
    address: IpAddr,
    prefix: u32,
}
impl Cidr {
    fn new(address: IpAddr, prefix: u32) -> Result<Self, RoutingError> {
        let bits = if address.is_ipv4() { 32 } else { 128 };
        if prefix > bits {
            return Err(RoutingError::InvalidIp);
        }
        Ok(Self { address, prefix })
    }

    fn parse(value: &str) -> Result<Self, RoutingError> {
        let (ip, prefix) = match value.split_once('/') {
            Some((ip, prefix)) => (
                ip,
                Some(prefix.parse::<u32>().map_err(|_| RoutingError::InvalidIp)?),
            ),
            None => (value, None),
        };
        let address = ip.parse::<IpAddr>().map_err(|_| RoutingError::InvalidIp)?;
        Self::new(
            address,
            prefix.unwrap_or(if address.is_ipv4() { 32 } else { 128 }),
        )
    }

    fn matches(self, ip: IpAddr) -> bool {
        match (self.address, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                self.prefix == 0 || (u32::from(a) ^ u32::from(b)) >> (32 - self.prefix) == 0
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                self.prefix == 0 || (u128::from(a) ^ u128::from(b)) >> (128 - self.prefix) == 0
            }
            _ => false,
        }
    }
}

#[derive(Debug)]
enum DomainPattern {
    Full(String),
    Suffix(String),
    Substring(String),
    Regex(Regex),
}
impl DomainPattern {
    fn matches(&self, host: &str) -> bool {
        match self {
            Self::Full(name) => name == host,
            Self::Suffix(name) => {
                host == name
                    || host
                        .strip_suffix(name.as_str())
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }
            Self::Substring(value) => host.contains(value.as_str()),
            Self::Regex(regex) => regex.is_match(host),
        }
    }
}

#[derive(Debug, Default)]
struct DomainCategory {
    full: HashSet<String>,
    suffix: HashSet<String>,
    other: Vec<DomainPattern>,
}
impl DomainCategory {
    fn insert(&mut self, pattern: DomainPattern) {
        match pattern {
            DomainPattern::Full(name) => {
                self.full.insert(name);
            }
            DomainPattern::Suffix(name) => {
                self.suffix.insert(name);
            }
            other => self.other.push(other),
        }
    }
    fn is_empty(&self) -> bool {
        self.full.is_empty() && self.suffix.is_empty() && self.other.is_empty()
    }
    fn matches(&self, host: &str) -> bool {
        self.full.contains(host)
            || self.suffix.contains(host)
            || host
                .match_indices('.')
                .any(|(index, _)| self.suffix.contains(&host[index + 1..]))
            || self.other.iter().any(|p| p.matches(host))
    }
}

#[derive(Debug)]
struct IpCategory {
    v4: Vec<(u128, u128)>,
    v6: Vec<(u128, u128)>,
    reverse: bool,
}

fn merge_ranges(mut ranges: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u128, u128)> = Vec::new();
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut() {
            if start <= last.1.saturating_add(1) {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}
fn range_contains(ranges: &[(u128, u128)], ip: u128) -> bool {
    let position = ranges.partition_point(|(start, _)| *start <= ip);
    position > 0 && ip <= ranges[position - 1].1
}
impl IpCategory {
    fn new(cidrs: Vec<Cidr>, reverse: bool) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for cidr in cidrs {
            match cidr.address {
                IpAddr::V4(ip) => {
                    let mask = if cidr.prefix == 0 {
                        0
                    } else {
                        u32::MAX << (32 - cidr.prefix)
                    };
                    let start = u32::from(ip) & mask;
                    v4.push((u128::from(start), u128::from(start | !mask)));
                }
                IpAddr::V6(ip) => {
                    let mask = if cidr.prefix == 0 {
                        0
                    } else {
                        u128::MAX << (128 - cidr.prefix)
                    };
                    let start = u128::from(ip) & mask;
                    v6.push((start, start | !mask));
                }
            }
        }
        Self {
            v4: merge_ranges(v4),
            v6: merge_ranges(v6),
            reverse,
        }
    }
    fn matches(&self, ip: IpAddr) -> bool {
        let contained = match ip {
            IpAddr::V4(ip) => range_contains(&self.v4, u128::from(u32::from(ip))),
            IpAddr::V6(ip) => range_contains(&self.v6, u128::from(ip)),
        };
        contained != self.reverse
    }
}

// Only protobuf wire types used by the Xray geodata schema are accepted.
// Every read is bounds checked, including length and varint overflow.
enum Field<'a> {
    Number(u64),
    Bytes(&'a [u8]),
    Other,
}
struct Wire<'a>(&'a [u8]);
impl<'a> Wire<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], RoutingError> {
        if n > self.0.len() {
            return Err(RoutingError::InvalidDat);
        }
        let (value, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(value)
    }
    fn varint(&mut self) -> Result<u64, RoutingError> {
        let mut result = 0u64;
        for shift in (0..=63).step_by(7) {
            let byte = self.take(1)?[0];
            if shift == 63 && byte > 1 {
                return Err(RoutingError::InvalidDat);
            }
            result |= u64::from(byte & 127) << shift;
            if byte & 128 == 0 {
                return Ok(result);
            }
        }
        Err(RoutingError::InvalidDat)
    }
    fn next(&mut self) -> Result<Option<(u32, Field<'a>)>, RoutingError> {
        if self.0.is_empty() {
            return Ok(None);
        }
        let tag = self.varint()?;
        let number = u32::try_from(tag >> 3).map_err(|_| RoutingError::InvalidDat)?;
        if number == 0 || number >= (1 << 29) {
            return Err(RoutingError::InvalidDat);
        }
        let value = match tag & 7 {
            0 => Field::Number(self.varint()?),
            1 => {
                self.take(8)?;
                Field::Other
            }
            2 => {
                let n = usize::try_from(self.varint()?).map_err(|_| RoutingError::InvalidDat)?;
                Field::Bytes(self.take(n)?)
            }
            5 => {
                self.take(4)?;
                Field::Other
            }
            _ => return Err(RoutingError::InvalidDat),
        };
        Ok(Some((number, value)))
    }
}

fn utf8(bytes: &[u8]) -> Result<&str, RoutingError> {
    std::str::from_utf8(bytes).map_err(|_| RoutingError::InvalidDat)
}

fn entry_code(bytes: &[u8]) -> Result<String, RoutingError> {
    let mut wire = Wire(bytes);
    let mut code = None;
    while let Some((field, value)) = wire.next()? {
        if field == 1 {
            match value {
                Field::Bytes(value) if code.is_none() => {
                    let name = utf8(value)?;
                    // Upstream may publish category keys outside Theia's
                    // selector grammar (for example attribute-qualified keys).
                    // Validate their structure, but never interpret them as
                    // user selectors or compile their unused domain records.
                    if name.is_empty()
                        || name.len() > 256
                        || !name.bytes().all(|b| b.is_ascii_graphic())
                    {
                        return Err(RoutingError::InvalidCategory);
                    }
                    code = Some(name.to_ascii_uppercase());
                }
                _ => return Err(RoutingError::InvalidDat),
            }
        }
    }
    code.ok_or(RoutingError::InvalidDat)
}

fn dat_domain(bytes: &[u8], regex_count: &mut usize) -> Result<DomainPattern, RoutingError> {
    let mut wire = Wire(bytes);
    let mut kind = None;
    let mut value = None;
    while let Some((field, item)) = wire.next()? {
        match (field, item) {
            (1, Field::Number(n)) if kind.is_none() => kind = Some(n),
            (2, Field::Bytes(bytes)) if value.is_none() => value = Some(utf8(bytes)?),
            // Attributes are not used by unqualified geosite:CODE selectors.
            (3, Field::Bytes(_)) => {}
            (1..=3, _) => return Err(RoutingError::InvalidDat),
            _ => {}
        }
    }
    let value = value.ok_or(RoutingError::InvalidDat)?;
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(RoutingError::InvalidDat);
    }
    match kind.unwrap_or(0) {
        0 => Ok(DomainPattern::Substring(value.to_ascii_lowercase())),
        1 => {
            *regex_count += 1;
            if *regex_count > MAX_REGEXES {
                return Err(RoutingError::Limit);
            }
            let regex = RegexBuilder::new(value)
                .size_limit(256 * 1024)
                .dfa_size_limit(256 * 1024)
                .build()
                .map_err(|_| RoutingError::InvalidDat)?;
            Ok(DomainPattern::Regex(regex))
        }
        2 => Ok(DomainPattern::Suffix(domain_name(value)?)),
        3 => Ok(DomainPattern::Full(domain_name(value)?)),
        _ => Err(RoutingError::InvalidDat),
    }
}

fn dat_cidr(bytes: &[u8]) -> Result<Cidr, RoutingError> {
    let mut wire = Wire(bytes);
    let mut ip = None;
    let mut prefix = None;
    while let Some((field, value)) = wire.next()? {
        match (field, value) {
            (1, Field::Bytes(bytes)) if ip.is_none() => {
                ip = Some(match bytes.len() {
                    4 => IpAddr::V4(Ipv4Addr::from(
                        <[u8; 4]>::try_from(bytes).map_err(|_| RoutingError::InvalidDat)?,
                    )),
                    16 => IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(bytes).map_err(|_| RoutingError::InvalidDat)?,
                    )),
                    _ => return Err(RoutingError::InvalidDat),
                });
            }
            (2, Field::Number(n)) if prefix.is_none() => {
                prefix = Some(u32::try_from(n).map_err(|_| RoutingError::InvalidDat)?);
            }
            (1 | 2, _) => return Err(RoutingError::InvalidDat),
            _ => {}
        }
    }
    Cidr::new(ip.ok_or(RoutingError::InvalidDat)?, prefix.unwrap_or(0))
}

#[derive(Debug)]
enum DomainSelector {
    Literal(DomainPattern),
    Category(String),
}
#[derive(Debug)]
enum IpSelector {
    Literal(Cidr),
    Category(String),
}
/// Exact executable content identity. The OS backend must obtain the digest
/// from a verified process/file handle; a PID, filename or reported hash is
/// not trusted application evidence on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ApplicationId([u8; 32]);

impl ApplicationId {
    pub fn from_sha256(hash: [u8; 32]) -> Self {
        Self(hash)
    }

    pub fn parse(selector: &str) -> Result<Self, RoutingError> {
        let hash = selector
            .strip_prefix("sha256:")
            .ok_or(RoutingError::InvalidApplication)?;
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(RoutingError::InvalidApplication);
        }
        let mut bytes = [0; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hash[i * 2..i * 2 + 2], 16)
                .map_err(|_| RoutingError::InvalidApplication)?;
        }
        Ok(Self::from_sha256(bytes))
    }
}

#[derive(Debug)]
struct CompiledRule {
    action: Action,
    domains: Vec<DomainSelector>,
    ips: Vec<IpSelector>,
    applications: HashSet<ApplicationId>,
}

/// Validated immutable rules and only the referenced geodata categories.
/// Callers must authenticate and verify exact DAT digests before compiling.
#[derive(Debug)]
pub struct Policy {
    rules: Vec<CompiledRule>,
    sites: HashMap<String, DomainCategory>,
    ips: HashMap<String, IpCategory>,
}

type Selectors = (Vec<CompiledRule>, HashSet<String>, HashSet<String>);

fn compile_selectors(rules: &[Rule]) -> Result<Selectors, RoutingError> {
    if rules.len() > MAX_RULES {
        return Err(RoutingError::Limit);
    }
    let mut site_codes = HashSet::new();
    let mut ip_codes = HashSet::new();
    let mut compiled = Vec::new();
    let mut selectors = 0usize;
    for rule in rules {
        if rule.name.trim().is_empty()
            || rule.name.len() > 128
            || rule.name.chars().any(char::is_control)
            || (rule.domains.is_empty() && rule.ips.is_empty() && rule.applications.is_empty())
        {
            return Err(RoutingError::InvalidRule);
        }
        selectors = selectors
            .saturating_add(rule.domains.len())
            .saturating_add(rule.ips.len())
            .saturating_add(rule.applications.len());
        if selectors > MAX_SELECTORS {
            return Err(RoutingError::Limit);
        }
        let mut domains = Vec::new();
        let mut ips = Vec::new();
        for selector in &rule.domains {
            domains.push(if let Some(value) = selector.strip_prefix("geosite:") {
                let code = category(value)?;
                site_codes.insert(code.clone());
                DomainSelector::Category(code)
            } else if let Some(value) = selector.strip_prefix("full:") {
                DomainSelector::Literal(DomainPattern::Full(domain_name(value)?))
            } else {
                let value = selector.strip_prefix("domain:").unwrap_or(selector);
                DomainSelector::Literal(DomainPattern::Suffix(domain_name(value)?))
            });
        }
        for selector in &rule.ips {
            ips.push(if let Some(value) = selector.strip_prefix("geoip:") {
                let code = category(value)?;
                ip_codes.insert(code.clone());
                IpSelector::Category(code)
            } else {
                IpSelector::Literal(Cidr::parse(selector)?)
            });
        }
        let applications = rule
            .applications
            .iter()
            .map(|selector| ApplicationId::parse(selector))
            .collect::<Result<HashSet<_>, _>>()?;
        compiled.push(CompiledRule {
            action: rule.action,
            domains,
            ips,
            applications,
        });
    }

    Ok((compiled, site_codes, ip_codes))
}

impl Policy {
    /// Syntactic validation; category existence is checked against pinned DAT at prepare time.
    pub fn validate_rules(rules: &[Rule]) -> Result<(), RoutingError> {
        compile_selectors(rules).map(|_| ())
    }

    pub fn compile(rules: &[Rule], geosite: &[u8], geoip: &[u8]) -> Result<Self, RoutingError> {
        if rules.len() > MAX_RULES || geosite.len() > MAX_DAT || geoip.len() > MAX_DAT {
            return Err(RoutingError::Limit);
        }
        let (compiled, site_codes, ip_codes) = compile_selectors(rules)?;
        let mut count = 0usize;
        let mut regex_count = 0usize;
        let mut sites = HashMap::new();
        let mut wire = Wire(geosite);
        while let Some((field, value)) = wire.next()? {
            if field != 1 {
                continue;
            }
            let Field::Bytes(bytes) = value else {
                return Err(RoutingError::InvalidDat);
            };
            let code = entry_code(bytes)?;
            if !site_codes.contains(&code) {
                continue;
            }
            let mut entries = DomainCategory::default();
            let mut entry = Wire(bytes);
            while let Some((field, value)) = entry.next()? {
                if field != 2 {
                    continue;
                }
                let Field::Bytes(bytes) = value else {
                    return Err(RoutingError::InvalidDat);
                };
                count += 1;
                if count > MAX_ENTRIES {
                    return Err(RoutingError::Limit);
                }
                entries.insert(dat_domain(bytes, &mut regex_count)?);
            }
            if entries.is_empty() || sites.insert(code, entries).is_some() {
                return Err(RoutingError::InvalidDat);
            }
        }
        let mut ips = HashMap::new();
        let mut wire = Wire(geoip);
        while let Some((field, value)) = wire.next()? {
            if field != 1 {
                continue;
            }
            let Field::Bytes(bytes) = value else {
                return Err(RoutingError::InvalidDat);
            };
            let code = entry_code(bytes)?;
            if !ip_codes.contains(&code) {
                continue;
            }
            let mut cidrs = Vec::new();
            let mut reverse = None;
            let mut entry = Wire(bytes);
            while let Some((field, value)) = entry.next()? {
                match (field, value) {
                    (2, Field::Bytes(bytes)) => {
                        count += 1;
                        if count > MAX_ENTRIES {
                            return Err(RoutingError::Limit);
                        }
                        cidrs.push(dat_cidr(bytes)?);
                    }
                    (3, Field::Number(n)) if n <= 1 && reverse.is_none() => reverse = Some(n == 1),
                    (2 | 3, _) => return Err(RoutingError::InvalidDat),
                    _ => {}
                }
            }
            if cidrs.is_empty()
                || ips
                    .insert(code, IpCategory::new(cidrs, reverse.unwrap_or(false)))
                    .is_some()
            {
                return Err(RoutingError::InvalidDat);
            }
        }
        if sites.len() != site_codes.len() || ips.len() != ip_codes.len() {
            return Err(RoutingError::MissingCategory);
        }
        Ok(Self {
            rules: compiled,
            sites,
            ips,
        })
    }

    /// One ordered classifier. A known OR match wins within a rule, but an
    /// earlier unresolved rule cannot be skipped in favor of a later rule.
    pub fn classify(
        &self,
        domain: Evidence<&str>,
        ip: Evidence<IpAddr>,
    ) -> Result<Classification, RoutingError> {
        self.classify_with_application(domain, ip, Evidence::Unknown)
    }

    pub fn classify_with_application(
        &self,
        domain: Evidence<&str>,
        ip: Evidence<IpAddr>,
        application: Evidence<ApplicationId>,
    ) -> Result<Classification, RoutingError> {
        let domain = match domain {
            Evidence::Known(host) => Evidence::Known(domain_name(host)?),
            Evidence::Absent => Evidence::Absent,
            Evidence::Unknown => Evidence::Unknown,
        };
        let ip = match ip {
            Evidence::Known(IpAddr::V6(v6)) => {
                Evidence::Known(v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4))
            }
            other => other,
        };
        for rule in &self.rules {
            let domain_match = match &domain {
                Evidence::Known(host) => rule.domains.iter().any(|selector| match selector {
                    DomainSelector::Literal(pattern) => pattern.matches(host),
                    DomainSelector::Category(code) => self.sites[code].matches(host),
                }),
                Evidence::Absent | Evidence::Unknown => false,
            };
            let ip_match = match ip {
                Evidence::Known(ip) => rule.ips.iter().any(|selector| match selector {
                    IpSelector::Literal(cidr) => cidr.matches(ip),
                    IpSelector::Category(code) => self.ips[code].matches(ip),
                }),
                Evidence::Absent | Evidence::Unknown => false,
            };
            let application_match = match application {
                Evidence::Known(id) => rule.applications.contains(&id),
                Evidence::Absent | Evidence::Unknown => false,
            };
            if domain_match || ip_match || application_match {
                return Ok(Classification::Matched(rule.action));
            }
            if (matches!(domain, Evidence::Unknown) && !rule.domains.is_empty())
                || (matches!(ip, Evidence::Unknown) && !rule.ips.is_empty())
                || (matches!(application, Evidence::Unknown) && !rule.applications.is_empty())
            {
                return Ok(Classification::Unresolved);
            }
        }
        Ok(Classification::Default)
    }

    /// Server-side destination projection. The server independently checks
    /// known domain/IP restrictions and cannot authenticate a client process.
    /// Client routing must use classify_with_application (or classify for
    /// an unknown process), never this projection.
    pub fn domain_decision(&self, domain: &str) -> Result<Option<Action>, RoutingError> {
        Ok(self
            .classify_with_application(
                Evidence::Known(domain),
                Evidence::Unknown,
                Evidence::Absent,
            )?
            .action())
    }

    /// Server-side destination projection for explicitly supplied attributes.
    pub fn matching_action(
        &self,
        domain: Option<&str>,
        ip: Option<IpAddr>,
    ) -> Result<Option<Action>, RoutingError> {
        match self.classify_with_application(
            domain.map_or(Evidence::Absent, Evidence::Known),
            ip.map_or(Evidence::Absent, Evidence::Known),
            Evidence::Absent,
        )? {
            Classification::Matched(action) => Ok(Some(action)),
            Classification::Default | Classification::Unresolved => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(action: Action, domains: &[&str], ips: &[&str]) -> Rule {
        Rule {
            name: "test".into(),
            action,
            domains: domains.iter().map(|s| (*s).into()).collect(),
            ips: ips.iter().map(|s| (*s).into()).collect(),
            applications: vec![],
        }
    }
    fn field(tag: u8, value: &[u8]) -> Vec<u8> {
        assert!(value.len() < 128);
        let mut result = vec![tag * 8 + 2, value.len() as u8];
        result.extend_from_slice(value);
        result
    }
    fn site(code: &str, kind: u8, name: &str) -> Vec<u8> {
        let mut domain = vec![8, kind];
        domain.extend(field(2, name.as_bytes()));
        let mut entry = field(1, code.as_bytes());
        entry.extend(field(2, &domain));
        field(1, &entry)
    }
    fn ip_data(code: &str, ip: &[u8], prefix: u8, reverse: bool) -> Vec<u8> {
        let mut cidr = field(1, ip);
        cidr.extend([16, prefix]);
        let mut entry = field(1, code.as_bytes());
        entry.extend(field(2, &cidr));
        if reverse {
            entry.extend([24, 1]);
        }
        field(1, &entry)
    }

    #[test]
    fn unknown_earlier_rule_blocks_later_egress_but_known_or_match_wins() {
        let ip = "192.0.2.1".parse().unwrap();
        let p = Policy::compile(
            &[
                rule(Action::Blocked, &["blocked.example"], &[]),
                rule(Action::Direct, &[], &["192.0.2.0/24"]),
            ],
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(
            p.classify(Evidence::Unknown, Evidence::Known(ip)).unwrap(),
            Classification::Unresolved
        );
        assert_eq!(
            p.classify(Evidence::Absent, Evidence::Known(ip)).unwrap(),
            Classification::Matched(Action::Direct)
        );
        assert_eq!(
            p.classify(Evidence::Known("blocked.example"), Evidence::Unknown)
                .unwrap(),
            Classification::Matched(Action::Blocked)
        );
        assert_eq!(
            p.classify(Evidence::Known("other.example"), Evidence::Unknown)
                .unwrap(),
            Classification::Unresolved
        );
        let or = Policy::compile(
            &[rule(Action::DirectDpi, &["example.com"], &["192.0.2.0/24"])],
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(
            or.classify(Evidence::Unknown, Evidence::Known(ip))
                .unwrap()
                .action(),
            Some(Action::DirectDpi)
        );
        assert_eq!(
            or.classify(Evidence::Absent, Evidence::Absent).unwrap(),
            Classification::Default
        );
        assert_eq!(Classification::Default.action(), Some(Action::Allowed));
        assert_eq!(Classification::Unresolved.action(), None);
        assert_eq!(Action::Direct.packet_action(), PacketAction::Pass);
        assert_eq!(Action::DirectDpi.packet_action(), PacketAction::Modify);
        assert_eq!(Action::Allowed.packet_action(), PacketAction::Redirect);
        assert_eq!(Action::Blocked.packet_action(), PacketAction::Drop);
    }

    #[test]
    fn application_evidence_is_exact_and_unknown_cannot_bypass() {
        let digest = "sha256:".to_owned() + &"ab".repeat(32);
        let id = ApplicationId::parse(&digest).unwrap();
        let mut first = rule(Action::Blocked, &[], &[]);
        first.applications.push(digest.clone());
        let later = rule(Action::Direct, &[], &["192.0.2.0/24"]);
        let p = Policy::compile(&[first.clone(), later.clone()], &[], &[]).unwrap();
        let ip = Evidence::Known("192.0.2.10".parse().unwrap());
        assert_eq!(
            p.classify(Evidence::Absent, ip).unwrap(),
            Classification::Unresolved
        );
        assert_eq!(
            p.classify_with_application(Evidence::Absent, ip, Evidence::Known(id))
                .unwrap(),
            Classification::Matched(Action::Blocked)
        );
        assert_eq!(
            p.classify_with_application(
                Evidence::Absent,
                ip,
                Evidence::Known(ApplicationId::from_sha256([0; 32]))
            )
            .unwrap(),
            Classification::Matched(Action::Direct)
        );
        assert_eq!(
            p.matching_action(None, Some("192.0.2.10".parse().unwrap()))
                .unwrap(),
            Some(Action::Direct)
        );
        first.domains.push("example.org".into());
        let p = Policy::compile(&[first.clone(), later], &[], &[]).unwrap();
        assert_eq!(
            p.classify(Evidence::Known("example.org"), ip).unwrap(),
            Classification::Matched(Action::Blocked)
        );
        assert!(ApplicationId::parse("chrome.exe").is_err());
        assert!(ApplicationId::parse(&digest.to_uppercase()).is_err());
        first.applications = vec!["pid:10".into()];
        assert_eq!(
            Policy::validate_rules(&[first]),
            Err(RoutingError::InvalidApplication)
        );
    }

    #[test]
    fn canonical_action_names_reject_legacy_in_v1() {
        for action in Action::ALL {
            let rule = rule(action, &["example.org"], &[]);
            let wire = toml::to_string(&rule).unwrap();
            assert!(wire.contains(action.name()));
            assert_eq!(Action::from_name(action.name()), Some(action));
            assert_eq!(toml::from_str::<Rule>(&wire).unwrap(), rule);
            for old in ["direct", "allowed", "blocked", "direct_dpi"] {
                assert!(Action::from_name(old).is_none());
                assert!(toml::from_str::<Rule>(&wire.replace(action.name(), old)).is_err());
            }
        }
    }

    #[test]
    fn first_match_or_and_domain_boundaries() {
        let p = Policy::compile(
            &[
                rule(Action::Blocked, &["full:ads.example.com"], &[]),
                rule(Action::Direct, &["example.com"], &["192.0.2.0/24"]),
                rule(Action::Allowed, &["geosite:google"], &[]),
            ],
            &site("GOOGLE", 2, "google.com"),
            &[],
        )
        .unwrap();
        assert_eq!(
            p.matching_action(Some("ads.example.com"), None).unwrap(),
            Some(Action::Blocked)
        );
        assert_eq!(
            p.matching_action(Some("WWW.EXAMPLE.COM."), None).unwrap(),
            Some(Action::Direct)
        );
        assert_eq!(
            p.matching_action(Some("badexample.com"), None).unwrap(),
            None
        );
        assert_eq!(
            p.matching_action(Some("unrelated.com"), Some("192.0.2.12".parse().unwrap()))
                .unwrap(),
            Some(Action::Direct)
        );
        assert_eq!(
            p.matching_action(Some("mail.google.com"), None).unwrap(),
            Some(Action::Allowed)
        );
    }

    #[test]
    fn dat_domain_types() {
        let mut data = site("SUB", 0, "keyword");
        data.extend(site("REG", 1, r"^foo[0-9]+\.example$"));
        data.extend(site("FULL", 3, "exact.example"));
        let p = Policy::compile(
            &[
                rule(Action::Blocked, &["geosite:sub"], &[]),
                rule(Action::Direct, &["geosite:reg"], &[]),
                rule(Action::Allowed, &["geosite:full"], &[]),
            ],
            &data,
            &[],
        )
        .unwrap();
        assert_eq!(
            p.matching_action(Some("keyword.example"), None).unwrap(),
            Some(Action::Blocked)
        );
        assert_eq!(
            p.matching_action(Some("foo12.example"), None).unwrap(),
            Some(Action::Direct)
        );
        assert_eq!(
            p.matching_action(Some("exact.example"), None).unwrap(),
            Some(Action::Allowed)
        );
        assert_eq!(
            p.matching_action(Some("sub.exact.example"), None).unwrap(),
            None
        );
    }

    #[test]
    fn cidrs_and_reverse() {
        let mut data = ip_data("RU", &[192, 0, 2, 0], 24, false);
        data.extend(ip_data(
            "V6",
            &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            32,
            false,
        ));
        data.extend(ip_data("NOT", &[203, 0, 113, 0], 24, true));
        let p = Policy::compile(
            &[
                rule(Action::Direct, &[], &["geoip:ru", "geoip:v6"]),
                rule(Action::Blocked, &[], &["geoip:not"]),
            ],
            &[],
            &data,
        )
        .unwrap();
        for ip in ["192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1"] {
            assert_eq!(
                p.matching_action(None, Some(ip.parse().unwrap())).unwrap(),
                Some(Action::Direct)
            );
        }
        assert_eq!(
            p.matching_action(None, Some("198.51.100.1".parse().unwrap()))
                .unwrap(),
            Some(Action::Blocked)
        );
        assert_eq!(
            p.matching_action(None, Some("203.0.113.1".parse().unwrap()))
                .unwrap(),
            None
        );
    }

    #[test]
    fn unrelated_upstream_category_keys_do_not_break_selected_rules() {
        let mut data = site("GOOGLE@CN", 2, "other.example");
        data.extend(site("GOOGLE", 2, "google.com"));
        let rules = [rule(Action::Direct, &["geosite:google"], &[])];
        let policy = Policy::compile(&rules, &data, &[]).unwrap();
        assert_eq!(
            policy.matching_action(Some("google.com"), None).unwrap(),
            Some(Action::Direct)
        );
        assert_eq!(
            policy.matching_action(Some("other.example"), None).unwrap(),
            None
        );
        assert!(matches!(
            Policy::compile(
                &[rule(Action::Direct, &["geosite:google@cn"], &[])],
                &data,
                &[]
            ),
            Err(RoutingError::InvalidCategory)
        ));
        assert!(matches!(
            Policy::compile(&rules, &site("BAD KEY", 2, "example.com"), &[]),
            Err(RoutingError::InvalidCategory)
        ));
        let (_, wire) = snapshot::Snapshot::build("scope", 2, &rules, &data, &[]).unwrap();
        assert!(snapshot::Snapshot::decode(&wire, "scope").is_ok());
    }

    #[test]
    fn invalid_policy_and_dat_fail_closed() {
        assert!(matches!(
            Policy::compile(&[rule(Action::Direct, &[], &[])], &[], &[]),
            Err(RoutingError::InvalidRule)
        ));
        assert!(matches!(
            Policy::compile(&[rule(Action::Direct, &["geosite:missing"], &[])], &[], &[]),
            Err(RoutingError::MissingCategory)
        ));
        assert!(matches!(
            Policy::compile(&[rule(Action::Direct, &[], &["192.0.2.1/33"])], &[], &[]),
            Err(RoutingError::InvalidIp)
        ));
        assert!(matches!(
            Policy::compile(&[], &[10, 127], &[]),
            Err(RoutingError::InvalidDat)
        ));
        assert!(matches!(
            Policy::compile(
                &[rule(Action::Direct, &["geosite:bad"], &[])],
                &site("BAD", 4, "example.com"),
                &[]
            ),
            Err(RoutingError::InvalidDat)
        ));
        let mut dup = site("GOOGLE", 2, "google.com");
        dup.extend(site("GOOGLE", 2, "other.com"));
        assert!(matches!(
            Policy::compile(&[rule(Action::Direct, &["geosite:google"], &[])], &dup, &[]),
            Err(RoutingError::InvalidDat)
        ));
    }
}
