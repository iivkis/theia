//! Verified, content-addressed XTLS datasets. The active pointer is a
//! cooperating CAS publication; a failed refresh never replaces the old pair.
//! Call from a supervised runtime or an explicitly confirmed operator action.
use super::{Policy, RoutingError, Rule};
use flate2::read::MultiGzDecoder;
use http::{header, StatusCode, Uri};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

const REPO: &str = "/XTLS/Xray-rules-dat/releases";
const LATEST: &str = "https://github.com/XTLS/Xray-rules-dat/releases/latest";
const SITE: &str = "geosite.dat";
const IP: &str = "geoip-lite.dat";
const MAX_CHECKSUM: usize = 1024;
const MAX_REDIRECTS: usize = 4;
// Bounds are deliberately above the current compact upstream assets;
// oversized future releases fail closed rather than loading full editions.
const MAX_COMPRESSED: usize = 16 * 1024 * 1024;
const MAX_DATASET: usize = 32 * 1024 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(300);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(86400);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Io,
    Network,
    Tls,
    Format,
    Integrity,
    Limit,
    Conflict,
    Routing(RoutingError),
}
impl From<RoutingError> for Error {
    fn from(value: RoutingError) -> Self {
        Self::Routing(value)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "geodata: {self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub release: String,
    pub geosite_sha256: [u8; 32],
    pub geoip_sha256: [u8; 32],
}
#[derive(Debug)]
pub struct Pair {
    manifest: Manifest,
    geosite: Vec<u8>,
    geoip: Vec<u8>,
}
impl Pair {
    pub fn verified(
        manifest: Manifest,
        geosite: Vec<u8>,
        geoip: Vec<u8>,
        rules: &[Rule],
    ) -> Result<Self, Error> {
        if !valid_tag(&manifest.release) || geosite.is_empty() || geoip.is_empty() {
            return Err(Error::Format);
        }
        if geosite.len() > MAX_DATASET || geoip.len() > MAX_DATASET {
            return Err(Error::Limit);
        }
        if hash(&geosite) != manifest.geosite_sha256 || hash(&geoip) != manifest.geoip_sha256 {
            return Err(Error::Integrity);
        }
        // Structural and selected category validation before publication.
        Policy::compile(rules, &geosite, &geoip)?;
        Ok(Self {
            manifest,
            geosite,
            geoip,
        })
    }
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn geosite(&self) -> &[u8] {
        &self.geosite
    }
    pub fn geoip(&self) -> &[u8] {
        &self.geoip
    }
    pub fn compile(&self, rules: &[Rule]) -> Result<Policy, Error> {
        Ok(Policy::compile(rules, &self.geosite, &self.geoip)?)
    }
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut result = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(result, "{b:02x}");
    }
    result
}
fn decode_hash(value: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Format);
    }
    let mut result = [0; 32];
    for (i, b) in result.iter_mut().enumerate() {
        *b = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|_| Error::Format)?;
    }
    Ok(result)
}

fn checksum(bytes: &[u8], expected_name: &str) -> Result<[u8; 32], Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Format)?;
    let mut fields = text.split_whitespace();
    let digest = decode_hash(fields.next().ok_or(Error::Format)?)?;
    let name = fields.next().ok_or(Error::Format)?;
    if name.strip_prefix('*').unwrap_or(name) != expected_name || fields.next().is_some() {
        return Err(Error::Format);
    }
    Ok(digest)
}

fn valid_tag(tag: &str) -> bool {
    tag.len() == 14 && tag.bytes().all(|b| b.is_ascii_digit())
}

fn location(base: &Uri, raw: &str) -> Result<Uri, Error> {
    let uri: Uri = if raw.starts_with('/') && !raw.starts_with("//") {
        format!("https://{}{}", base.authority().ok_or(Error::Format)?, raw)
            .parse()
            .map_err(|_| Error::Format)?
    } else {
        raw.parse().map_err(|_| Error::Format)?
    };
    let host = uri.host().ok_or(Error::Format)?;
    if uri.scheme_str() != Some("https")
        || uri.authority().is_none_or(|a| a.as_str() != host)
        || !matches!(
            host,
            "github.com" | "release-assets.githubusercontent.com" | "objects.githubusercontent.com"
        )
        || raw.contains('#')
    {
        return Err(Error::Format);
    }
    Ok(uri)
}
fn release_tag(base: &Uri, raw: &str) -> Result<String, Error> {
    let uri = location(base, raw)?;
    if uri.host() != Some("github.com") || uri.query().is_some() {
        return Err(Error::Format);
    }
    let tag = uri
        .path()
        .strip_prefix(REPO)
        .and_then(|s| s.strip_prefix("/tag/"))
        .filter(|t| valid_tag(t))
        .ok_or(Error::Format)?;
    Ok(tag.to_owned())
}

struct Abort(tokio::task::JoinHandle<()>);
impl Drop for Abort {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Reply {
    status: StatusCode,
    redirect: Option<String>,
    bytes: Vec<u8>,
}

fn roots() -> Result<rustls::RootCertStore, Error> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    if roots.is_empty() {
        return Err(Error::Tls);
    }
    Ok(roots)
}
async fn get_once(uri: Uri, limit: usize, roots: &rustls::RootCertStore) -> Result<Reply, Error> {
    let host = uri.host().ok_or(Error::Format)?.to_owned();
    let tls = crate::transport_policy::Carrier::H2
        .client_tls(roots.clone())
        .map_err(|_| Error::Tls)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls));
    let (mut sender, _driver) = tokio::time::timeout(CONNECT_TIMEOUT, async {
        let tcp = tokio::net::TcpStream::connect((host.as_str(), 443))
            .await
            .map_err(|_| Error::Network)?;
        let name = rustls::pki_types::ServerName::try_from(host).map_err(|_| Error::Tls)?;
        let tls = connector.connect(name, tcp).await.map_err(|_| Error::Tls)?;
        if !crate::transport_policy::Carrier::H2.accepts_tls(
            tls.get_ref().1.protocol_version(),
            tls.get_ref().1.alpn_protocol(),
        ) {
            return Err(Error::Tls);
        }
        let (sender, conn) = h2::client::Builder::new()
            .max_header_list_size(16 * 1024)
            .handshake::<_, bytes::Bytes>(tls)
            .await
            .map_err(|_| Error::Network)?;
        Ok((
            sender,
            Abort(tokio::spawn(async move {
                let _ = conn.await;
            })),
        ))
    })
    .await
    .map_err(|_| Error::Network)??;
    sender = sender.ready().await.map_err(|_| Error::Network)?;
    let request = http::Request::get(uri)
        .header(header::USER_AGENT, "Theia-geodata/1")
        .header(header::ACCEPT_ENCODING, "identity")
        .body(())
        .map_err(|_| Error::Format)?;
    let (response, _) = sender
        .send_request(request, true)
        .map_err(|_| Error::Network)?;
    let response = response.await.map_err(|_| Error::Network)?;
    let status = response.status();
    if status.is_redirection() {
        if response.headers().get_all(header::LOCATION).iter().count() != 1 {
            return Err(Error::Format);
        }
        let redirect = response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .filter(|s| s.len() <= 8192)
            .ok_or(Error::Format)?
            .to_owned();
        return Ok(Reply {
            status,
            redirect: Some(redirect),
            bytes: Vec::new(),
        });
    }
    if status != StatusCode::OK
        || response
            .headers()
            .get_all(header::CONTENT_LENGTH)
            .iter()
            .count()
            > 1
        || response
            .headers()
            .get(header::CONTENT_ENCODING)
            .is_some_and(|v| v.as_bytes() != b"identity")
    {
        return Err(Error::Network);
    }
    let expected = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .map(|v| {
            v.to_str()
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .ok_or(Error::Format)
        })
        .transpose()?;
    if expected.is_some_and(|n| n > limit) {
        return Err(Error::Limit);
    }
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|_| Error::Network)?;
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|n| n > limit)
        {
            return Err(Error::Limit);
        }
        bytes.extend_from_slice(&chunk);
        body.flow_control()
            .release_capacity(chunk.len())
            .map_err(|_| Error::Network)?;
    }
    if expected.is_some_and(|n| n != bytes.len())
        || body.trailers().await.map_err(|_| Error::Network)?.is_some()
    {
        return Err(Error::Format);
    }
    Ok(Reply {
        status,
        redirect: None,
        bytes,
    })
}

async fn latest(roots: &rustls::RootCertStore) -> Result<String, Error> {
    let uri: Uri = LATEST.parse().map_err(|_| Error::Format)?;
    let reply = tokio::time::timeout(CONNECT_TIMEOUT, get_once(uri.clone(), 0, roots))
        .await
        .map_err(|_| Error::Network)??;
    if !reply.status.is_redirection() {
        return Err(Error::Format);
    }
    release_tag(&uri, reply.redirect.as_deref().ok_or(Error::Format)?)
}

fn asset_uri(tag: &str, name: &str) -> Result<Uri, Error> {
    if !valid_tag(tag) {
        return Err(Error::Format);
    }
    format!("https://github.com{REPO}/download/{tag}/{name}")
        .parse()
        .map_err(|_| Error::Format)
}

async fn asset(
    tag: &str,
    name: &str,
    limit: usize,
    roots: &rustls::RootCertStore,
) -> Result<Vec<u8>, Error> {
    tokio::time::timeout(FETCH_TIMEOUT, async {
        let mut uri = asset_uri(tag, name)?;
        for _ in 0..=MAX_REDIRECTS {
            let reply = get_once(uri.clone(), limit, roots).await?;
            match reply.redirect {
                Some(raw) => {
                    let next = location(&uri, &raw)?;
                    // Never redirect a pinned release to an alternate repo,
                    // tag, filename or a credential-bearing URL.
                    if next.host() == Some("github.com")
                        && (next.path() != asset_uri(tag, name)?.path() || next.query().is_some())
                    {
                        return Err(Error::Format);
                    }
                    uri = next;
                }
                None => return Ok(reply.bytes),
            }
        }
        Err(Error::Format)
    })
    .await
    .map_err(|_| Error::Network)?
}

fn decompress(compressed: &[u8], expected: [u8; 32]) -> Result<Vec<u8>, Error> {
    let mut result = Vec::new();
    MultiGzDecoder::new(compressed)
        .take((MAX_DATASET + 1) as u64)
        .read_to_end(&mut result)
        .map_err(|_| Error::Format)?;
    if result.len() > MAX_DATASET {
        return Err(Error::Limit);
    }
    if result.is_empty() || hash(&result) != expected {
        return Err(Error::Integrity);
    }
    Ok(result)
}

async fn dataset(
    tag: &str,
    name: &str,
    roots: &rustls::RootCertStore,
) -> Result<(Vec<u8>, [u8; 32]), Error> {
    let raw_sum = asset(tag, &format!("{name}.sha256sum"), MAX_CHECKSUM, roots).await?;
    let expected = checksum(&raw_sum, name)?;
    let gz_name = format!("{name}.gz");
    let gz_sum = asset(tag, &format!("{gz_name}.sha256sum"), MAX_CHECKSUM, roots).await?;
    let expected_gz = checksum(&gz_sum, &gz_name)?;
    let gz = asset(tag, &gz_name, MAX_COMPRESSED, roots).await?;
    if hash(&gz) != expected_gz {
        return Err(Error::Integrity);
    }
    let data = tokio::task::spawn_blocking(move || decompress(&gz, expected))
        .await
        .map_err(|_| Error::Io)??;
    Ok((data, expected))
}

/// A cache directory must be owned by the operator and have trusted parents.
/// Only a small edition-specific active manifest is replaced; old files are
/// deliberately retained, so a reader of the old manifest remains valid.
pub struct Store {
    directory: PathBuf,
}
impl Store {
    pub fn new(directory: PathBuf) -> Result<Self, Error> {
        if !directory.is_absolute()
            || !fs::symlink_metadata(&directory).is_ok_and(|m| m.file_type().is_dir())
        {
            return Err(Error::Io);
        }
        Ok(Self { directory })
    }
    fn active(&self) -> PathBuf {
        // Different upstream editions have different semantics even at the
        // same release tag. Never reuse the previous full/expanded pointer.
        self.directory.join("active-standard-lite.toml")
    }
    fn data_path(&self, name: &str, digest: &[u8; 32]) -> PathBuf {
        self.directory.join(format!("{}-{name}", hex(digest)))
    }
    fn current_bytes(&self) -> Result<Option<Vec<u8>>, Error> {
        match fs::symlink_metadata(self.active()) {
            Ok(_) => crate::bounded_input::read(&self.active(), 4096, true, true)
                .map(|b| Some(b.to_vec()))
                .map_err(|_| Error::Io),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(Error::Io),
        }
    }
    fn load_bytes(&self, bytes: &[u8], rules: &[Rule]) -> Result<Pair, Error> {
        let manifest: Manifest =
            toml::from_str(std::str::from_utf8(bytes).map_err(|_| Error::Format)?)
                .map_err(|_| Error::Format)?;
        let site = crate::bounded_input::read(
            &self.data_path(SITE, &manifest.geosite_sha256),
            MAX_DATASET as u64,
            true,
            true,
        )
        .map_err(|_| Error::Io)?;
        let ip = crate::bounded_input::read(
            &self.data_path(IP, &manifest.geoip_sha256),
            MAX_DATASET as u64,
            true,
            true,
        )
        .map_err(|_| Error::Io)?;
        Pair::verified(manifest, site.to_vec(), ip.to_vec(), rules)
    }
    /// Prepare exact content-addressed files, not the mutable active pointer.
    pub fn load_pinned(&self, manifest: &Manifest, rules: &[Rule]) -> Result<Pair, Error> {
        let text = toml::to_string(manifest).map_err(|_| Error::Format)?;
        self.load_bytes(text.as_bytes(), rules)
    }
    pub fn load(&self, rules: &[Rule]) -> Result<Option<Pair>, Error> {
        self.current_bytes()?
            .map(|b| self.load_bytes(&b, rules))
            .transpose()
    }
    fn write_blob(&self, name: &str, bytes: &[u8], digest: [u8; 32]) -> Result<(), Error> {
        let path = self.data_path(name, &digest);
        let check = || -> Result<(), Error> {
            let existing = crate::bounded_input::read(&path, MAX_DATASET as u64, true, true)
                .map_err(|_| Error::Io)?;
            if hash(&existing) != digest {
                return Err(Error::Integrity);
            }
            Ok(())
        };
        match fs::symlink_metadata(&path) {
            Ok(_) => return check(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error::Io),
        }
        let mut random = [0u8; 16];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| Error::Io)?;
        let temp = self
            .directory
            .join(format!(".geodata-{}.tmp", hex(&random)));
        let mut file = new_file(&temp).map_err(|_| Error::Io)?;
        let result = (|| {
            file.write_all(bytes).map_err(|_| Error::Io)?;
            file.sync_all().map_err(|_| Error::Io)?;
            drop(file);
            match fs::hard_link(&temp, &path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => check(),
                Err(_) => Err(Error::Io),
            }
        })();
        let removed = fs::remove_file(&temp).map_err(|_| Error::Io);
        result?;
        removed?;
        #[cfg(unix)]
        File::open(&self.directory)
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::Io)?;
        Ok(())
    }
    fn publish(&self, pair: &Pair, expected: Option<&[u8]>) -> Result<(), Error> {
        self.write_blob(SITE, &pair.geosite, pair.manifest.geosite_sha256)?;
        self.write_blob(IP, &pair.geoip, pair.manifest.geoip_sha256)?;
        let text = toml::to_string(&pair.manifest).map_err(|_| Error::Format)?;
        crate::config::guarded_trust_write(&self.active(), &text, expected)
            .map_err(|_| Error::Conflict)
    }

    /// Download one pinned release, validate both compressed and raw
    /// checksums, validate all referenced categories, then publish the pair.
    /// Concurrent writes are refused by exact old-manifest CAS.
    pub async fn refresh(&self, rules: &[Rule]) -> Result<Pair, Error> {
        let previous = self.current_bytes()?;
        let roots = tokio::task::spawn_blocking(roots)
            .await
            .map_err(|_| Error::Io)??;
        let tag = latest(&roots).await?;
        if let Some(bytes) = previous.as_deref() {
            let manifest: Manifest =
                toml::from_str(std::str::from_utf8(bytes).map_err(|_| Error::Format)?)
                    .map_err(|_| Error::Format)?;
            if !valid_tag(&manifest.release) || manifest.release > tag {
                return Err(Error::Conflict);
            }
            if manifest.release == tag {
                return self.load_bytes(bytes, rules);
            }
            // A new release may contain categories missing in the old one.
            // Validate only the new pair before changing the active pointer.
        }
        let (site, site_hash) = dataset(&tag, SITE, &roots).await?;
        let (ip, ip_hash) = dataset(&tag, IP, &roots).await?;
        let directory = self.directory.clone();
        let rules = rules.to_vec();
        tokio::task::spawn_blocking(move || {
            let pair = Pair::verified(
                Manifest {
                    release: tag,
                    geosite_sha256: site_hash,
                    geoip_sha256: ip_hash,
                },
                site,
                ip,
                &rules,
            )?;
            Store::new(directory)?.publish(&pair, previous.as_deref())?;
            Ok(pair)
        })
        .await
        .map_err(|_| Error::Io)?
    }
}

fn new_file(path: &Path) -> std::io::Result<File> {
    #[cfg(windows)]
    {
        crate::client_import::new_private_file(path)
    }
    #[cfg(not(windows))]
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dat(code: u8) -> Vec<u8> {
        // An entry with a category name and a valid suffix record.
        vec![10, 12, 10, 1, code, 18, 7, 8, 2, 18, 3, b'a', b'.', b'b']
    }
    fn ip() -> Vec<u8> {
        vec![10, 13, 10, 1, b'X', 18, 8, 10, 4, 192, 0, 2, 0, 16, 24]
    }

    #[test]
    fn pinned_sources_and_checksums() {
        let latest: Uri = LATEST.parse().unwrap();
        assert_eq!(
            release_tag(&latest, "/XTLS/Xray-rules-dat/releases/tag/20261126014317").unwrap(),
            "20261126014317"
        );
        for bad in [
            "http://github.com/XTLS/Xray-rules-dat/releases/tag/20261126014317",
            "https://evil.example/XTLS/Xray-rules-dat/releases/tag/20261126014317",
            "https://github.com:443/XTLS/Xray-rules-dat/releases/tag/20261126014317",
            "https://github.com/other/repo/releases/tag/20261126014317",
            "//github.com/XTLS/Xray-rules-dat/releases/tag/20261126014317",
            "https://github.com/XTLS/Xray-rules-dat/releases/tag/20261126014317?x=1",
        ] {
            assert!(release_tag(&latest, bad).is_err());
        }
        assert!(location(
            &latest,
            "https://release-assets.githubusercontent.com/asset?token=example"
        )
        .is_ok());
        assert!(asset_uri("../latest", SITE).is_err());
        assert_eq!(SITE, "geosite.dat");
        assert_eq!(IP, "geoip-lite.dat");
        assert!(super::super::GEOSITE_URL.ends_with("/geosite.dat"));
        assert!(super::super::GEOIP_URL.ends_with("/geoip-lite.dat"));
        assert!(asset_uri("20261126014317", SITE)
            .unwrap()
            .path()
            .ends_with("/geosite.dat"));
        assert!(asset_uri("20261126014317", IP)
            .unwrap()
            .path()
            .ends_with("/geoip-lite.dat"));
        let digest = hash(b"test");
        let sum = format!("{}  {SITE}\n", hex(&digest));
        assert_eq!(checksum(sum.as_bytes(), SITE).unwrap(), digest);
        assert!(checksum(sum.as_bytes(), IP).is_err());
        assert!(checksum(b"abcd wrong.dat", SITE).is_err());
    }

    #[test]
    fn gzip_and_both_hashes() {
        let mut writer = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        writer.write_all(b"test data").unwrap();
        let gz = writer.finish().unwrap();
        assert_eq!(decompress(&gz, hash(b"test data")).unwrap(), b"test data");
        assert_eq!(decompress(&gz, hash(b"wrong")), Err(Error::Integrity));
        assert!(decompress(&gz[..gz.len() - 2], hash(b"test data")).is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn geodata_automatic_activation_preserves_pending_edit_and_rejects_rollback() {
        use crate::{
            config::{self, Config},
            live_auth::LiveAuthorization,
            reload_preflight::ReloadPreflight,
            runtime_generation::{State, View},
        };
        let mut random = [0; 16];
        SystemRandom::new().fill(&mut random).unwrap();
        let dir = std::env::temp_dir().join(format!("theia-geodata-activation-{}", hex(&random)));
        fs::create_dir(&dir).unwrap();
        let store = Store::new(dir.clone()).unwrap();
        let pair = |release: &str, code: u8| {
            let site = dat(code);
            let ip = ip();
            Pair::verified(
                Manifest {
                    release: release.into(),
                    geosite_sha256: hash(&site),
                    geoip_sha256: hash(&ip),
                },
                site,
                ip,
                &[],
            )
            .unwrap()
        };
        let old = pair("20261126014317", b'X');
        let next = pair("20261127014317", b'Y');
        store.publish(&old, None).unwrap();
        store
            .publish(&next, store.current_bytes().unwrap().as_deref())
            .unwrap();
        let Config::Server(mut doc) = config::parse(
            &include_str!("../../../../examples/server.toml")
                .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"a".repeat(64)),
        )
        .unwrap() else {
            panic!()
        };
        doc.server.policy.routing = Some(crate::routing::Settings {
            revision: 2,
            geodata_directory: Some(dir.to_str().unwrap().into()),
            rules: vec![],
            datasets: Some(old.manifest().clone()),
        });
        let path = dir.join("server.toml");
        config::atomic_write(&path, &Config::Server(doc.clone())).unwrap();
        let live = Arc::new(LiveAuthorization::new(doc.clone()).unwrap());
        let state = State::new(View {
            document: Arc::new(doc.clone()),
            inbounds: doc.server.inbounds.len(),
            preflight: Arc::new(ReloadPreflight::new(path.clone(), doc.clone(), vec![])),
            live: live.clone(),
        })
        .with_reality_ledger(crate::quota::Ledger::new(
            &doc.server.policy,
            &doc.server.users,
        ));
        let view = state.snapshot().unwrap();
        let stage = state
            .prepare_geodata(&view, &path, next.manifest().clone())
            .unwrap()
            .unwrap();
        let mut edit = doc.clone();
        edit.server.users[0].disabled = true;
        config::atomic_write(&path, &Config::Server(edit.clone())).unwrap();
        assert!(state.activate_geodata(stage).is_err());
        assert_eq!(config::read_file(&path).unwrap(), Config::Server(edit));
        assert_eq!(live.revision(), Ok(1));
        config::atomic_write(&path, &Config::Server(doc.clone())).unwrap();
        let stage = state
            .prepare_geodata(&view, &path, next.manifest().clone())
            .unwrap()
            .unwrap();
        state.activate_geodata(stage).unwrap();
        let current = state.snapshot().unwrap();
        assert_eq!(current.live.revision(), Ok(2));
        let routing = current.document.server.policy.routing.as_ref().unwrap();
        assert_eq!(routing.revision, 3);
        assert_eq!(routing.datasets.as_ref(), Some(next.manifest()));
        assert_eq!(
            config::read_file(&path).unwrap(),
            Config::Server(current.document.as_ref().clone())
        );
        assert!(state
            .prepare_geodata(&current, &path, old.manifest().clone())
            .is_err());
        assert!(state
            .prepare_geodata(&current, &path, next.manifest().clone())
            .unwrap()
            .is_none());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn compact_cache_never_reuses_old_full_edition() {
        let mut random = [0; 16];
        SystemRandom::new().fill(&mut random).unwrap();
        let dir = std::env::temp_dir().join(format!("theia-geodata-edition-{}", hex(&random)));
        fs::create_dir(&dir).unwrap();
        let store = Store::new(dir.clone()).unwrap();
        let site = dat(b'X');
        let ip = ip();
        let old = Manifest {
            release: "20261126014317".into(),
            geosite_sha256: hash(&site),
            geoip_sha256: hash(&ip),
        };
        let previous = toml::to_string(&old).unwrap();
        fs::write(dir.join("active.toml"), &previous).unwrap();
        fs::write(
            store.data_path("geosite-expand.dat", &old.geosite_sha256),
            &site,
        )
        .unwrap();
        fs::write(store.data_path("geoip-full.dat", &old.geoip_sha256), &ip).unwrap();
        assert!(store.load(&[]).unwrap().is_none());
        assert!(store.load_pinned(&old, &[]).is_err());
        let pair = Pair::verified(old.clone(), site, ip, &[]).unwrap();
        store.publish(&pair, None).unwrap();
        assert_eq!(store.load(&[]).unwrap().unwrap().manifest(), &old);
        assert_eq!(
            fs::read_to_string(dir.join("active.toml")).unwrap(),
            previous
        );
        assert!(store
            .data_path("geosite-expand.dat", &old.geosite_sha256)
            .exists());
        assert!(store
            .data_path("geoip-full.dat", &old.geoip_sha256)
            .exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn publication_is_cas_and_preserves_old_pair() {
        let mut random = [0; 16];
        SystemRandom::new().fill(&mut random).unwrap();
        let dir = std::env::temp_dir().join(format!("theia-geodata-{}", hex(&random)));
        fs::create_dir(&dir).unwrap();
        let store = Store::new(dir.clone()).unwrap();
        let site = dat(b'X');
        let ip = ip();
        let manifest = Manifest {
            release: "20261126014317".into(),
            geosite_sha256: hash(&site),
            geoip_sha256: hash(&ip),
        };
        let pair = Pair::verified(manifest.clone(), site.clone(), ip.clone(), &[]).unwrap();
        assert!(store.load(&[]).unwrap().is_none());
        store.publish(&pair, None).unwrap();
        let baseline = store.current_bytes().unwrap().unwrap();
        let next_site = dat(b'Y');
        let mut next = manifest.clone();
        next.release = "20261127014317".into();
        next.geosite_sha256 = hash(&next_site);
        let next = Pair::verified(next, next_site, ip.clone(), &[]).unwrap();
        assert!(store.publish(&next, None).is_err());
        assert_eq!(store.load(&[]).unwrap().unwrap().manifest(), &manifest);
        store.publish(&next, Some(&baseline)).unwrap();
        assert_eq!(
            store.load(&[]).unwrap().unwrap().manifest(),
            next.manifest()
        );
        assert!(Pair::verified(manifest, site, b"wrong".to_vec(), &[]).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
