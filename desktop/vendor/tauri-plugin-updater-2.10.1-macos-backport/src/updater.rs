// Copyright 2019-2023 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use std::{
    collections::HashMap,
    ffi::OsString,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

#[cfg(target_os = "windows")]
use std::ffi::OsStr;
#[cfg(any(target_os = "macos", all(target_os = "windows", feature = "zip")))]
use std::io::Cursor;

use futures_util::StreamExt;
use http::{header::ACCEPT, HeaderName};
use percent_encoding::{AsciiSet, CONTROLS};
use reqwest::{
    header::{HeaderMap, HeaderValue},
    ClientBuilder, StatusCode,
};
use semver::Version;
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize};
use tauri::{
    utils::{
        config::BundleType,
        platform::{bundle_type, current_exe},
    },
    AppHandle, Resource, Runtime,
};
use time::OffsetDateTime;
use url::Url;

use crate::{
    error::{Error, Result},
    Config,
};

const UPDATER_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

#[cfg(not(any(
    feature = "rustls-tls",
    feature = "native-tls",
    feature = "native-tls-vendored"
)))]
compile_error!("This ShellX updater requires rustls-tls, native-tls, or native-tls-vendored");

fn enforce_tls_validation(request: ClientBuilder) -> ClientBuilder {
    // Preconfigured TLS backends ignore reqwest's verification flags. Restore
    // a standard backend as well as both flags after the client hook.
    #[cfg(any(feature = "native-tls", feature = "native-tls-vendored"))]
    let request = request.use_native_tls();
    #[cfg(all(
        feature = "rustls-tls",
        not(any(feature = "native-tls", feature = "native-tls-vendored"))
    ))]
    let request = request.use_rustls_tls();

    request
        .danger_accept_invalid_certs(false)
        .danger_accept_invalid_hostnames(false)
}

#[cfg(all(test, feature = "rustls-tls"))]
#[path = "updater/tls_validation_tests.rs"]
mod tls_validation_tests;

mod download_bounds;
mod installed_package;
mod release_url_policy;
mod signed_release;

#[derive(Copy, Clone)]
pub enum Installer {
    AppImage,
    Deb,
    Rpm,

    App,

    Msi,
    Nsis,
}

impl Installer {
    fn name(self) -> &'static str {
        match self {
            Self::AppImage => "appimage",
            Self::Deb => "deb",
            Self::Rpm => "rpm",
            Self::App => "app",
            Self::Msi => "msi",
            Self::Nsis => "nsis",
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ReleaseManifestPlatform {
    /// Download URL for the platform
    pub url: Url,
    /// Signature for the platform
    pub signature: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum RemoteReleaseInner {
    Dynamic(ReleaseManifestPlatform),
    Static {
        platforms: HashMap<String, ReleaseManifestPlatform>,
    },
}

/// Information about a release returned by the remote update server.
///
/// This type can have one of two shapes: Server Format (Dynamic Format) and Static Format.
#[derive(Debug, Clone)]
pub struct RemoteRelease {
    /// Version to install.
    pub version: Version,
    /// Release notes.
    pub notes: Option<String>,
    /// Release date.
    pub pub_date: Option<OffsetDateTime>,
    /// Release data.
    pub data: RemoteReleaseInner,
}

impl RemoteRelease {
    /// The release's download URL for the given target.
    pub fn download_url(&self, target: &str) -> Result<&Url> {
        match self.data {
            RemoteReleaseInner::Dynamic(ref platform) => Ok(&platform.url),
            RemoteReleaseInner::Static { ref platforms } => platforms
                .get(target)
                .map_or(Err(Error::TargetNotFound(target.to_string())), |p| {
                    Ok(&p.url)
                }),
        }
    }

    /// The release's signature for the given target.
    pub fn signature(&self, target: &str) -> Result<&String> {
        match self.data {
            RemoteReleaseInner::Dynamic(ref platform) => Ok(&platform.signature),
            RemoteReleaseInner::Static { ref platforms } => platforms
                .get(target)
                .map_or(Err(Error::TargetNotFound(target.to_string())), |platform| {
                    Ok(&platform.signature)
                }),
        }
    }
}

pub type OnBeforeExit = Arc<dyn Fn() + Send + Sync + 'static>;
pub type OnBeforeRequest = Arc<dyn Fn(ClientBuilder) -> ClientBuilder + Send + Sync + 'static>;
pub type VersionComparator = Arc<dyn Fn(Version, RemoteRelease) -> bool + Send + Sync>;
type MainThreadClosure = Box<dyn FnOnce() + Send + Sync + 'static>;
type RunOnMainThread =
    Box<dyn Fn(MainThreadClosure) -> std::result::Result<(), tauri::Error> + Send + Sync + 'static>;

pub struct UpdaterBuilder {
    #[allow(dead_code)]
    run_on_main_thread: RunOnMainThread,
    app_name: String,
    current_version: Version,
    config: Config,
    pub(crate) version_comparator: Option<VersionComparator>,
    executable_path: Option<PathBuf>,
    target: Option<String>,
    endpoints: Option<Vec<Url>>,
    headers: HeaderMap,
    timeout: Option<Duration>,
    proxy: Option<Url>,
    no_proxy: bool,
    installer_args: Vec<OsString>,
    current_exe_args: Vec<OsString>,
    on_before_exit: Option<OnBeforeExit>,
    configure_client: Option<OnBeforeRequest>,
}

impl UpdaterBuilder {
    pub(crate) fn new<R: Runtime>(app: &AppHandle<R>, config: crate::Config) -> Self {
        let app_ = app.clone();
        let run_on_main_thread = move |f| app_.run_on_main_thread(f);
        Self {
            run_on_main_thread: Box::new(run_on_main_thread),
            installer_args: config
                .windows
                .as_ref()
                .map(|w| w.installer_args.clone())
                .unwrap_or_default(),
            current_exe_args: Vec::new(),
            app_name: app.package_info().name.clone(),
            current_version: app.package_info().version.clone(),
            config,
            version_comparator: None,
            executable_path: None,
            target: None,
            endpoints: None,
            headers: Default::default(),
            timeout: None,
            proxy: None,
            no_proxy: false,
            on_before_exit: None,
            configure_client: None,
        }
    }

    pub fn version_comparator<F: Fn(Version, RemoteRelease) -> bool + Send + Sync + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.version_comparator = Some(Arc::new(f));
        self
    }

    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.target.replace(target.into());
        self
    }

    pub fn endpoints(mut self, endpoints: Vec<Url>) -> Result<Self> {
        crate::config::validate_endpoints(
            &endpoints,
            self.config.dangerous_insecure_transport_protocol,
        )?;

        self.endpoints.replace(endpoints);
        Ok(self)
    }

    pub fn executable_path<P: AsRef<Path>>(mut self, p: P) -> Self {
        self.executable_path.replace(p.as_ref().into());
        self
    }

    pub fn header<K, V>(mut self, key: K, value: V) -> Result<Self>
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        let key: std::result::Result<HeaderName, http::Error> = key.try_into().map_err(Into::into);
        let value: std::result::Result<HeaderValue, http::Error> =
            value.try_into().map_err(Into::into);
        self.headers.insert(key?, value?);

        Ok(self)
    }

    pub fn headers(mut self, headers: HeaderMap) -> Self {
        self.headers = headers;
        self
    }

    pub fn clear_headers(mut self) -> Self {
        self.headers.clear();
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn proxy(mut self, proxy: Url) -> Self {
        self.proxy.replace(proxy);
        self
    }

    /// Clear all proxies. See [`reqwest::ClientBuilder::no_proxy`](https://docs.rs/reqwest/latest/reqwest/struct.ClientBuilder.html#method.no_proxy).
    pub fn no_proxy(mut self) -> Self {
        self.no_proxy = true;
        self
    }

    pub fn pubkey<S: Into<String>>(mut self, pubkey: S) -> Self {
        self.config.pubkey = pubkey.into();
        self
    }

    /// Adds an argument to pass to the Windows installer.
    pub fn installer_arg<S>(mut self, arg: S) -> Self
    where
        S: Into<OsString>,
    {
        self.installer_args.push(arg.into());
        self
    }

    /// Adds multiple arguments to pass to the Windows installer.
    pub fn installer_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.installer_args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Removes all the additional arguments to pass to the Windows installer.
    ///
    /// Note: this only removes the additional arguments added through
    /// [`Self::installer_arg`], [`crate::Builder::installer_arg`]
    /// and the `plugins > updater > windows > installerArgs` config,
    /// not the ones managed by us (e.g. `/UPDATER` flag passed to the NSIS installer)
    pub fn clear_installer_args(mut self) -> Self {
        self.installer_args.clear();
        self
    }

    /// Function to run before we run the installer and exit the app through `std::process::exit(0)` on Windows
    pub fn on_before_exit<F: Fn() + Send + Sync + 'static>(mut self, f: F) -> Self {
        self.on_before_exit.replace(Arc::new(f));
        self
    }

    /// Allows you to modify the `reqwest` client builder before the HTTP request is sent.
    ///
    /// This ShellX vendor restores standard TLS verification and its release URL
    /// policy after the hook. Preconfigured TLS backends and insecure TLS flags
    /// are not retained.
    ///
    /// Note that `reqwest` crate may be updated in minor releases of tauri-plugin-updater.
    /// Therefore it's recommended to pin the plugin to at least a minor version when you're using `configure_client`.
    pub fn configure_client<F: Fn(ClientBuilder) -> ClientBuilder + Send + Sync + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.configure_client.replace(Arc::new(f));
        self
    }

    pub fn build(self) -> Result<Updater> {
        let endpoints = self
            .endpoints
            .unwrap_or_else(|| self.config.endpoints.clone());

        if endpoints.is_empty() {
            return Err(Error::EmptyEndpoints);
        };

        let arch = updater_arch().ok_or(Error::UnsupportedArch)?;

        let executable_path = self.executable_path.clone().unwrap_or(current_exe()?);

        // Get the extract_path from the provided executable_path
        let extract_path = if cfg!(target_os = "linux") {
            executable_path
        } else {
            extract_path_from_executable(&executable_path)?
        };

        Ok(Updater {
            run_on_main_thread: Arc::new(self.run_on_main_thread),
            config: self.config,
            app_name: self.app_name,
            current_version: self.current_version,
            version_comparator: self.version_comparator,
            timeout: self.timeout,
            proxy: self.proxy,
            no_proxy: self.no_proxy,
            endpoints,
            installer_args: self.installer_args,
            current_exe_args: self.current_exe_args,
            arch,
            target: self.target,
            headers: self.headers,
            extract_path,
            on_before_exit: self.on_before_exit,
            configure_client: self.configure_client,
        })
    }
}

impl UpdaterBuilder {
    pub(crate) fn current_exe_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.current_exe_args
            .extend(args.into_iter().map(Into::into));
        self
    }
}

pub struct Updater {
    #[allow(dead_code)]
    run_on_main_thread: Arc<RunOnMainThread>,
    config: Config,
    app_name: String,
    current_version: Version,
    version_comparator: Option<VersionComparator>,
    timeout: Option<Duration>,
    proxy: Option<Url>,
    no_proxy: bool,
    endpoints: Vec<Url>,
    arch: &'static str,
    // The `{{target}}` variable we replace in the endpoint and serach for in the JSON,
    // this is either the user provided target or the current operating system by default
    target: Option<String>,
    headers: HeaderMap,
    extract_path: PathBuf,
    on_before_exit: Option<OnBeforeExit>,
    configure_client: Option<OnBeforeRequest>,
    #[allow(unused)]
    installer_args: Vec<OsString>,
    #[allow(unused)]
    current_exe_args: Vec<OsString>,
}

impl Updater {
    pub async fn check(&self) -> Result<Option<Update>> {
        // we want JSON only
        let mut headers = self.headers.clone();
        if !headers.contains_key(ACCEPT) {
            headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        }

        // Set SSL certs for linux if they aren't available.
        #[cfg(target_os = "linux")]
        {
            if std::env::var_os("SSL_CERT_FILE").is_none() {
                std::env::set_var("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt");
            }
            if std::env::var_os("SSL_CERT_DIR").is_none() {
                std::env::set_var("SSL_CERT_DIR", "/etc/ssl/certs");
            }
        }
        let target = if let Some(target) = &self.target {
            target
        } else {
            updater_os().ok_or(Error::UnsupportedOs)?
        };

        let mut remote_release: Option<RemoteRelease> = None;
        let mut raw_json: Option<serde_json::Value> = None;
        let mut last_error: Option<Error> = None;
        for url in &self.endpoints {
            // replace {{current_version}}, {{target}}, {{arch}} and {{bundle_type}} in the provided URL
            // this is useful if we need to query example
            // https://releases.myapp.com/update/{{target}}/{{arch}}/{{current_version}}
            // will be translated into ->
            // https://releases.myapp.com/update/darwin/aarch64/1.0.0
            // The main objective is if the update URL is defined via the Cargo.toml
            // the URL will be generated dynamically
            let version = self.current_version.to_string();
            let version = version.as_bytes();
            const CONTROLS_ADD: &AsciiSet = &CONTROLS.add(b'+');
            let encoded_version = percent_encoding::percent_encode(version, CONTROLS_ADD);
            let encoded_version = encoded_version.to_string();
            let installer = installed_package::current(&self.extract_path)
                .map(|i| i.name())
                .unwrap_or("unknown");

            let url: Url = url
                .to_string()
                // url::Url automatically url-encodes the path components
                .replace("%7B%7Bcurrent_version%7D%7D", &encoded_version)
                .replace("%7B%7Btarget%7D%7D", target)
                .replace("%7B%7Barch%7D%7D", self.arch)
                .replace("%7B%7Bbundle_type%7D%7D", installer)
                // but not query parameters
                .replace("{{current_version}}", &encoded_version)
                .replace("{{target}}", target)
                .replace("{{arch}}", self.arch)
                .replace("{{bundle_type}}", installer)
                .parse()?;

            release_url_policy::validate_feed_endpoint(&url).map_err(Error::InvalidReleaseUrl)?;

            log::debug!("checking for updates {url}");

            #[cfg(feature = "rustls-tls")]
            if rustls::crypto::CryptoProvider::get_default().is_none() {
                // This can only fail if there is already a default provider which we checked for already.
                let _ = rustls::crypto::ring::default_provider().install_default();
            }

            let mut request = ClientBuilder::new().user_agent(UPDATER_USER_AGENT);
            if let Some(timeout) = self.timeout {
                request = request.timeout(timeout);
            }
            if self.no_proxy {
                log::debug!("disabling proxy");
                request = request.no_proxy();
            } else if let Some(ref proxy) = self.proxy {
                log::debug!("using proxy {proxy}");
                let proxy = reqwest::Proxy::all(proxy.as_str())?;
                request = request.proxy(proxy);
            }

            if let Some(ref configure_client) = self.configure_client {
                request = configure_client(request);
            }
            // Keep the application-specific transport policy last: a caller's
            // client hook must not be able to restore reqwest's open redirect
            // behavior or restore referrer propagation.
            request = request
                .redirect(release_url_policy::feed_redirect_policy())
                .referer(false);
            request = enforce_tls_validation(request);

            let response = request
                .build()?
                .get(url)
                .headers(headers.clone())
                .send()
                .await;

            match response {
                Ok(res) => {
                    if res.status().is_success() {
                        // no updates found!
                        if StatusCode::NO_CONTENT == res.status() {
                            log::debug!("update endpoint returned 204 No Content");
                            return Ok(None);
                        };

                        let content_length = res.content_length();
                        let mut update_body = download_bounds::BoundedBody::new(
                            content_length,
                            download_bounds::MAX_UPDATE_FEED_BYTES,
                            "update feed response",
                        )?;
                        let mut stream = res.bytes_stream();
                        while let Some(chunk) = stream.next().await {
                            update_body.push(&chunk?)?;
                        }
                        let update_response: serde_json::Value =
                            serde_json::from_slice(update_body.as_bytes())?;
                        log::debug!("update response: {update_response:?}");
                        raw_json = Some(update_response.clone());
                        match serde_json::from_value::<RemoteRelease>(update_response)
                            .map_err(Into::into)
                        {
                            Ok(release) => {
                                log::debug!("parsed release response {release:?}");
                                last_error = None;
                                remote_release = Some(release);
                                // we found a release, break the loop
                                break;
                            }
                            Err(err) => {
                                log::error!("failed to deserialize update response: {err}");
                                last_error = Some(err)
                            }
                        }
                    } else {
                        log::error!(
                            "update endpoint did not respond with a successful status code"
                        );
                    }
                }
                Err(err) => {
                    log::error!("failed to check for updates: {err}");
                    last_error = Some(err.into())
                }
            }
        }

        // Last error is cleaned on success.
        // Shouldn't be triggered if we had a successfull call
        if let Some(error) = last_error {
            return Err(error);
        }

        // Extracted remote metadata
        let release = remote_release.ok_or(Error::ReleaseNotFound)?;

        let should_update = match self.version_comparator.as_ref() {
            Some(comparator) => comparator(self.current_version.clone(), release.clone()),
            None => release.version > self.current_version,
        };

        let installer = installed_package::current(&self.extract_path);
        let (download_url, signature) = self.get_urls(&release, &installer)?;

        let update = if should_update {
            let platform = installed_release_platform(installer.ok_or_else(|| {
                Error::InvalidReleaseUrl("unknown installed bundle type".into())
            })?)?;
            release_url_policy::validate_artifact_url(download_url, &release.version, &platform)
                .map_err(Error::InvalidReleaseUrl)?;
            Some(Update {
                run_on_main_thread: self.run_on_main_thread.clone(),
                config: self.config.clone(),
                on_before_exit: self.on_before_exit.clone(),
                app_name: self.app_name.clone(),
                current_version: self.current_version.to_string(),
                target: target.to_owned(),
                extract_path: self.extract_path.clone(),
                version: release.version.to_string(),
                date: release.pub_date,
                download_url: download_url.clone(),
                signature: signature.to_owned(),
                body: release.notes,
                raw_json: raw_json.unwrap(),
                timeout: None,
                proxy: self.proxy.clone(),
                no_proxy: self.no_proxy,
                headers: self.headers.clone(),
                installer_args: self.installer_args.clone(),
                current_exe_args: self.current_exe_args.clone(),
                configure_client: self.configure_client.clone(),
            })
        } else {
            None
        };

        Ok(update)
    }

    fn get_urls<'a>(
        &self,
        release: &'a RemoteRelease,
        installer: &Option<Installer>,
    ) -> Result<(&'a Url, &'a String)> {
        // Use the user provided target
        if let Some(target) = &self.target {
            return Ok((release.download_url(target)?, release.signature(target)?));
        }

        // Or else we search for [`{os}-{arch}-{installer}`, `{os}-{arch}`] in order
        let os = updater_os().ok_or(Error::UnsupportedOs)?;
        let arch = self.arch;
        let mut targets = Vec::new();
        if let Some(installer) = installer {
            let installer = installer.name();
            targets.push(format!("{os}-{arch}-{installer}"));
        }
        targets.push(format!("{os}-{arch}"));

        for target in &targets {
            log::debug!("Searching for updater target '{target}' in release data");
            if let (Ok(download_url), Ok(signature)) =
                (release.download_url(target), release.signature(target))
            {
                return Ok((download_url, signature));
            };
        }

        Err(Error::TargetsNotFound(targets))
    }
}

fn installed_release_platform(installer: Installer) -> Result<String> {
    Ok(format!(
        "{}-{}-{}",
        updater_os().ok_or(Error::UnsupportedOs)?,
        std::env::consts::ARCH,
        installer.name()
    ))
}

#[derive(Clone)]
pub struct Update {
    #[allow(dead_code)]
    run_on_main_thread: Arc<RunOnMainThread>,
    config: Config,
    #[allow(unused)]
    on_before_exit: Option<OnBeforeExit>,
    /// Update description
    pub body: Option<String>,
    /// Version used to check for update
    pub current_version: String,
    /// Version announced
    pub version: String,
    /// Update publish date
    pub date: Option<OffsetDateTime>,
    /// The `{{target}}` variable we replace in the endpoint and search for in the JSON,
    /// this is either the user provided target or the current operating system by default
    pub target: String,
    /// Download URL announced
    pub download_url: Url,
    /// Signature announced
    pub signature: String,
    /// The raw version of server's JSON response. Useful if the response contains additional fields that the updater doesn't handle.
    pub raw_json: serde_json::Value,
    /// Request timeout
    pub timeout: Option<Duration>,
    /// Request proxy
    pub proxy: Option<Url>,
    /// Disable system proxy
    pub no_proxy: bool,
    /// Request headers
    pub headers: HeaderMap,
    /// Extract path
    #[allow(unused)]
    extract_path: PathBuf,
    /// App name, used for creating named tempfiles on Windows
    #[allow(unused)]
    app_name: String,
    #[allow(unused)]
    installer_args: Vec<OsString>,
    #[allow(unused)]
    current_exe_args: Vec<OsString>,
    configure_client: Option<OnBeforeRequest>,
}

impl Resource for Update {}

impl Update {
    /// Downloads the updater package, verifies it then return it as bytes.
    ///
    /// Use [`Update::install`] to install it
    pub async fn download<C: FnMut(usize, Option<u64>), D: FnOnce()>(
        &self,
        mut on_chunk: C,
        on_download_finish: D,
    ) -> Result<Vec<u8>> {
        // set our headers
        let mut headers = self.headers.clone();
        if !headers.contains_key(ACCEPT) {
            headers.insert(ACCEPT, HeaderValue::from_static("application/octet-stream"));
        }

        let version = Version::parse(&self.version)?;
        let platform = installed_release_platform(
            installed_package::current(&self.extract_path)
                .ok_or_else(|| Error::InvalidReleaseUrl("unknown installed bundle type".into()))?,
        )?;
        // Update is public and its URL can be changed after `check`; recheck
        // immediately before the first package request.
        release_url_policy::validate_artifact_url(&self.download_url, &version, &platform)
            .map_err(Error::InvalidReleaseUrl)?;
        let redirect = release_url_policy::artifact_redirect_policy(&version, &platform)
            .map_err(Error::InvalidReleaseUrl)?;

        let mut request = ClientBuilder::new().user_agent(UPDATER_USER_AGENT);
        if let Some(timeout) = self.timeout {
            request = request.timeout(timeout);
        }
        if self.no_proxy {
            request = request.no_proxy();
        } else if let Some(ref proxy) = self.proxy {
            let proxy = reqwest::Proxy::all(proxy.as_str())?;
            request = request.proxy(proxy);
        }
        if let Some(ref configure_client) = self.configure_client {
            request = configure_client(request);
        }
        request = request.redirect(redirect).referer(false);
        request = enforce_tls_validation(request);
        let response = request
            .build()?
            .get(self.download_url.clone())
            .headers(headers)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(Error::Network(format!(
                "Download request failed with status: {}",
                response.status()
            )));
        }

        let content_length: Option<u64> = response
            .headers()
            .get("Content-Length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok());

        let mut buffer = download_bounds::BoundedBody::new(
            content_length,
            download_bounds::MAX_COMPRESSED_INSTALLER_BYTES,
            "compressed updater installer",
        )?;

        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            buffer.push_and_then(&chunk, || on_chunk(chunk.len(), content_length))?;
        }
        on_download_finish();

        self.verify_signed_release(buffer.as_bytes())?;

        Ok(buffer.into_vec())
    }

    /// Installs the updater package downloaded by [`Update::download`]
    pub fn install(&self, bytes: impl AsRef<[u8]>) -> Result<()> {
        // Enforce at the terminal boundary too: callers may retain downloaded
        // bytes, replace them, or call install without using download at all.
        self.verify_signed_release(bytes.as_ref())?;
        self.install_inner(bytes.as_ref())
    }

    fn verify_signed_release(&self, bytes: &[u8]) -> Result<()> {
        let installer = installed_package::current(&self.extract_path)
            .ok_or_else(|| Error::InvalidSignedRelease("unknown installed bundle type".into()))?;
        let platform = installed_release_platform(installer)?;
        signed_release::verify(
            bytes,
            &self.signature,
            &self.config.pubkey,
            &self.current_version,
            &self.version,
            &platform,
            &self.download_url,
        )
        .map_err(Error::InvalidSignedRelease)
    }

    /// Downloads and installs the updater package
    pub async fn download_and_install<C: FnMut(usize, Option<u64>), D: FnOnce()>(
        &self,
        on_chunk: C,
        on_download_finish: D,
    ) -> Result<()> {
        let bytes = self.download(on_chunk, on_download_finish).await?;
        self.install(bytes)
    }

    #[cfg(mobile)]
    fn install_inner(&self, _bytes: &[u8]) -> Result<()> {
        Ok(())
    }
}

#[cfg(windows)]
enum WindowsUpdaterType {
    Nsis {
        path: PathBuf,
        #[allow(unused)]
        temp: Option<tempfile::TempPath>,
    },
    Msi {
        path: PathBuf,
        #[allow(unused)]
        temp: Option<tempfile::TempPath>,
    },
}

#[cfg(windows)]
impl WindowsUpdaterType {
    fn nsis(path: PathBuf, temp: Option<tempfile::TempPath>) -> Self {
        Self::Nsis { path, temp }
    }

    fn msi(path: PathBuf, temp: Option<tempfile::TempPath>) -> Self {
        Self::Msi {
            path: path.wrap_in_quotes(),
            temp,
        }
    }
}

#[cfg(windows)]
impl Config {
    fn install_mode(&self) -> crate::config::WindowsUpdateInstallMode {
        self.windows
            .as_ref()
            .map(|w| w.install_mode.clone())
            .unwrap_or_default()
    }
}

/// Windows
#[cfg(windows)]
impl Update {
    /// ### Expected structure:
    /// ├── [AppName]_[version]_x64.msi              # Application MSI
    /// ├── [AppName]_[version]_x64-setup.exe        # NSIS installer
    /// ├── [AppName]_[version]_x64.msi.zip          # ZIP generated by tauri-bundler
    /// │   └──[AppName]_[version]_x64.msi           # Application MSI
    /// ├── [AppName]_[version]_x64-setup.exe.zip          # ZIP generated by tauri-bundler
    /// │   └──[AppName]_[version]_x64-setup.exe           # NSIS installer
    /// └── ...
    fn install_inner(&self, bytes: &[u8]) -> Result<()> {
        use std::iter::once;
        use windows_sys::{
            w,
            Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOW},
        };

        let updater_type = self.extract(bytes)?;

        let install_mode = self.config.install_mode();
        let current_args = &self.current_exe_args()[1..];
        let msi_args;
        let nsis_args;

        let installer_args: Vec<&OsStr> = match &updater_type {
            WindowsUpdaterType::Nsis { .. } => {
                nsis_args = current_args
                    .iter()
                    .map(escape_nsis_current_exe_arg)
                    .collect::<Vec<_>>();

                install_mode
                    .nsis_args()
                    .iter()
                    .map(OsStr::new)
                    .chain(once(OsStr::new("/UPDATE")))
                    .chain(once(OsStr::new("/ARGS")))
                    .chain(nsis_args.iter().map(OsStr::new))
                    .chain(self.installer_args())
                    .collect()
            }
            WindowsUpdaterType::Msi { path, .. } => {
                let escaped_args = current_args
                    .iter()
                    .map(escape_msi_property_arg)
                    .collect::<Vec<_>>()
                    .join(" ");
                msi_args = OsString::from(format!("LAUNCHAPPARGS=\"{escaped_args}\""));

                [OsStr::new("/i"), path.as_os_str()]
                    .into_iter()
                    .chain(install_mode.msiexec_args().iter().map(OsStr::new))
                    .chain(once(OsStr::new("/promptrestart")))
                    .chain(self.installer_args())
                    .chain(once(OsStr::new("AUTOLAUNCHAPP=True")))
                    .chain(once(msi_args.as_os_str()))
                    .collect()
            }
        };

        if let Some(on_before_exit) = self.on_before_exit.as_ref() {
            log::debug!("running on_before_exit hook");
            on_before_exit();
        }

        let file = match &updater_type {
            WindowsUpdaterType::Nsis { path, .. } => path.as_os_str().to_os_string(),
            WindowsUpdaterType::Msi { .. } => std::env::var("SYSTEMROOT").as_ref().map_or_else(
                |_| OsString::from("msiexec.exe"),
                |p| OsString::from(format!("{p}\\System32\\msiexec.exe")),
            ),
        };
        let file = encode_wide(file);

        let parameters = installer_args.join(OsStr::new(" "));
        let parameters = encode_wide(parameters);

        unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                w!("open"),
                file.as_ptr(),
                parameters.as_ptr(),
                std::ptr::null(),
                SW_SHOW,
            )
        };

        std::process::exit(0);
    }

    fn installer_args(&self) -> Vec<&OsStr> {
        self.installer_args
            .iter()
            .map(OsStr::new)
            .collect::<Vec<_>>()
    }

    fn current_exe_args(&self) -> Vec<&OsStr> {
        self.current_exe_args
            .iter()
            .map(OsStr::new)
            .collect::<Vec<_>>()
    }

    fn extract(&self, bytes: &[u8]) -> Result<WindowsUpdaterType> {
        #[cfg(feature = "zip")]
        if infer::archive::is_zip(bytes) {
            return self.extract_zip(bytes);
        }

        self.extract_exe(bytes)
    }

    fn make_temp_dir(&self) -> Result<PathBuf> {
        Ok(tempfile::Builder::new()
            .prefix(&format!("{}-{}-updater-", self.app_name, self.version))
            .tempdir()?
            .keep())
    }

    #[cfg(feature = "zip")]
    fn extract_zip(&self, bytes: &[u8]) -> Result<WindowsUpdaterType> {
        let temp_dir = self.make_temp_dir()?;

        let archive = Cursor::new(bytes);
        let mut extractor = zip::ZipArchive::new(archive)?;
        extractor.extract(&temp_dir)?;

        let paths = std::fs::read_dir(&temp_dir)?;
        for path in paths {
            let path = path?.path();
            let ext = path.extension();
            if ext == Some(OsStr::new("exe")) {
                return Ok(WindowsUpdaterType::nsis(path, None));
            } else if ext == Some(OsStr::new("msi")) {
                return Ok(WindowsUpdaterType::msi(path, None));
            }
        }

        Err(crate::Error::BinaryNotFoundInArchive)
    }

    fn extract_exe(&self, bytes: &[u8]) -> Result<WindowsUpdaterType> {
        if infer::app::is_exe(bytes) {
            let (path, temp) = self.write_to_temp(bytes, ".exe")?;
            Ok(WindowsUpdaterType::nsis(path, temp))
        } else if infer::archive::is_msi(bytes) {
            let (path, temp) = self.write_to_temp(bytes, ".msi")?;
            Ok(WindowsUpdaterType::msi(path, temp))
        } else {
            Err(crate::Error::InvalidUpdaterFormat)
        }
    }

    fn write_to_temp(
        &self,
        bytes: &[u8],
        ext: &str,
    ) -> Result<(PathBuf, Option<tempfile::TempPath>)> {
        use std::io::Write;

        let temp_dir = self.make_temp_dir()?;
        let mut temp_file = tempfile::Builder::new()
            .prefix(&format!("{}-{}-installer", self.app_name, self.version))
            .suffix(ext)
            .rand_bytes(0)
            .tempfile_in(temp_dir)?;
        temp_file.write_all(bytes)?;

        let temp = temp_file.into_temp_path();
        Ok((temp.to_path_buf(), Some(temp)))
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
))]
mod linux_replacement;

#[cfg(any(
    target_os = "linux",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
))]
mod linux_privileges;

/// Linux (AppImage, Deb, RPM)
#[cfg(any(
    target_os = "linux",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
))]
impl Update {
    /// ### Expected structure:
    /// ├── [AppName]_[version]_amd64.AppImage.tar.gz    # GZ generated by tauri-bundler
    /// │   └──[AppName]_[version]_amd64.AppImage        # Application AppImage
    /// ├── [AppName]_[version]_amd64.deb                # Debian package
    /// ├── [AppName]_[version]_amd64.rpm                # RPM package
    /// └── ...
    ///
    fn install_inner(&self, bytes: &[u8]) -> Result<()> {
        match installed_package::current(&self.extract_path) {
            Some(Installer::Deb) => self.install_deb(bytes),
            Some(Installer::Rpm) => self.install_rpm(bytes),
            _ => self.install_appimage(bytes),
        }
    }

    fn install_appimage(&self, bytes: &[u8]) -> Result<()> {
        linux_replacement::install_appimage(&self.extract_path, bytes)
    }

    fn install_deb(&self, bytes: &[u8]) -> Result<()> {
        // First verify the bytes are actually a .deb package
        if !infer::archive::is_deb(bytes) {
            log::warn!("update is not a valid deb package");
            return Err(Error::InvalidUpdaterFormat);
        }

        linux_privileges::install_package(bytes, "/usr/bin/dpkg", "-i")
    }

    fn install_rpm(&self, bytes: &[u8]) -> Result<()> {
        // First verify the bytes are actually a .rpm package
        if !infer::archive::is_rpm(bytes) {
            return Err(Error::InvalidUpdaterFormat);
        }
        linux_privileges::install_package(bytes, "/usr/bin/rpm", "-U")
    }
}

/// MacOS
#[cfg(target_os = "macos")]
impl Update {
    /// ### Expected structure:
    /// ├── [AppName]_[version]_x64.app.tar.gz       # GZ generated by tauri-bundler
    /// │   └──[AppName].app                         # Main application
    /// │      └── Contents                          # Application contents...
    /// │          └── ...
    /// └── ...
    fn install_inner(&self, bytes: &[u8]) -> Result<()> {
        use flate2::read::GzDecoder;
        use sha2::{Digest, Sha256};

        let archive_digest = format!("{:x}", Sha256::digest(bytes));
        let mut archive_file = tempfile::Builder::new()
            .prefix("tauri_verified_archive")
            .tempfile()?;
        std::io::Write::write_all(&mut archive_file, bytes)?;

        let cursor = Cursor::new(bytes);
        let mut extracted_files: Vec<PathBuf> = Vec::new();

        // Extract the signed update before moving the installed app.
        let tmp_extract_dir = tempfile::Builder::new()
            .prefix("tauri_updated_app")
            .tempdir()?;

        let decoder = GzDecoder::new(cursor);
        let mut archive = tar::Archive::new(decoder);

        // Extract files to temporary directory
        for entry in archive.entries()? {
            let mut entry = entry?;
            macos_replacement::macos_validate_archive_entry(&mut entry)?;
            let collected_path: PathBuf = entry.path()?.iter().skip(1).collect();
            let extraction_path = tmp_extract_dir.path().join(&collected_path);

            // Ensure parent directories exist
            if let Some(parent) = extraction_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            if let Err(err) = entry.unpack(&extraction_path) {
                // Cleanup on error
                std::fs::remove_dir_all(tmp_extract_dir.path()).ok();
                return Err(err.into());
            }
            extracted_files.push(extraction_path);
        }

        #[cfg(target_os = "macos")]
        macos_replacement::macos_validate_path(&self.extract_path)?;

        match macos_replacement::macos_stage_verified_replacement(
            &self.extract_path,
            tmp_extract_dir.path(),
        ) {
            Ok(staged_replacement) => {
                match macos_replacement::macos_backup_directory(&self.extract_path) {
                    Ok(backup_directory) => {
                        let backup_directory = backup_directory.keep();
                        let backup_path = backup_directory.join("current_app");
                        match macos_replacement::macos_rename_without_replacing(
                            &self.extract_path,
                            &backup_path,
                        ) {
                            Ok(()) => {
                                let replacement =
                                    macos_replacement::macos_replace_staged_with_rollback(
                                        staged_replacement.path(),
                                        &self.extract_path,
                                        &backup_path,
                                    );
                                if replacement.is_ok() {
                                    let _ = std::fs::remove_dir_all(&backup_directory);
                                }
                                replacement?;
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                                log::debug!("app installation needs admin privileges");
                                let privileged_backup =
                                    macos_replacement::macos_privileged_backup_path(
                                        &self.extract_path,
                                        staged_replacement.path(),
                                    )?;
                                let replacement =
                                    macos_replacement::macos_replace_with_authorization(
                                        &self.extract_path,
                                        archive_file.path(),
                                        &macos_replacement::macos_privileged_staging_path(
                                            &self.extract_path,
                                            staged_replacement.path(),
                                        )?,
                                        &privileged_backup,
                                        &archive_digest,
                                        &self.run_on_main_thread,
                                    );
                                let _ = std::fs::remove_dir(&backup_directory);
                                replacement?;
                            }
                            Err(error) => {
                                let _ = std::fs::remove_dir(&backup_directory);
                                return Err(error.into());
                            }
                        }
                    }
                    Err(Error::Io(error))
                        if error.kind() == std::io::ErrorKind::PermissionDenied =>
                    {
                        log::debug!("app installation needs admin privileges");
                        let privileged_backup = macos_replacement::macos_privileged_backup_path(
                            &self.extract_path,
                            staged_replacement.path(),
                        )?;
                        macos_replacement::macos_replace_with_authorization(
                            &self.extract_path,
                            archive_file.path(),
                            &macos_replacement::macos_privileged_staging_path(
                                &self.extract_path,
                                staged_replacement.path(),
                            )?,
                            &privileged_backup,
                            &archive_digest,
                            &self.run_on_main_thread,
                        )?;
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                log::debug!("app installation needs admin privileges");
                let privileged_staging = macos_replacement::macos_privileged_staging_path(
                    &self.extract_path,
                    tmp_extract_dir.path(),
                )?;
                let privileged_backup = macos_replacement::macos_privileged_backup_path(
                    &self.extract_path,
                    tmp_extract_dir.path(),
                )?;
                macos_replacement::macos_replace_with_authorization(
                    &self.extract_path,
                    archive_file.path(),
                    &privileged_staging,
                    &privileged_backup,
                    &archive_digest,
                    &self.run_on_main_thread,
                )?;
            }
            Err(error) => return Err(error),
        }

        let _ = std::process::Command::new("/usr/bin/touch")
            .arg(&self.extract_path)
            .status();

        Ok(())
    }
}

#[cfg(target_os = "macos")]
mod macos_replacement;

/// Gets the base target string used by the updater. If bundle type is available it
/// will be added to this string when selecting the download URL and signature.
/// `tauri::utils::platform::bundle_type` method is used to obtain current bundle type.
pub fn target() -> Option<String> {
    if let (Some(target), Some(arch)) = (updater_os(), updater_arch()) {
        Some(format!("{target}-{arch}"))
    } else {
        None
    }
}

fn updater_os() -> Option<&'static str> {
    if cfg!(target_os = "linux") {
        Some("linux")
    } else if cfg!(target_os = "macos") {
        // TODO shouldn't this be macos instead?
        Some("darwin")
    } else if cfg!(target_os = "windows") {
        Some("windows")
    } else {
        None
    }
}

fn updater_arch() -> Option<&'static str> {
    if cfg!(target_arch = "x86") {
        Some("i686")
    } else if cfg!(target_arch = "x86_64") {
        Some("x86_64")
    } else if cfg!(target_arch = "arm") {
        Some("armv7")
    } else if cfg!(target_arch = "aarch64") {
        Some("aarch64")
    } else if cfg!(target_arch = "riscv64") {
        Some("riscv64")
    } else {
        None
    }
}

pub fn extract_path_from_executable(executable_path: &Path) -> Result<PathBuf> {
    // Return the path of the current executable by default
    // Example C:\Program Files\My App\
    let extract_path = executable_path
        .parent()
        .map(PathBuf::from)
        .ok_or(Error::FailedToDetermineExtractPath)?;

    // MacOS example binary is in /Applications/TestApp.app/Contents/MacOS/myApp
    // We need to get /Applications/<app>.app
    // TODO(lemarier): Need a better way here
    // Maybe we could search for <*.app> to get the right path
    #[cfg(target_os = "macos")]
    if extract_path
        .display()
        .to_string()
        .contains("Contents/MacOS")
    {
        return extract_path
            .parent()
            .map(PathBuf::from)
            .ok_or(Error::FailedToDetermineExtractPath)?
            .parent()
            .map(PathBuf::from)
            .ok_or(Error::FailedToDetermineExtractPath);
    }

    Ok(extract_path)
}

impl<'de> Deserialize<'de> for RemoteRelease {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct InnerRemoteRelease {
            #[serde(alias = "name", deserialize_with = "parse_version")]
            version: Version,
            notes: Option<String>,
            pub_date: Option<String>,
            platforms: Option<HashMap<String, ReleaseManifestPlatform>>,
            // dynamic platform response
            url: Option<Url>,
            signature: Option<String>,
        }

        let release = InnerRemoteRelease::deserialize(deserializer)?;

        let pub_date = if let Some(date) = release.pub_date {
            Some(
                OffsetDateTime::parse(&date, &time::format_description::well_known::Rfc3339)
                    .map_err(|e| DeError::custom(format!("invalid value for `pub_date`: {e}")))?,
            )
        } else {
            None
        };

        Ok(RemoteRelease {
            version: release.version,
            notes: release.notes,
            pub_date,
            data: if let Some(platforms) = release.platforms {
                RemoteReleaseInner::Static { platforms }
            } else {
                RemoteReleaseInner::Dynamic(ReleaseManifestPlatform {
                    url: release.url.ok_or_else(|| {
                        DeError::custom("the `url` field was not set on the updater response")
                    })?,
                    signature: release.signature.ok_or_else(|| {
                        DeError::custom("the `signature` field was not set on the updater response")
                    })?,
                })
            },
        })
    }
}

fn installer_for_bundle_type(bundle: Option<BundleType>) -> Option<Installer> {
    match bundle? {
        BundleType::Deb => Some(Installer::Deb),
        BundleType::Rpm => Some(Installer::Rpm),
        BundleType::AppImage => Some(Installer::AppImage),
        BundleType::Msi => Some(Installer::Msi),
        BundleType::Nsis => Some(Installer::Nsis),
        BundleType::App => Some(Installer::App), // App is also returned for Dmg type
        _ => None,
    }
}

fn parse_version<'de, D>(deserializer: D) -> std::result::Result<Version, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;

    Version::from_str(str.trim_start_matches('v')).map_err(serde::de::Error::custom)
}

#[cfg(windows)]
fn encode_wide(string: impl AsRef<OsStr>) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    string
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(windows)]
trait PathExt {
    fn wrap_in_quotes(&self) -> Self;
}

#[cfg(windows)]
impl PathExt for PathBuf {
    fn wrap_in_quotes(&self) -> Self {
        let mut msi_path = OsString::from("\"");
        msi_path.push(self.as_os_str());
        msi_path.push("\"");
        PathBuf::from(msi_path)
    }
}

// adapted from https://github.com/rust-lang/rust/blob/1c047506f94cd2d05228eb992b0a6bbed1942349/library/std/src/sys/args/windows.rs#L174
#[cfg(windows)]
fn escape_nsis_current_exe_arg(arg: &&OsStr) -> String {
    let arg = arg.to_string_lossy();
    let mut cmd: Vec<char> = Vec::new();

    // compared to std we additionally escape `/` so that nsis won't interpret them as a beginning of an nsis argument.
    let quote = arg.chars().any(|c| c == ' ' || c == '\t' || c == '/') || arg.is_empty();
    let escape = true;
    if quote {
        cmd.push('"');
    }
    let mut backslashes: usize = 0;
    for x in arg.chars() {
        if escape {
            if x == '\\' {
                backslashes += 1;
            } else {
                if x == '"' {
                    // Add n+1 backslashes to total 2n+1 before internal '"'.
                    cmd.extend((0..=backslashes).map(|_| '\\'));
                }
                backslashes = 0;
            }
        }
        cmd.push(x);
    }
    if quote {
        // Add n backslashes to total 2n before ending '"'.
        cmd.extend((0..backslashes).map(|_| '\\'));
        cmd.push('"');
    }
    cmd.into_iter().collect()
}

#[cfg(windows)]
fn escape_msi_property_arg(arg: impl AsRef<OsStr>) -> String {
    let mut arg = arg.as_ref().to_string_lossy().to_string();

    // Otherwise this argument will get lost in ShellExecute
    if arg.is_empty() {
        return "\"\"\"\"".to_string();
    } else if !arg.contains(' ') && !arg.contains('"') {
        return arg;
    }

    if arg.contains('"') {
        arg = arg.replace('"', r#""""""#);
    }

    if arg.starts_with('-') {
        if let Some((a1, a2)) = arg.split_once('=') {
            format!("{a1}=\"\"{a2}\"\"")
        } else {
            format!("\"\"{arg}\"\"")
        }
    } else {
        format!("\"\"{arg}\"\"")
    }
}

#[cfg(test)]
mod tests {

    #[test]
    #[cfg(windows)]
    fn it_wraps_correctly() {
        use super::PathExt;
        use std::path::PathBuf;

        assert_eq!(
            PathBuf::from("C:\\Users\\Some User\\AppData\\tauri-example.exe").wrap_in_quotes(),
            PathBuf::from("\"C:\\Users\\Some User\\AppData\\tauri-example.exe\"")
        )
    }

    #[test]
    #[cfg(windows)]
    fn it_escapes_correctly_for_msi() {
        use crate::updater::escape_msi_property_arg;

        // Explanation for quotes:
        // The output of escape_msi_property_args() will be used in `LAUNCHAPPARGS=\"{HERE}\"`. This is the first quote level.
        // To escape a quotation mark we use a second quotation mark, so "" is interpreted as " later.
        // This means that the escaped strings can't ever have a single quotation mark!
        // Now there are 3 major things to look out for to not break the msiexec call:
        //   1) Wrap spaces in quotation marks, otherwise it will be interpreted as the end of the msiexec argument.
        //   2) Escape escaping quotation marks, otherwise they will either end the msiexec argument or be ignored.
        //   3) Escape emtpy args in quotation marks, otherwise the argument will get lost.
        let cases = [
            "something",
            "--flag",
            "--empty=",
            "--arg=value",
            "some space",                     // This simulates `./my-app "some string"`.
            "--arg value", // -> This simulates `./my-app "--arg value"`. Same as above but it triggers the startsWith(`-`) logic.
            "--arg=unwrapped space", // `./my-app --arg="unwrapped space"`
            "--arg=\"wrapped\"", // `./my-app --args=""wrapped""`
            "--arg=\"wrapped space\"", // `./my-app --args=""wrapped space""`
            "--arg=midword\"wrapped space\"", // `./my-app --args=midword""wrapped""`
            "",            // `./my-app '""'`
        ];
        let cases_escaped = [
            "something",
            "--flag",
            "--empty=",
            "--arg=value",
            "\"\"some space\"\"",
            "\"\"--arg value\"\"",
            "--arg=\"\"unwrapped space\"\"",
            r#"--arg=""""""wrapped"""""""#,
            r#"--arg=""""""wrapped space"""""""#,
            r#"--arg=""midword""""wrapped space"""""""#,
            "\"\"\"\"",
        ];

        // Just to be sure we didn't mess that up
        assert_eq!(cases.len(), cases_escaped.len());

        for (orig, escaped) in cases.iter().zip(cases_escaped) {
            assert_eq!(escape_msi_property_arg(orig), escaped);
        }
    }

    #[test]
    #[cfg(windows)]
    fn it_escapes_correctly_for_nsis() {
        use crate::updater::escape_nsis_current_exe_arg;
        use std::ffi::OsStr;

        let cases = [
            "something",
            "--flag",
            "--empty=",
            "--arg=value",
            "some space",                     // This simulates `./my-app "some string"`.
            "--arg value", // -> This simulates `./my-app "--arg value"`. Same as above but it triggers the startsWith(`-`) logic.
            "--arg=unwrapped space", // `./my-app --arg="unwrapped space"`
            "--arg=\"wrapped\"", // `./my-app --args=""wrapped""`
            "--arg=\"wrapped space\"", // `./my-app --args=""wrapped space""`
            "--arg=midword\"wrapped space\"", // `./my-app --args=midword""wrapped""`
            "",            // `./my-app '""'`
        ];
        // Note: These may not be the results we actually want (monitor this!).
        // We only make sure the implementation doesn't unintentionally change.
        let cases_escaped = [
            "something",
            "--flag",
            "--empty=",
            "--arg=value",
            "\"some space\"",
            "\"--arg value\"",
            "\"--arg=unwrapped space\"",
            "--arg=\\\"wrapped\\\"",
            "\"--arg=\\\"wrapped space\\\"\"",
            "\"--arg=midword\\\"wrapped space\\\"\"",
            "\"\"",
        ];

        // Just to be sure we didn't mess that up
        assert_eq!(cases.len(), cases_escaped.len());

        for (orig, escaped) in cases.iter().zip(cases_escaped) {
            assert_eq!(escape_nsis_current_exe_arg(&OsStr::new(orig)), escaped);
        }
    }
}
