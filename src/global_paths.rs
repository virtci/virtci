use std::path::{Path, PathBuf};

use anyhow::Context;
#[cfg(target_os = "windows")]
use std::process::Command;

pub struct VciGlobalPaths {
    pub user_home: PathBuf,
    pub system_home: PathBuf,
    pub temp: PathBuf,
    #[cfg(target_os = "windows")]
    pub wsl: Option<WslPaths>,
}

/// macOS can't use [`std::env::temp_dir`] which is `$TMPDIR`. It prefixes it with ~50-char
/// `/var/folders/<xx>/<hash>/T/` path, which can actually cause swtpm control socket
/// path to exceed the 104-byte `sockaddr_un.sun_path` limit.
#[cfg(target_os = "macos")]
fn default_temp_path() -> PathBuf {
    unsafe extern "C" {
        fn getuid() -> u32;
    }
    PathBuf::from(format!("/tmp/vci-{}", unsafe { getuid() }))
}

#[cfg(not(target_os = "macos"))]
fn default_temp_path() -> PathBuf {
    std::env::temp_dir().join("vci")
}

impl Default for VciGlobalPaths {
    fn default() -> Self {
        #[cfg(not(target_os = "windows"))]
        {
            Self {
                user_home: default_user_home_path(),
                system_home: default_system_home_path(),
                temp: default_temp_path(),
            }
        }

        #[cfg(target_os = "windows")]
        {
            Self {
                user_home: default_user_home_path(),
                system_home: default_system_home_path(),
                temp: default_temp_path(),
                wsl: None,
            }
        }
    }
}

impl VciGlobalPaths {
    #[cfg(target_os = "windows")]
    pub fn with_wsl() -> anyhow::Result<Self> {
        let wsl_paths = WslPaths::new()?;
        Ok(Self {
            user_home: default_user_home_path(),
            system_home: default_system_home_path(),
            temp: default_temp_path(),
            wsl: Some(wsl_paths),
        })
    }

    /// Returns a `TargetPath` with the actual full file path, not just its directory.
    /// Precedence order:
    /// 1. User home
    /// 2. System home
    /// 3. WSL user home
    /// 4. WSL system home
    pub fn resolve_image_home(&self, name: &str) -> Option<TargetPath> {
        let filename = format!("{name}.vci");
        if self.user_home.join(&filename).exists() {
            return Some(TargetPath {
                path: self.user_home.join(filename),
                #[cfg(target_os = "windows")]
                wsl_distro: None,
            });
        } else if self.system_home.join(&filename).exists() {
            return Some(TargetPath {
                path: self.system_home.join(filename),
                #[cfg(target_os = "windows")]
                wsl_distro: None,
            });
        }

        #[cfg(target_os = "windows")]
        {
            if let Some(wsl_paths) = &self.wsl {
                let user_unc = wsl_paths.to_unc(&wsl_paths.user_home);
                if user_unc.join(&filename).exists() {
                    return Some(TargetPath {
                        path: user_unc.join(filename),
                        wsl_distro: Some(wsl_paths.distro.clone()),
                    });
                }

                let system_unc = wsl_paths.to_unc(&wsl_paths.system_home);
                if system_unc.join(&filename).exists() {
                    return Some(TargetPath {
                        path: system_unc.join(filename),
                        wsl_distro: Some(wsl_paths.distro.clone()),
                    });
                }
            }
        }

        None
    }

    /// Returns a `TargetPath` with directories to check, not a bunch of files.
    /// Precedence order:
    /// 1. User home
    /// 2. System home
    /// 3. WSL user home
    /// 4. WSL system home
    pub fn image_homes(&self) -> Vec<TargetPath> {
        #[cfg_attr(not(target_os = "windows"), allow(unused_mut))]
        let mut vec = vec![
            TargetPath {
                path: self.user_home.clone(),
                #[cfg(target_os = "windows")]
                wsl_distro: None,
            },
            TargetPath {
                path: self.system_home.clone(),
                #[cfg(target_os = "windows")]
                wsl_distro: None,
            },
        ];
        #[cfg(target_os = "windows")]
        {
            if let Some(wsl_paths) = &self.wsl {
                vec.push(TargetPath {
                    path: wsl_paths.to_unc(&wsl_paths.user_home),
                    wsl_distro: Some(wsl_paths.distro.clone()),
                });
                vec.push(TargetPath {
                    path: wsl_paths.to_unc(&wsl_paths.system_home),
                    wsl_distro: Some(wsl_paths.distro.clone()),
                });
            }
        }
        vec
    }

    /// Get the directory of the long-term LRU cache storage for `virtci run` runs.
    pub fn cache_dir(&self) -> TargetPath {
        self.cache_dir_impl(false)
    }

    /// Get the temporary directory of the cache storage for `virtci run` runs, to be moved to the
    /// long term one when possible.
    /// The staging one exists because atomic file rename doesn't work without doing a full copy
    /// or byte move across file systems, and tmpfs usually is it's own file system on linux.
    pub fn cache_staging_dir(&self) -> TargetPath {
        self.cache_dir_impl(true)
    }

    /// Get the directory of the long-term LRU cache storage for `virtci run` runs in a WSL2
    /// distro.
    #[cfg(target_os = "windows")]
    pub fn wsl_cache_dir(&self) -> TargetPath {
        self.wsl_cache_dir_impl(false)
    }

    /// Get the temporary directory of the cache storage for `virtci run` runs in a WSL2 distro,
    /// to be moved to the long term one when possible.
    /// The staging one exists because atomic file rename doesn't work without doing a full copy
    /// or byte move across file systems, and tmpfs usually is it's own file system on linux.
    #[cfg(target_os = "windows")]
    pub fn wsl_cache_staging_dir(&self) -> TargetPath {
        self.wsl_cache_dir_impl(true)
    }

    fn cache_dir_impl(&self, staging: bool) -> TargetPath {
        let cache_dir_name = if staging { ".cache-staging" } else { ".cache" };

        TargetPath {
            path: cache_home_base(&self.user_home).join(cache_dir_name),
            #[cfg(target_os = "windows")]
            wsl_distro: None,
        }
    }

    #[cfg(target_os = "windows")]
    fn wsl_cache_dir_impl(&self, staging: bool) -> TargetPath {
        let cache_dir_name = if staging { ".cache-staging" } else { ".cache" };

        let wsl_info = self.wsl.as_ref().expect("Should have WSL paths");

        let base = wsl_cache_home_base(&wsl_info.user_home);
        let wsl_path = format!("{}/{cache_dir_name}", base.trim_end_matches('/'));
        TargetPath {
            path: wsl_info.to_unc(&wsl_path),
            wsl_distro: Some(wsl_info.distro.clone()),
        }
    }
}

fn cache_home_base(user_home: &Path) -> PathBuf {
    if let Some(over) = std::env::var_os("VIRTCI_CACHE_HOME") {
        return PathBuf::from(over);
    }
    user_home.to_path_buf()
}

#[cfg(target_os = "windows")]
fn wsl_cache_home_base(wsl_user_home: &str) -> String {
    if let Some(over) = std::env::var_os("VIRTCI_WSL_CACHE_HOME") {
        return over.to_string_lossy().into_owned();
    }
    wsl_user_home.to_string()
}

/// All paths are WSL-namespace Linux paths stored as `String`, so they're build with '/'
/// instead of '\'. They must not be ran through `PathBuf::join()` directly on the Windows
/// hosts, so use [`WslPaths::to_unc`] instead.
#[cfg(target_os = "windows")]
pub struct WslPaths {
    pub distro: String,
    /// Basically just `/home/USERNAME`.
    pub wsl_home: String,
    /// This directory on the Windows host is the same directory as the one when running inside
    /// WSL2 directly. In general this is `/home/USERNAME/.local/share/vci/`.
    pub user_home: String,
    /// This directory on the Windows host is the same directory as the one when running inside
    /// WSL2 directly. In general this is `/var/lib/vci/`.
    pub system_home: String,
    /// This directory is NOT the same one when running inside of WSL2 directly. In general this is
    /// `/tmp/vci_wsl/`, not to be confused with `/tmp/vci/`, which is the WSL2 INTERNAL temp
    /// directory, not for use from the Windows host directly.
    pub temp: String,
}

#[cfg(target_os = "windows")]
impl WslPaths {
    pub fn new() -> anyhow::Result<Self> {
        let distro: String = if let Some(distro) = std::env::var_os("VIRTCI_WSL_DISTRO") {
            distro.into_string().map_err(|os| {
                anyhow::anyhow!("Invalid unicode in VIRTCI_WSL_DISTRO: {}", os.display())
            })?
        } else {
            default_wsl_distro()?
        };

        // Query $HOME once and store absolute WSL paths; see the type-level note about why
        // these are `String` and never `PathBuf::join`ed.
        let wsl_home = wsl_actual_user_home(&distro)?;
        let wsl_home = wsl_home.trim_end_matches('/').to_string();

        Ok(Self {
            distro,
            user_home: wsl_user_home(&wsl_home),
            system_home: wsl_system_home(),
            temp: wsl_temp(),
            wsl_home,
        })
    }

    /// Render a WSL-namespace path (e.g. `/var/lib/vci`) as a Windows UNC path
    /// (`\\wsl.localhost\<distro>\...`) usable with `std::fs`.
    pub fn to_unc(&self, wsl_path: &str) -> PathBuf {
        wsl_path_to_unc(&self.distro, wsl_path)
    }
}

/// Render a WSL-namespace path (e.g. `/var/lib/vci`) as a Windows UNC path
/// (`\\wsl.localhost\<distro>\...`) usable with `std::fs`. The single source of the UNC
/// prefix: [`WslPaths::to_unc`] delegates here, and [`ImageHome::native_dir`] is its inverse.
pub fn wsl_path_to_unc(distro: &str, wsl_path: &str) -> PathBuf {
    let rel = wsl_path.trim_start_matches('/').replace('/', "\\");
    PathBuf::from(format!(r"\\wsl.localhost\{distro}\{rel}"))
}

#[derive(Debug, Clone)]
pub struct TargetPath {
    /// May be a file or directory.
    /// If [`ImageHome::in_wsl()`], has `\\wsl.localhost\<distro>\` prefixed.
    pub path: PathBuf,
    #[cfg(target_os = "windows")]
    pub wsl_distro: Option<String>,
}

impl TargetPath {
    /// If [`ImageHome::in_wsl()`], strips `\\wsl.localhost\<wsl_distro>\`.
    /// Returned as a string for handling WSL in-distro QEMU.
    /// Uses same prefix as [`WslPaths::to_unc()`].
    pub fn native_path(&self) -> String {
        #[cfg(target_os = "windows")]
        {
            if let Some(distro) = &self.wsl_distro {
                let path = self.path.to_string_lossy();
                let prefix = format!(r"\\wsl.localhost\{distro}");
                return path
                    .strip_prefix(prefix.as_str())
                    .expect("Expected to strip WSL UNC path prefix")
                    .replace('\\', "/");
            }
        }
        self.path.to_string_lossy().into_owned()
    }

    #[cfg(target_os = "windows")]
    pub fn in_wsl(&self) -> bool {
        self.wsl_distro.is_some()
    }

    #[must_use]
    pub fn join(&self, component: &str) -> TargetPath {
        TargetPath {
            path: self.path.join(component),
            #[cfg(target_os = "windows")]
            wsl_distro: self.wsl_distro.clone(),
        }
    }

    /// A sibling path (same parent directory, different file name).
    #[must_use]
    pub fn sibling(&self, file_name: &str) -> TargetPath {
        let path = match self.path.parent() {
            Some(parent) => parent.join(file_name),
            None => PathBuf::from(file_name),
        };
        TargetPath {
            path,
            #[cfg(target_os = "windows")]
            wsl_distro: self.wsl_distro.clone(),
        }
    }

    /// Atomically renames the file at `self` to `new_path`.
    /// Generally this is only used to promote a `.cache-staging` file into a `.cache` file.
    /// This only works well under the same file system, making is a true rename, not a
    /// cross-filesystem/device copy. For the caches, they live in the `user_home` directory so
    /// it works well. `rename`/`mv` both require the destination's parent directory to already exist,
    /// so the directory hierarchy necessary is created here.
    pub fn atomic_file_rename(&self, new_path: &TargetPath) -> anyhow::Result<()> {
        // `PathBuf::parent()` works for a UNC path too (it just strips the final component), and
        // `create_dir_all` over `\\wsl.localhost\...` creates the directory inside the WSL fs.
        if let Some(parent) = new_path.path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create cache directory {}", parent.display())
            })?;
        }

        #[cfg(target_os = "windows")]
        {
            match (&self.wsl_distro, &new_path.wsl_distro) {
                // do the rename inside the distro
                (Some(src_distro), Some(dst_distro)) => {
                    anyhow::ensure!(
                        src_distro == dst_distro,
                        "cannot atomically rename across different WSL distros ({src_distro} -> \
                         {dst_distro})"
                    );
                    return wsl_move(src_distro, &self.native_path(), &new_path.native_path());
                }
                // windows native so fallthrough.
                (None, None) => {}
                _ => anyhow::bail!(
                    "cannot atomically rename between the Windows host and a WSL2 distro; they are \
                     different filesystems"
                ),
            }
        }

        std::fs::rename(&self.path, &new_path.path).with_context(|| {
            format!(
                "failed to rename {} -> {}",
                self.path.display(),
                new_path.path.display()
            )
        })
    }
}

/// Rename a file inside a WSL2 distro via `wsl -d <distro> -- mv -f`, using in-WSL paths. Mirrors
/// the `wsl_copy` precedent so in-namespace moves never go through the Windows->WSL bridge.
#[cfg(target_os = "windows")]
fn wsl_move(distro: &str, src: &str, dst: &str) -> anyhow::Result<()> {
    let output = Command::new("wsl")
        .args(["-d", distro, "--", "mv", "-f", src, dst])
        .output()
        .with_context(|| format!("failed to run `wsl mv {src} {dst}`"))?;
    anyhow::ensure!(
        output.status.success(),
        "`wsl mv {src} {dst}` failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

fn default_user_home_path() -> PathBuf {
    if let Some(vci_home) = std::env::var_os("VIRTCI_USER_HOME") {
        return PathBuf::from(vci_home);
    }

    #[cfg(target_os = "macos")]
    {
        // ~/.vci/ (kinda matches tart)
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".vci");
        }
    }

    #[cfg(target_os = "linux")]
    {
        // $XDG_DATA_HOME/vci, else ~/.local/share/vci
        if let Some(xdg_data) = std::env::var_os("XDG_DATA_HOME") {
            return PathBuf::from(xdg_data).join("vci");
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".local/share/vci");
        }
    }

    #[cfg(target_os = "windows")]
    {
        // %LOCALAPPDATA%\vci\
        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(local_app_data).join("vci");
        }
    }

    #[allow(unreachable_code)]
    PathBuf::from(".vci")
}

fn default_system_home_path() -> PathBuf {
    if let Some(vci_system_home) = std::env::var_os("VIRTCI_SYSTEM_HOME") {
        return PathBuf::from(vci_system_home);
    }

    #[cfg(target_os = "macos")]
    {
        // /Library/Application Support/vci/
        return PathBuf::from("/Library/Application Support/vci");
    }

    #[cfg(target_os = "linux")]
    {
        // /var/lib/vci (FHS variable state, not subject to tmpfiles cleanup)
        return PathBuf::from("/var/lib/vci");
    }

    #[cfg(target_os = "windows")]
    {
        // %PROGRAMDATA%\vci\ (typically C:\ProgramData\vci)
        if let Some(program_data) = std::env::var_os("PROGRAMDATA") {
            return PathBuf::from(program_data).join("vci");
        }
        return PathBuf::from(r"C:\ProgramData\vci");
    }

    #[allow(unreachable_code)]
    PathBuf::from(".vci-system")
}

#[cfg(target_os = "windows")]
fn default_wsl_distro() -> anyhow::Result<String> {
    let output = Command::new("wsl")
        .env("WSL_UTF8", "1")
        .args(["-l", "-v"])
        .output()
        .context("Could not run 'wsl -l -v' to find the default distro")?;

    if !output.status.success() {
        anyhow::bail!(
            "'wsl -l -v' exited with {}:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let Some(rest) = line.trim_start().strip_prefix("* ") else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        let name = fields
            .next()
            .context("Malformed default distro line in 'wsl -l -v'")?;
        let version = fields
            .last()
            .context("Malformed default distro line in 'wsl -l -v'")?;

        if version != "2" {
            anyhow::bail!(
                "Default WSL distro '{name}' is WSL version {version}, but VirtCI requires WSL2. \
                 Convert it with: wsl --set-version {name} 2"
            );
        }
        return Ok(name.to_string());
    }

    anyhow::bail!("Could not find a default WSL distro in 'wsl -l -v' output")
}

#[cfg(target_os = "windows")]
fn wsl_actual_user_home(distro: &str) -> anyhow::Result<String> {
    let output = Command::new("wsl")
        .args(["-d", distro, "--", "sh", "-c", "echo \"$HOME\""])
        .output()
        .context("Failed to run wsl to query $HOME")?;
    if !output.status.success() {
        anyhow::bail!(
            "wsl exited {} querying $HOME: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let home = String::from_utf8(output.stdout)
        .context("wsl $HOME output was not UTF-8")?
        .trim()
        .to_string();
    if !home.starts_with('/') {
        anyhow::bail!("wsl returned an unexpected $HOME: {home:?}");
    }
    Ok(home)
}

#[cfg(target_os = "windows")]
fn wsl_user_home(wsl_home: &str) -> String {
    if let Some(over) = std::env::var_os("VIRTCI_WSL_USER_HOME") {
        return over.to_string_lossy().into_owned();
    }
    format!("{wsl_home}/.local/share/vci")
}

#[cfg(target_os = "windows")]
fn wsl_system_home() -> String {
    if let Some(over) = std::env::var_os("VIRTCI_WSL_SYSTEM_HOME") {
        return over.to_string_lossy().into_owned();
    }
    "/var/lib/vci".to_string()
}

#[cfg(target_os = "windows")]
fn wsl_temp() -> String {
    if let Some(over) = std::env::var_os("VIRTCI_WSL_TEMP") {
        return over.to_string_lossy().into_owned();
    }
    "/tmp/vci_wsl".to_string()
}
