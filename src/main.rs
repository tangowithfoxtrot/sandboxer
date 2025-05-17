use anyhow::{Ok, bail};
use clap::{CommandFactory, Parser};
use clap_complete::{Shell, generate};
use std::io;
use std::path::PathBuf;

use landlock::{
    ABI, Access, AccessFs, AccessNet, NetPort, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetStatus, Scope, path_beneath_rules,
};
use std::os::unix::process::CommandExt;
use std::process::Command;

/// Environment variables
const ENV_FS_RO_NAME: &str = "LL_FS_RO";
const ENV_FS_RW_NAME: &str = "LL_FS_RW";
const ENV_TCP_BIND_NAME: &str = "LL_TCP_BIND";
const ENV_TCP_CONNECT_NAME: &str = "LL_TCP_CONNECT";
const ENV_SCOPED_NAME: &str = "LL_SCOPED";

/// Fallback PATH to use if --auto-mount-essential is specified and no PATH is available (unlikely)
const FALLBACK_PATH: [&str; 6] = [
    "/bin",
    "/usr/bin",
    "/sbin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
];

/// Fallback LD_LIBRARY_PATH to use if --auto-mount-essential is specified and LD_LIBRARY_PATH is not set (common)
const FALLBACK_LD_LIBRARY_PATH: [&str; 4] = ["/lib", "/lib64", "/usr/lib", "/usr/lib64"];

/// Execute a command in a sandboxed environment using Linux Landlock
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Command to run in the sandbox
    #[arg(required_unless_present = "generate")]
    command: Option<String>,

    /// Command arguments
    #[arg(trailing_var_arg = true)]
    args: Vec<String>,

    /// Generate shell completion script
    #[arg(long, value_name = "SHELL")]
    generate: Option<Shell>,

    /// Paths allowed to be used in read-only mode (colon-separated list)
    #[arg(long, env = ENV_FS_RO_NAME)]
    ro_paths: Option<String>,

    /// Paths allowed to be used in read-write mode (colon-separated list)
    #[arg(long, env = ENV_FS_RW_NAME)]
    rw_paths: Option<String>,

    /// Ports allowed to bind as server (colon-separated list)
    #[arg(long, short, env = ENV_TCP_BIND_NAME)]
    bind_ports: Option<String>,

    /// Ports allowed to connect to as client (colon-separated list)
    #[arg(long, env = ENV_TCP_CONNECT_NAME)]
    connect_ports: Option<String>,

    #[arg(long, env = ENV_SCOPED_NAME, help =
r#"Actions denied outside of Landlock domain (colon-separated list)
  - "a" to restrict opening abstract unix sockets
  - "s" to restrict sending signals"#)]
    scoped: Option<String>,

    /// Write output to the specified file (same as > redirection)
    #[arg(long = "output", short)]
    output_file: Option<String>,

    /// Automatically mount $PATH and $LD_LIBRARY_PATH as read-only
    #[arg(long, short)]
    auto_mount_essential: bool,
}

/// Generic function to parse colon-separated values into a collection
fn parse_colon_separated<T, F>(input: &str, parser: F) -> Vec<T>
where
    F: Fn(&str) -> Option<T>,
{
    if input.is_empty() {
        return Vec::new();
    }

    input
        .split(':')
        .filter(|s| !s.is_empty())
        .filter_map(parser)
        .collect()
}

fn parse_paths(paths_str: &str) -> Vec<PathBuf> {
    parse_colon_separated(paths_str, |p| Some(PathBuf::from(p)))
}

fn parse_ports(ports_str: &str) -> Vec<u16> {
    parse_colon_separated(ports_str, |s| s.parse::<u16>().ok())
}

/// Add common paths needed for running commands
fn add_essential_paths(paths: &mut Vec<PathBuf>) {
    // Account for fish, which uses spaces as delimiters
    let split_delimiter = if Shell::from_env() == Some(Shell::Fish) {
        ' '
    } else {
        ':'
    };

    // Read (or infer) PATH and LD_LIBRARY_PATH from the environment
    let path_env =
        std::env::var("PATH").unwrap_or(FALLBACK_PATH.join(split_delimiter.to_string().as_str()));
    let ld_library_path_env = std::env::var("LD_LIBRARY_PATH")
        .unwrap_or(FALLBACK_LD_LIBRARY_PATH.join(split_delimiter.to_string().as_str()));

    let essential_dirs: Vec<&str> = path_env
        .split(split_delimiter)
        .chain(ld_library_path_env.split(split_delimiter))
        .filter(|p| !p.is_empty())
        .collect();

    for dir in essential_dirs {
        let path = PathBuf::from(dir);
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
}

/// Debug helper to print paths being added
fn debug_paths(ro_paths: &[PathBuf], rw_paths: &[PathBuf]) {
    eprintln!("Read-only paths:");
    for path in ro_paths {
        eprintln!("  {}", path.display());
    }
    eprintln!("Read-write paths:");
    for path in rw_paths {
        eprintln!("  {}", path.display());
    }
}

/// Run a command with optional output redirection to a file
fn run_command_with_redirection(
    command: &str,
    args: &[String],
    output_file: Option<&str>,
) -> anyhow::Result<()> {
    let mut cmd = Command::new(command);
    cmd.args(args);

    if let Some(file_path) = output_file {
        let file = std::fs::File::create(file_path)?;
        cmd.stdout(file);
        // should we also redirect stderr?
    }

    Err(cmd.exec().into())
}

fn main() -> anyhow::Result<()> {
    let args: Cli = Cli::parse();

    if let Some(shell) = &args.generate {
        let mut cmd = Cli::command();
        generate(
            *shell,
            &mut cmd,
            std::env::args().next().expect("Program name not found"),
            &mut io::stdout(),
        );
        return Ok(());
    }

    let command = args.command.as_ref().expect("A command is required");
    let ro_paths = args.ro_paths.unwrap_or_default();
    let rw_paths = args.rw_paths.unwrap_or_default();

    let abi = ABI::V6;
    let mut ruleset = Ruleset::default().handle_access(AccessFs::from_all(abi))?;

    if args.bind_ports.is_some() {
        ruleset = ruleset.handle_access(AccessNet::BindTcp)?;
    }
    if args.connect_ports.is_some() {
        ruleset = ruleset.handle_access(AccessNet::ConnectTcp)?;
    }

    if let Some(scoped) = &args.scoped {
        let mut abstract_scoping = false;
        let mut signal_scoping = false;

        let is_empty = scoped.is_empty();
        for scope in scoped.split(':').skip_while(move |_| is_empty) {
            match scope {
                "a" => {
                    if abstract_scoping {
                        bail!("Duplicate scope 'a'");
                    }
                    ruleset = ruleset.scope(Scope::AbstractUnixSocket)?;
                    abstract_scoping = true;
                }
                "s" => {
                    if signal_scoping {
                        bail!("Duplicate scope 's'");
                    }
                    ruleset = ruleset.scope(Scope::Signal)?;
                    signal_scoping = true;
                }
                _ => bail!("Unknown scope '{scope}'"),
            }
        }
    }

    let mut ro_path_list = parse_paths(&ro_paths);
    let rw_path_list = parse_paths(&rw_paths);

    if args.auto_mount_essential {
        add_essential_paths(&mut ro_path_list);
    }

    let mut ruleset_created = ruleset.create()?;

    ruleset_created =
        ruleset_created.add_rules(path_beneath_rules(&ro_path_list, AccessFs::from_read(abi)))?;

    ruleset_created =
        ruleset_created.add_rules(path_beneath_rules(&rw_path_list, AccessFs::from_all(abi)))?;

    if let Some(bind_ports_str) = &args.bind_ports {
        let bind_ports = parse_ports(bind_ports_str);
        for port in bind_ports {
            let port_rule = NetPort::new(port, AccessNet::BindTcp);
            ruleset_created = ruleset_created.add_rule(port_rule)?;
        }
    }

    if let Some(connect_ports_str) = &args.connect_ports {
        let connect_ports = parse_ports(connect_ports_str);
        for port in connect_ports {
            let port_rule = NetPort::new(port, AccessNet::ConnectTcp);
            ruleset_created = ruleset_created.add_rule(port_rule)?;
        }
    }

    let status = ruleset_created.restrict_self()?;

    match status.ruleset {
        RulesetStatus::NotEnforced => {
            bail!("Landlock is not supported by the running kernel.");
        }
        RulesetStatus::PartiallyEnforced => {
            eprintln!(
                "Warning: Landlock is partially enforced. Some features may not work as expected."
            );
        }
        RulesetStatus::FullyEnforced => {}
    }

    if std::env::var("SANDBOXER_DEBUG").is_ok() {
        debug_paths(&ro_path_list, &rw_path_list);
        let cmd_str = format!("{} {}", command, args.args.join(" "));
        eprintln!("Executing sandboxed command: {}", cmd_str);
    }

    run_command_with_redirection(command, &args.args, args.output_file.as_deref())
}
