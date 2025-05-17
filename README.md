# sandboxer

A standalone build of [sandboxer](https://github.com/landlock-lsm/rust-landlock/blob/8b8de51204d0390458f26604627b247a54923fd5/examples/sandboxer.rs) with additional features.

Execute a command in a sandboxed environment using Linux Landlock.

```sh
Usage: sandboxer [OPTIONS] [COMMAND] [ARGS]...

Arguments:
  [COMMAND]  Command to run in the sandbox
  [ARGS]...  Command arguments

Options:
    --generate <SHELL>               Generate shell completion script [possible values: bash, elvish, fish, powershell, zsh]
    --ro-paths <RO_PATHS>            Paths allowed to be used in read-only mode (colon-separated list) [env: LL_FS_RO=]
    --rw-paths <RW_PATHS>            Paths allowed to be used in read-write mode (colon-separated list) [env: LL_FS_RW=]
-b, --bind-ports <BIND_PORTS>        Ports allowed to bind as server (colon-separated list) [env: LL_TCP_BIND=]
    --connect-ports <CONNECT_PORTS>  Ports allowed to connect to as client (colon-separated list) [env: LL_TCP_CONNECT=]
    --scoped <SCOPED>                Actions denied outside of Landlock domain (colon-separated list) [env: LL_SCOPED=]
                                      - "a" to restrict opening abstract unix sockets
                                      - "s" to restrict sending signals
-o, --output <OUTPUT_FILE>           Write output to the specified file (same as > redirection)
-a, --auto-mount-essential           Automatically mount `$PATH` and `$LD_LIBRARY_PATH` as read-only
```

## Attribution
The original [sandboxer](https://github.com/landlock-lsm/rust-landlock/blob/8b8de51204d0390458f26604627b247a54923fd5/examples/sandboxer.rs) license and copyright info can be found in [OLD_LICENSE](./OLD_LICENSE). The license for this project can be found in [LICENSE](./LICENSE).
