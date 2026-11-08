//! Exec-style wrapper argv resolution.
//!
//! Each supported wrapper has its own option grammar.  Callers get the one command that the
//! wrapper actually executes, rather than searching every later argument for an interesting word.

use crate::posix_basename;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ActualExec {
    /// The AST command verb itself is the executable.
    Outer,
    /// A wrapper chain resolves to this executable and its first argument in the original argv.
    Wrapped {
        verb: String,
        args_start: usize,
        /// A resolved xargs wrapper turns its stdin into child argv.
        stdin_as_args: bool,
    },
    /// No supplied child executable to inspect (`command -v`, or bare `xargs` with default echo).
    None,
    /// An opaque word controls where or what the executable is.
    Opaque,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandIndex {
    At(usize),
    None,
    Opaque,
}

/// Resolve nested exec-style wrappers. `args` contains the outer command's argv, excluding argv[0].
pub(crate) fn actual_exec(outer: &str, args: &[Option<&str>]) -> ActualExec {
    let mut verb = outer.to_string();
    let mut base = 0;
    let mut current = args;
    let mut wrapped = false;
    let mut stdin_as_args = false;

    loop {
        let wrapper = posix_basename(&verb);
        let Some(next) = wrapped_command(wrapper, current) else {
            return if wrapped {
                ActualExec::Wrapped {
                    verb,
                    args_start: base,
                    stdin_as_args,
                }
            } else {
                ActualExec::Outer
            };
        };
        let relative = match next {
            CommandIndex::At(i) => i,
            CommandIndex::None => return ActualExec::None,
            CommandIndex::Opaque => return ActualExec::Opaque,
        };
        let Some(raw) = current.get(relative).and_then(|word| *word) else {
            return ActualExec::Opaque;
        };
        stdin_as_args |= wrapper == "xargs";
        verb = raw.to_string();
        base += relative + 1;
        current = &current[relative + 1..];
        wrapped = true;
    }
}

/// `Some` means `verb` is a supported wrapper. `None` means it is the actual executable.
fn wrapped_command(verb: &str, args: &[Option<&str>]) -> Option<CommandIndex> {
    Some(match verb {
        "sudo" => sudo_command(args),
        "doas" => doas_command(args),
        "env" => env_command(args),
        "nice" => nice_command(args),
        "nohup" => simple_exec(args, &[], &[], &[]),
        "timeout" => timeout_command(args),
        "stdbuf" => simple_exec(args, &['e', 'i', 'o'], &["error", "input", "output"], &[]),
        "command" => command_builtin(args),
        "exec" => simple_exec(args, &['a'], &["argv0"], &[]),
        "setsid" => simple_exec(args, &[], &["wait-signal"], &['h', 'V']),
        "ionice" => ionice_command(args),
        "xargs" => xargs_command(args),
        _ => return None,
    })
}

fn sudo_command(args: &[Option<&str>]) -> CommandIndex {
    const SHORT_VALUES: &[char] = &[
        'a', 'C', 'c', 'D', 'g', 'h', 'p', 'R', 'r', 't', 'T', 'U', 'u',
    ];
    const LONG_VALUES: &[&str] = &[
        "auth-type",
        "chdir",
        "chroot",
        "close-from",
        "command-timeout",
        "group",
        "host",
        "login-class",
        "other-user",
        "prompt",
        "role",
        "type",
        "user",
    ];
    let mut i = 0;
    let mut shell_mode = false;
    let mut reset_timestamp = false;
    while i < args.len() {
        let Some(word) = args[i] else {
            return CommandIndex::Opaque;
        };
        if word == "--" {
            return sudo_child(args, i + 1, shell_mode);
        }
        if word == "-" || !word.starts_with('-') {
            // sudo resumes option parsing after environment assignments, but not after `--`.
            if word.contains('=') && !word.starts_with(['/', '=']) {
                i += 1;
                continue;
            }
            return sudo_child(args, i, shell_mode);
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, attached) = split_long(long);
            if matches!(
                name,
                "edit" | "help" | "list" | "remove-timestamp" | "validate" | "version"
            ) {
                return CommandIndex::None;
            }
            if matches!(name, "login" | "shell") {
                shell_mode = true;
            }
            if name == "reset-timestamp" {
                reset_timestamp = true;
            }
            if LONG_VALUES.contains(&name) && !attached {
                i += 1;
                if i >= args.len() {
                    return CommandIndex::None;
                }
            }
        } else {
            let chars: Vec<char> = word.chars().skip(1).collect();
            for (position, ch) in chars.iter().enumerate() {
                if SHORT_VALUES.contains(ch) {
                    if position + 1 == chars.len() {
                        i += 1;
                        if i >= args.len() {
                            return CommandIndex::None;
                        }
                    }
                    break;
                }
                if matches!(ch, 'e' | 'K' | 'l' | 'v' | 'V') {
                    return CommandIndex::None;
                }
                if matches!(ch, 'i' | 's') {
                    shell_mode = true;
                }
                if *ch == 'k' {
                    reset_timestamp = true;
                }
            }
        }
        i += 1;
    }
    // Only standalone -k invalidates credentials without a child. Bare sudo starts a shell.
    if reset_timestamp && !shell_mode {
        CommandIndex::None
    } else {
        CommandIndex::Opaque
    }
}

fn sudo_child(args: &[Option<&str>], index: usize, shell_mode: bool) -> CommandIndex {
    if index >= args.len() {
        return CommandIndex::Opaque;
    }
    // -i/-s escape shell metacharacters except '$' when rebuilding the command for shell -c.
    // Fully literal argv retains its executable; dollar expansion can change its argv again.
    if shell_mode
        && args[index..]
            .iter()
            .any(|word| word.is_none_or(|value| value.contains('$')))
    {
        return CommandIndex::Opaque;
    }
    command_after(args, index)
}

fn doas_command(args: &[Option<&str>]) -> CommandIndex {
    let mut i = 0;
    while i < args.len() {
        let Some(word) = args[i] else {
            return CommandIndex::Opaque;
        };
        if word == "--" {
            return command_after(args, i + 1);
        }
        if word == "-" || !word.starts_with('-') {
            return CommandIndex::At(i);
        }
        let chars: Vec<char> = word.chars().skip(1).collect();
        for (position, ch) in chars.iter().enumerate() {
            if *ch == 'C' || *ch == 'L' {
                return CommandIndex::None;
            }
            if *ch == 's' {
                return CommandIndex::Opaque;
            }
            if matches!(ch, 'a' | 'u') {
                if position + 1 == chars.len() {
                    i += 1;
                    if i >= args.len() {
                        return CommandIndex::None;
                    }
                }
                break;
            }
        }
        i += 1;
    }
    CommandIndex::None
}

fn simple_exec(
    args: &[Option<&str>],
    short_with_value: &[char],
    long_with_value: &[&str],
    terminal_short: &[char],
) -> CommandIndex {
    let mut i = 0;
    while i < args.len() {
        let Some(word) = args[i] else {
            return CommandIndex::Opaque;
        };
        if word == "--" {
            return command_after(args, i + 1);
        }
        if word == "-" || !word.starts_with('-') {
            return CommandIndex::At(i);
        }
        if let Some(long) = word.strip_prefix("--") {
            if matches!(long, "help" | "version") {
                return CommandIndex::None;
            }
            let (name, attached) = split_long(long);
            if long_with_value.contains(&name) && !attached {
                i += 1;
                if i >= args.len() {
                    return CommandIndex::None;
                }
            }
        } else {
            if short_option(word, terminal_short) {
                return CommandIndex::None;
            }
            if short_option_takes_next(word, short_with_value) {
                i += 1;
                if i >= args.len() {
                    return CommandIndex::None;
                }
            }
        }
        i += 1;
    }
    CommandIndex::None
}

fn env_command(args: &[Option<&str>]) -> CommandIndex {
    let mut i = 0;
    let mut options = true;
    while i < args.len() {
        let Some(word) = args[i] else {
            return CommandIndex::Opaque;
        };
        if options && word == "--" {
            options = false;
            i += 1;
            continue;
        }
        if !options {
            if word.contains('=') && !word.starts_with('=') {
                i += 1;
                continue;
            }
            return CommandIndex::At(i);
        }
        if matches!(word, "--help" | "--version") {
            return CommandIndex::None;
        }
        if word == "-" || word == "-i" || word == "--ignore-environment" || word == "--null" {
            i += 1;
            continue;
        }
        if word.starts_with("--split-string=") || word.starts_with("-S") && word.len() > 2 {
            return CommandIndex::Opaque;
        }
        if matches!(word, "-S" | "--split-string") {
            // The value is itself split into argv and can contain the executable.
            return CommandIndex::Opaque;
        }
        if long_option(word, &["argv0", "chdir", "env0-from", "unset"]) {
            if !word.contains('=') {
                i += 1;
                if i >= args.len() {
                    return CommandIndex::None;
                }
            }
            i += 1;
            continue;
        }
        if short_option(word, &['a', 'C', 'u']) {
            if short_option_takes_next(word, &['a', 'C', 'u']) {
                i += 1;
                if i >= args.len() {
                    return CommandIndex::None;
                }
            }
            i += 1;
            continue;
        }
        if word.contains('=') && !word.starts_with('=') {
            i += 1;
            continue;
        }
        if word.starts_with('-') {
            i += 1;
            continue;
        }
        return CommandIndex::At(i);
    }
    CommandIndex::None
}

fn nice_command(args: &[Option<&str>]) -> CommandIndex {
    let mut i = 0;
    while i < args.len() {
        let Some(word) = args[i] else {
            return CommandIndex::Opaque;
        };
        if word == "--" {
            return command_after(args, i + 1);
        }
        if word
            .strip_prefix('-')
            .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
        {
            i += 1;
            continue;
        }
        if matches!(word, "-n" | "--adjustment") {
            i += 2;
            continue;
        }
        if word.starts_with("-n") && word.len() > 2 || word.starts_with("--adjustment=") {
            i += 1;
            continue;
        }
        if matches!(word, "--help" | "--version") {
            return CommandIndex::None;
        }
        if word == "-" || !word.starts_with('-') {
            return CommandIndex::At(i);
        }
        i += 1;
    }
    CommandIndex::None
}

fn timeout_command(args: &[Option<&str>]) -> CommandIndex {
    let mut i = 0;
    while i < args.len() {
        let Some(word) = args[i] else {
            // It may expand to an option, a duration, or multiple argv words.
            return CommandIndex::Opaque;
        };
        if word == "--" {
            i += 1;
            break;
        }
        if matches!(word, "--help" | "--version") {
            return CommandIndex::None;
        }
        if long_option(word, &["kill-after", "signal"]) {
            if !word.contains('=') {
                i += 1;
                if i >= args.len() {
                    return CommandIndex::None;
                }
            }
            i += 1;
            continue;
        }
        if short_option(word, &['k', 's']) {
            if short_option_takes_next(word, &['k', 's']) {
                i += 1;
                if i >= args.len() {
                    return CommandIndex::None;
                }
            }
            i += 1;
            continue;
        }
        if word.starts_with('-') {
            i += 1;
            continue;
        }
        break;
    }
    // The first positional word is duration; the following word is the executable.
    command_after(args, i + 1)
}

fn command_builtin(args: &[Option<&str>]) -> CommandIndex {
    let mut i = 0;
    while i < args.len() {
        let Some(word) = args[i] else {
            return CommandIndex::Opaque;
        };
        if word == "--" {
            return command_after(args, i + 1);
        }
        if word == "-" || !word.starts_with('-') {
            return CommandIndex::At(i);
        }
        if word.chars().skip(1).any(|c| matches!(c, 'v' | 'V')) {
            return CommandIndex::None;
        }
        i += 1;
    }
    CommandIndex::None
}

fn ionice_command(args: &[Option<&str>]) -> CommandIndex {
    let mut i = 0;
    let mut existing_process = false;
    while i < args.len() {
        let Some(word) = args[i] else {
            return CommandIndex::Opaque;
        };
        if word == "--" {
            return if existing_process {
                CommandIndex::None
            } else {
                command_after(args, i + 1)
            };
        }
        if matches!(word, "--help" | "--version") {
            return CommandIndex::None;
        }
        if short_option(word, &['h', 'V']) {
            return CommandIndex::None;
        }
        if word == "-" || !word.starts_with('-') {
            return if existing_process {
                CommandIndex::None
            } else {
                CommandIndex::At(i)
            };
        }
        if has_short_option(word, &['p', 'P', 'u']) || long_option(word, &["pid", "pgid", "uid"]) {
            existing_process = true;
        }
        if long_option(
            word,
            &["class", "classdata", "pid", "pgid", "priority", "uid"],
        ) && !word.contains('=')
            || short_option_takes_next(word, &['c', 'n', 'p', 'P', 'u'])
        {
            i += 1;
            if i >= args.len() {
                return CommandIndex::None;
            }
        }
        i += 1;
    }
    CommandIndex::None
}

/// `xargs` is not an exec-style wrapper: its own stdin constructs child argv and a missing command
/// selects the default `echo`.  Only an explicit command position is returned.
fn xargs_command(args: &[Option<&str>]) -> CommandIndex {
    let mut i = 0;
    while i < args.len() {
        let Some(word) = args[i] else {
            return CommandIndex::Opaque;
        };
        if word == "--" {
            return command_after(args, i + 1);
        }
        if word == "-" || !word.starts_with('-') {
            return CommandIndex::At(i);
        }
        if matches!(word, "--help" | "--version") {
            return CommandIndex::None;
        }
        let long_values = [
            "arg-file",
            "delimiter",
            "max-args",
            "max-chars",
            "max-lines",
            "max-procs",
            "process-slot-var",
        ];
        if long_option(word, &long_values) && !word.contains('=')
            || short_option_takes_next(word, &['E', 'I', 'L', 'P', 'a', 'd', 'n', 's'])
        {
            i += 1;
            if i >= args.len() {
                return CommandIndex::None;
            }
        }
        i += 1;
    }
    CommandIndex::None
}

fn command_after(args: &[Option<&str>], index: usize) -> CommandIndex {
    match args.get(index) {
        Some(Some(_)) => CommandIndex::At(index),
        Some(None) => CommandIndex::Opaque,
        None => CommandIndex::None,
    }
}

fn split_long(long: &str) -> (&str, bool) {
    long.split_once('=')
        .map_or((long, false), |(name, _)| (name, true))
}

fn long_option(word: &str, names: &[&str]) -> bool {
    word.strip_prefix("--")
        .map(|long| split_long(long).0)
        .is_some_and(|name| names.contains(&name))
}

fn short_option(word: &str, names: &[char]) -> bool {
    word.starts_with('-')
        && !word.starts_with("--")
        && word.chars().skip(1).any(|c| names.contains(&c))
}

fn has_short_option(word: &str, names: &[char]) -> bool {
    short_option(word, names)
}

/// True only when a value-taking option is the last character in the cluster.  A suffix is its
/// attached value (`-uapp`, `-n5`), so no following argv word is consumed.
fn short_option_takes_next(word: &str, value_options: &[char]) -> bool {
    if !word.starts_with('-') || word.starts_with("--") {
        return false;
    }
    let chars: Vec<char> = word.chars().skip(1).collect();
    chars
        .iter()
        .position(|c| value_options.contains(c))
        .is_some_and(|position| position + 1 == chars.len())
}
