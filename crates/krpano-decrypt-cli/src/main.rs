//! `krpano-decrypt` — a versatile CLI for decrypting obfuscated krpano assets.
//!
//! See `krpano-decrypt --help` for usage. Built on the `krpano-decrypt` library.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use krpano_decrypt::{
    BodyCipher, CipherMode, EngineFamily, decrypt_xml, decrypt_xml_to_string, detect_engine,
    extract_decoded_viewer_js, extract_key_from_viewer_js, inspect,
};

/// Decrypt obfuscated krpano tour XML and viewer JavaScript.
///
/// krpano ships tours as an encrypted `tour.xml` paired with an obfuscated
/// `tour.js`. This tool decrypts the XML (using the JS when needed),
/// decodes the packed viewer engine, and inspects encrypted payloads — all
/// without executing any JavaScript.
#[derive(Parser)]
#[command(name = "krpano-decrypt", version, propagate_version = true)]
struct Cli {
    /// Initialize the logger for diagnostic output (`-v` enables debug logs).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Decrypt an encrypted krpano XML file.
    Decrypt {
        /// Path to the encrypted XML file (e.g. `tour.xml`).
        xml: PathBuf,
        /// Path to the krpano viewer JS file (e.g. `tour.js`).
        ///
        /// May be omitted for public payloads whose stable constants are known.
        /// Protected and version-specific payloads return a clear error.
        js: Option<PathBuf>,
        /// Write the decrypted XML here. If omitted, prints to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Decode the packed, obfuscated krpano viewer engine from a viewer JS file.
    DecodeViewer {
        /// Path to the viewer JS file (e.g. `tour.js`).
        js: PathBuf,
        /// Write the decoded engine source here. If omitted, prints to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the `krp:`/`ptp:` wrapper key embedded in a viewer JS file.
    WrapperKey {
        /// Path to the viewer JS file.
        js: PathBuf,
    },
    /// Inspect an encrypted XML payload: print the KENC header, cipher, mode,
    /// detected engine family, and body length without decrypting.
    Inspect {
        /// Path to the encrypted XML file.
        xml: PathBuf,
        /// Also load the viewer JS to report engine family and key lengths.
        js: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logger(cli.verbose);
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn init_logger(verbose: u8) {
    let level = match verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level))
        .format_module_path(verbose >= 2)
        .try_init();
}

fn run(command: Command) -> Result<()> {
    match command {
        Command::Decrypt { xml, js, output } => decrypt(&xml, js, output),
        Command::DecodeViewer { js, output } => decode_viewer(&js, output),
        Command::WrapperKey { js } => wrapper_key(&js),
        Command::Inspect { xml, js } => inspect_cmd(&xml, js),
    }
}

fn read_bytes(path: &PathBuf, role: &str) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("failed to read {role}: {}", path.display()))
}

fn write_output(bytes: &[u8], output: &Option<PathBuf>) -> Result<()> {
    match output {
        Some(path) => {
            std::fs::write(path, bytes)
                .with_context(|| format!("failed to write {}", path.display()))?;
            eprintln!("wrote {} bytes to {}", bytes.len(), path.display());
        }
        None => {
            // Write raw bytes to stdout (the decrypted XML may not be valid
            // UTF-8 on every platform, so use the byte-oriented API).
            std::io::Write::write_all(&mut std::io::stdout(), bytes)
                .context("failed to write to stdout")?;
        }
    }
    Ok(())
}

fn decrypt(xml: &PathBuf, js: Option<PathBuf>, output: Option<PathBuf>) -> Result<()> {
    let xml_bytes = read_bytes(xml, "encrypted XML")?;
    let js_bytes = match &js {
        Some(path) => Some(read_bytes(path, "viewer JS")?),
        None => None,
    };

    // If the input isn't actually encrypted, pass it through.
    if !krpano_decrypt::is_encrypted_xml(&xml_bytes) {
        eprintln!(
            "note: {} does not look encrypted; copying input to output",
            xml.display()
        );
        write_output(&xml_bytes, &output)?;
        return Ok(());
    }

    let plaintext = decrypt_xml(&xml_bytes, js_bytes.as_deref())
        .with_context(|| format!("failed to decrypt {}", xml.display()))?;

    if output.is_none() {
        eprintln!("decrypted {} bytes", plaintext.len());
    }
    write_output(&plaintext, &output)
}

fn decode_viewer(js: &PathBuf, output: Option<PathBuf>) -> Result<()> {
    let js_bytes = read_bytes(js, "viewer JS")?;
    let decoded = extract_decoded_viewer_js(&js_bytes)
        .with_context(|| format!("no decodable packed payload found in {}", js.display()))?;
    if output.is_none() {
        eprintln!("decoded {} bytes of engine source", decoded.len());
    }
    write_output(&decoded, &output)
}

fn wrapper_key(js: &PathBuf) -> Result<()> {
    let js_bytes = read_bytes(js, "viewer JS")?;
    let key = extract_key_from_viewer_js(&js_bytes)
        .with_context(|| format!("no krp:/ptp: wrapper key found in {}", js.display()))?;
    println!("{key}");
    Ok(())
}

fn inspect_cmd(xml: &PathBuf, js: Option<PathBuf>) -> Result<()> {
    let xml_bytes = read_bytes(xml, "encrypted XML")?;
    let info =
        inspect(&xml_bytes).with_context(|| format!("failed to inspect {}", xml.display()))?;

    if !info.is_encrypted {
        println!("{}: not an encrypted krpano document", xml.display());
        return Ok(());
    }

    println!("file:        {}", xml.display());
    println!("header:      {}", info.header);
    println!("cipher:      {}", cipher_name(info.cipher));
    println!("mode:        {}", mode_name(info.mode));
    println!("body length: {} bytes", info.body_len);

    if let Some(js_path) = js {
        let js_bytes = read_bytes(&js_path, "viewer JS")?;
        let wrapper = extract_key_from_viewer_js(&js_bytes).ok();
        let decoded = extract_decoded_viewer_js(&js_bytes).ok();
        let engine = decoded.as_deref().map(detect_engine);

        println!();
        println!("viewer JS:   {}", js_path.display());
        match &wrapper {
            Some(w) => println!("wrapper key: {} chars", w.len()),
            None => println!("wrapper key: not found"),
        }
        match &decoded {
            Some(d) => println!("engine:      {} bytes", d.len()),
            None => println!("engine:      could not decode packed payload"),
        }
        match engine {
            Some(EngineFamily::Old) => println!("engine fam:  old (pre-2018, KENC literal)"),
            Some(EngineFamily::Modern) => {
                println!("engine fam:  modern (we.subdiv / startup IIFE)")
            }
            None => {}
        }
    }
    Ok(())
}

fn cipher_name(c: BodyCipher) -> &'static str {
    match c {
        BodyCipher::ClassicZ => "ClassicZ (Base85 → RC4 → LZ4 → UTF-8)",
        BodyCipher::ClassicB => "ClassicB (Base64 → RC4 → UTF-8)",
        BodyCipher::Subdiv => "Subdiv (token replace → we.subdiv branch 5)",
    }
}

fn mode_name(m: CipherMode) -> &'static str {
    match m {
        CipherMode::Public => "Public (no license key)",
        CipherMode::Protected => "Protected (license key required)",
    }
}

// Keep `decrypt_xml_to_string` referenced so it is part of the public surface
// documented from the CLI even if a future subcommand uses it.
#[allow(dead_code)]
fn _ensure_string_api_linked(contents: &[u8], js: Option<&[u8]>) {
    let _ = decrypt_xml_to_string(contents, js);
}
