use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use cantor_core::{
    ContentDigest, SOP_CORPUS_PROFILE, SOP_LOWERING_PROFILE, SOP_SOURCE_PROFILE, SopCorpusManifest,
    SopDocumentInput, SopFault, SopFaultKind, SopSigningKeys, build_sop_corpus,
    embedded_environment_digest, sha256_bytes,
};
use ed25519_dalek::SigningKey;
use serde::Serialize;

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_KEY_BYTES: u64 = 128;

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(receipt) => {
            let mut stdout = std::io::stdout().lock();
            if serde_json::to_writer(&mut stdout, &receipt).is_err() || writeln!(stdout).is_err() {
                eprintln!(
                    "{{\"status\":\"fault\",\"faults\":[{{\"kind\":\"ArtifactWrite\",\"message\":\"failed to write build receipt\"}}]}}"
                );
                return ExitCode::from(70);
            }
            ExitCode::SUCCESS
        }
        Err(faults) => {
            let envelope = FaultEnvelope {
                status: "fault",
                faults: &faults,
            };
            let mut stderr = std::io::stderr().lock();
            if serde_json::to_writer(&mut stderr, &envelope).is_ok() {
                let _ = writeln!(stderr);
            }
            ExitCode::from(2)
        }
    }
}

fn run(arguments: Vec<String>) -> Result<BuildReceipt, Vec<SopFault>> {
    let started = Instant::now();
    let paths = parse_arguments(&arguments)?;
    let manifest_path = canonical_file(&paths.manifest, "manifest")?;
    let manifest_bytes = read_bounded(&manifest_path, MAX_MANIFEST_BYTES, "manifest")?;
    let manifest: SopCorpusManifest = serde_json::from_slice(&manifest_bytes).map_err(|error| {
        vec![SopFault::external(
            SopFaultKind::InvalidManifest,
            format!("manifest is not strict valid JSON: {error}"),
        )]
    })?;
    if manifest.corpus_version != SOP_CORPUS_PROFILE {
        return Err(vec![SopFault::manifest(format!(
            "unsupported corpus_version {:?}",
            manifest.corpus_version
        ))]);
    }
    let manifest_directory = manifest_path.parent().ok_or_else(|| {
        vec![SopFault::external(
            SopFaultKind::Io,
            "manifest path has no parent directory",
        )]
    })?;
    let source_root_relative = Path::new(&manifest.source_root);
    if source_root_relative.is_absolute()
        || source_root_relative
            .components()
            .any(|component| matches!(component, Component::Prefix(_) | Component::RootDir))
    {
        return Err(vec![SopFault::manifest(
            "source_root must be a relative path",
        )]);
    }
    let source_root = manifest_directory
        .join(source_root_relative)
        .canonicalize()
        .map_err(|error| {
            vec![SopFault::external(
                SopFaultKind::Io,
                format!(
                    "cannot resolve source_root {:?}: {error}",
                    manifest.source_root
                ),
            )]
        })?;
    if !source_root.is_dir() {
        return Err(vec![SopFault::external(
            SopFaultKind::Io,
            format!("source_root {} is not a directory", source_root.display()),
        )]);
    }
    let mut documents = Vec::with_capacity(manifest.documents.len());
    for document in &manifest.documents {
        let relative = Path::new(&document.path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| matches!(component, Component::Prefix(_) | Component::RootDir))
        {
            return Err(vec![SopFault::manifest(format!(
                "document {:?} path must be relative",
                document.document_id
            ))]);
        }
        let resolved = source_root.join(relative).canonicalize().map_err(|error| {
            vec![SopFault::external(
                SopFaultKind::Io,
                format!(
                    "cannot resolve document {:?} path {:?}: {error}",
                    document.document_id, document.path
                ),
            )]
        })?;
        if !resolved.starts_with(&source_root) {
            return Err(vec![SopFault::external(
                SopFaultKind::InvalidManifest,
                format!(
                    "document {:?} escapes declared source_root",
                    document.document_id
                ),
            )]);
        }
        if !resolved.is_file() {
            return Err(vec![SopFault::external(
                SopFaultKind::Io,
                format!("document {} is not a file", resolved.display()),
            )]);
        }
        documents.push(SopDocumentInput {
            document_id: document.document_id.clone(),
            path: document.path.clone(),
            bytes: read_bounded(
                &resolved,
                cantor_core::MAX_DOCUMENT_BYTES as u64,
                "SOP document",
            )?,
        });
    }
    let loaded_milliseconds = elapsed_milliseconds(started);
    let authority_seed = read_seed_file(&paths.authority_key, "authority key")?;
    let compiler_seed = read_seed_file(&paths.compiler_key, "compiler key")?;
    let authority_key = SigningKey::from_bytes(&authority_seed);
    let compiler_key = SigningKey::from_bytes(&compiler_seed);
    let authority_public_fingerprint = sha256_bytes(&authority_key.verifying_key().to_bytes());
    let compiler_public_fingerprint = sha256_bytes(&compiler_key.verifying_key().to_bytes());
    let build_started = Instant::now();
    let built = build_sop_corpus(
        &manifest,
        documents,
        SopSigningKeys {
            authority: authority_key,
            compiler: compiler_key,
        },
    )?;
    let build_milliseconds = elapsed_milliseconds(build_started);
    let environment_digest = embedded_environment_digest(&built.environment).map_err(|fault| {
        vec![SopFault::external(
            SopFaultKind::Verification,
            fault.to_string(),
        )]
    })?;
    let certificate_id = built
        .package
        .certificate
        .as_ref()
        .ok_or_else(|| {
            vec![SopFault::external(
                SopFaultKind::Signing,
                "built package has no certificate",
            )]
        })?
        .certificate_id
        .clone();

    let mut artifact_bytes = BTreeMap::new();
    artifact_bytes.insert(
        "environment.json".to_owned(),
        json_line(&built.environment, "environment")?,
    );
    for request in &built.requests {
        artifact_bytes.insert(
            format!("{}.json", request.name),
            json_line(&request.request, "protocol request")?,
        );
    }
    let artifact_digests = artifact_bytes
        .iter()
        .map(|(name, bytes)| (name.clone(), sha256_bytes(bytes)))
        .collect::<BTreeMap<_, _>>();
    let source_digests = built
        .package
        .content
        .sources
        .iter()
        .map(|source| {
            (
                source.file_id.to_string(),
                SourceBuildRecord {
                    path: source.path.clone(),
                    digest: source.document_digest.clone(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let build_manifest = BuildManifest {
        corpus_profile: SOP_CORPUS_PROFILE,
        source_profile: SOP_SOURCE_PROFILE,
        lowering_profile: SOP_LOWERING_PROFILE,
        manifest_digest: sha256_bytes(&manifest_bytes),
        package_id: built.package.package_id.to_string(),
        certificate_id: certificate_id.to_string(),
        environment_digest: environment_digest.clone(),
        authority_public_key_fingerprint: authority_public_fingerprint.clone(),
        compiler_public_key_fingerprint: compiler_public_fingerprint.clone(),
        source_count: built.source_count,
        unit_count: built.unit_count,
        relation_count: built.relation_count,
        sources: source_digests,
        artifacts: artifact_digests,
    };
    let build_manifest_bytes = json_line(&build_manifest, "build manifest")?;
    let build_manifest_digest = sha256_bytes(&build_manifest_bytes);
    artifact_bytes.insert("build-manifest.json".to_owned(), build_manifest_bytes);

    let write_started = Instant::now();
    publish_artifacts(&paths.output, &artifact_bytes, paths.replace)?;
    let write_milliseconds = elapsed_milliseconds(write_started);
    Ok(BuildReceipt {
        status: "success",
        corpus_profile: SOP_CORPUS_PROFILE,
        package_id: built.package.package_id.to_string(),
        certificate_id: certificate_id.to_string(),
        environment_digest,
        authority_public_key_fingerprint: authority_public_fingerprint,
        compiler_public_key_fingerprint: compiler_public_fingerprint,
        source_count: built.source_count,
        unit_count: built.unit_count,
        relation_count: built.relation_count,
        artifact_count: artifact_bytes.len(),
        build_manifest_digest,
        timings_milliseconds: TimingReceipt {
            load: loaded_milliseconds,
            build: build_milliseconds,
            write: write_milliseconds,
            total: elapsed_milliseconds(started),
        },
    })
}

struct InvocationPaths {
    manifest: PathBuf,
    authority_key: PathBuf,
    compiler_key: PathBuf,
    output: PathBuf,
    replace: bool,
}

fn parse_arguments(arguments: &[String]) -> Result<InvocationPaths, Vec<SopFault>> {
    let Some(command) = arguments.first() else {
        return Err(vec![SopFault::manifest(
            "usage: cantor-corpus compile --manifest <path> --authority-key <path> --compiler-key <path> --output <directory> [--replace]",
        )]);
    };
    if command != "compile" {
        return Err(vec![SopFault::manifest(format!(
            "unknown command {command:?}; expected \"compile\""
        ))]);
    }
    let mut manifest = None;
    let mut authority_key = None;
    let mut compiler_key = None;
    let mut output = None;
    let mut replace = false;
    let mut position = 1;
    while position < arguments.len() {
        let flag = &arguments[position];
        if flag == "--replace" {
            if replace {
                return Err(vec![SopFault::manifest(
                    "--replace may be supplied only once",
                )]);
            }
            replace = true;
            position += 1;
            continue;
        }
        let value = arguments.get(position + 1).ok_or_else(|| {
            vec![SopFault::manifest(format!(
                "{flag} requires a nonempty path"
            ))]
        })?;
        if value.is_empty() {
            return Err(vec![SopFault::manifest(format!(
                "{flag} requires a nonempty path"
            ))]);
        }
        let slot = match flag.as_str() {
            "--manifest" => &mut manifest,
            "--authority-key" => &mut authority_key,
            "--compiler-key" => &mut compiler_key,
            "--output" => &mut output,
            _ => {
                return Err(vec![SopFault::manifest(format!(
                    "unknown argument {flag:?}"
                ))]);
            }
        };
        if slot.replace(PathBuf::from(value)).is_some() {
            return Err(vec![SopFault::manifest(format!(
                "{flag} may be supplied only once"
            ))]);
        }
        position += 2;
    }
    Ok(InvocationPaths {
        manifest: manifest.ok_or_else(|| vec![SopFault::manifest("--manifest is required")])?,
        authority_key: authority_key
            .ok_or_else(|| vec![SopFault::manifest("--authority-key is required")])?,
        compiler_key: compiler_key
            .ok_or_else(|| vec![SopFault::manifest("--compiler-key is required")])?,
        output: output.ok_or_else(|| vec![SopFault::manifest("--output is required")])?,
        replace,
    })
}

fn canonical_file(path: &Path, label: &str) -> Result<PathBuf, Vec<SopFault>> {
    let canonical = path.canonicalize().map_err(|error| {
        vec![SopFault::external(
            SopFaultKind::Io,
            format!("cannot resolve {label} {}: {error}", path.display()),
        )]
    })?;
    if !canonical.is_file() {
        return Err(vec![SopFault::external(
            SopFaultKind::Io,
            format!("{label} {} is not a file", canonical.display()),
        )]);
    }
    Ok(canonical)
}

fn read_bounded(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>, Vec<SopFault>> {
    let file = File::open(path).map_err(|error| {
        vec![SopFault::external(
            SopFaultKind::Io,
            format!("cannot open {label} {}: {error}", path.display()),
        )]
    })?;
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            vec![SopFault::external(
                SopFaultKind::Io,
                format!("cannot read {label} {}: {error}", path.display()),
            )]
        })?;
    if bytes.is_empty() {
        return Err(vec![SopFault::external(
            SopFaultKind::Io,
            format!("{label} {} is empty", path.display()),
        )]);
    }
    if bytes.len() as u64 > maximum {
        return Err(vec![SopFault::external(
            SopFaultKind::ResourceLimit,
            format!(
                "{label} {} exceeds the {maximum}-byte limit",
                path.display()
            ),
        )]);
    }
    Ok(bytes)
}

fn read_seed_file(path: &Path, label: &str) -> Result<[u8; 32], Vec<SopFault>> {
    let file = File::open(path).map_err(|error| {
        vec![SopFault::external(
            SopFaultKind::Signing,
            format!("cannot open {label}: {error}"),
        )]
    })?;
    let mut bytes = Vec::new();
    file.take(MAX_KEY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            vec![SopFault::external(
                SopFaultKind::Signing,
                format!("cannot read {label}: {error}"),
            )]
        })?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_KEY_BYTES {
        return Err(vec![SopFault::external(
            SopFaultKind::Signing,
            format!("{label} is empty or exceeds the {MAX_KEY_BYTES}-byte limit"),
        )]);
    }
    if bytes.len() == 32 {
        return bytes.try_into().map_err(|_| {
            vec![SopFault::external(
                SopFaultKind::Signing,
                format!("{label} raw seed must contain exactly 32 bytes"),
            )]
        });
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        vec![SopFault::external(
            SopFaultKind::Signing,
            format!("{label} must be 32 raw bytes or 64 ASCII hexadecimal digits"),
        )]
    })?;
    let candidate = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    if candidate.len() != 64 || !candidate.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(vec![SopFault::external(
            SopFaultKind::Signing,
            format!("{label} must be 32 raw bytes or 64 ASCII hexadecimal digits"),
        )]);
    }
    let mut seed = [0_u8; 32];
    for (position, output) in seed.iter_mut().enumerate() {
        let high = hex_nibble(candidate.as_bytes()[position * 2]);
        let low = hex_nibble(candidate.as_bytes()[position * 2 + 1]);
        *output = high * 16 + low;
    }
    Ok(seed)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => unreachable!("hex input is validated"),
    }
}

fn json_line(value: &impl Serialize, label: &str) -> Result<Vec<u8>, Vec<SopFault>> {
    let mut bytes = serde_json::to_vec(value).map_err(|error| {
        vec![SopFault::external(
            SopFaultKind::ArtifactWrite,
            format!("cannot serialize {label}: {error}"),
        )]
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn publish_artifacts(
    output: &Path,
    artifacts: &BTreeMap<String, Vec<u8>>,
    replace: bool,
) -> Result<(), Vec<SopFault>> {
    if output.exists() && !output.is_dir() {
        return Err(vec![SopFault::external(
            SopFaultKind::ArtifactConflict,
            format!("output {} exists and is not a directory", output.display()),
        )]);
    }
    fs::create_dir_all(output).map_err(|error| {
        vec![SopFault::external(
            SopFaultKind::ArtifactWrite,
            format!(
                "cannot create output directory {}: {error}",
                output.display()
            ),
        )]
    })?;
    for name in artifacts.keys() {
        let target = output.join(name);
        if target.exists() && !replace {
            return Err(vec![SopFault::external(
                SopFaultKind::ArtifactConflict,
                format!(
                    "artifact {} already exists; use --replace to replace verified outputs",
                    target.display()
                ),
            )]);
        }
        if target.exists() && !target.is_file() {
            return Err(vec![SopFault::external(
                SopFaultKind::ArtifactConflict,
                format!("artifact target {} is not a file", target.display()),
            )]);
        }
    }
    let publication_order = artifacts
        .iter()
        .filter(|(name, _)| name.as_str() != "build-manifest.json")
        .chain(artifacts.get_key_value("build-manifest.json"));
    for (sequence, (name, bytes)) in publication_order.enumerate() {
        let target = output.join(name);
        let temporary = output.join(format!(".{name}.{}.{sequence}.tmp", std::process::id()));
        let write_result = (|| -> std::io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, &target)
        })();
        if let Err(error) = write_result {
            let _ = fs::remove_file(&temporary);
            return Err(vec![SopFault::external(
                SopFaultKind::ArtifactWrite,
                format!("cannot publish artifact {}: {error}", target.display()),
            )]);
        }
    }
    Ok(())
}

fn elapsed_milliseconds(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[derive(Serialize)]
struct FaultEnvelope<'a> {
    status: &'static str,
    faults: &'a [SopFault],
}

#[derive(Serialize)]
struct SourceBuildRecord {
    path: String,
    digest: ContentDigest,
}

#[derive(Serialize)]
struct BuildManifest {
    corpus_profile: &'static str,
    source_profile: &'static str,
    lowering_profile: &'static str,
    manifest_digest: ContentDigest,
    package_id: String,
    certificate_id: String,
    environment_digest: ContentDigest,
    authority_public_key_fingerprint: ContentDigest,
    compiler_public_key_fingerprint: ContentDigest,
    source_count: usize,
    unit_count: usize,
    relation_count: usize,
    sources: BTreeMap<String, SourceBuildRecord>,
    artifacts: BTreeMap<String, ContentDigest>,
}

#[derive(Serialize)]
struct TimingReceipt {
    load: u64,
    build: u64,
    write: u64,
    total: u64,
}

#[derive(Serialize)]
struct BuildReceipt {
    status: &'static str,
    corpus_profile: &'static str,
    package_id: String,
    certificate_id: String,
    environment_digest: ContentDigest,
    authority_public_key_fingerprint: ContentDigest,
    compiler_public_key_fingerprint: ContentDigest,
    source_count: usize,
    unit_count: usize,
    relation_count: usize,
    artifact_count: usize,
    build_manifest_digest: ContentDigest,
    timings_milliseconds: TimingReceipt,
}
