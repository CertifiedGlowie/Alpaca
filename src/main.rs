use aes_gcm::aead::Aead;
use aes_gcm::AeadCore;
use aes_gcm::Aes128Gcm;
use aes_gcm::KeyInit;
use clap::Parser;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use rand::rngs::OsRng;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use serde::Deserialize;
use serde::Serialize;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser)]
enum Args {
    Encrypt {
        #[clap(index = 1)]
        filepath: PathBuf,
    },
    Decrypt {
        #[clap(short = 'k', long, required = true)]
        key: String,
        #[clap(index = 1)]
        filepath: PathBuf,
    },
    LoadSchematic {
        #[clap(index = 1)]
        filepath: PathBuf,
    },
    MakeSchematic,
}

enum GzipMode {
    Compress,
    Decompress,
}

fn gzip(input: &[u8], mode: GzipMode) -> Vec<u8> {
    match mode {
        GzipMode::Compress => {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
            encoder.write_all(input).unwrap();
            encoder.finish().unwrap()
        }
        GzipMode::Decompress => {
            let mut decoder = GzDecoder::new(input);
            let mut decompressed_data = Vec::new();
            decoder.read_to_end(&mut decompressed_data).unwrap();
            decompressed_data
        }
    }
}

type GcmKey = aes_gcm::aead::generic_array::GenericArray<
    u8,
    aes_gcm::aead::generic_array::typenum::UInt<
        aes_gcm::aead::generic_array::typenum::UInt<
            aes_gcm::aead::generic_array::typenum::UInt<
                aes_gcm::aead::generic_array::typenum::UInt<
                    aes_gcm::aead::generic_array::typenum::UInt<
                        aes_gcm::aead::generic_array::typenum::UTerm,
                        aes_gcm::aead::consts::B1,
                    >,
                    aes_gcm::aead::consts::B0,
                >,
                aes_gcm::aead::consts::B0,
            >,
            aes_gcm::aead::consts::B0,
        >,
        aes_gcm::aead::consts::B0,
    >,
>;

type GcmNonce = aes_gcm::aead::generic_array::GenericArray<
    u8,
    aes_gcm::aead::generic_array::typenum::UInt<
        aes_gcm::aead::generic_array::typenum::UInt<
            aes_gcm::aead::generic_array::typenum::UInt<
                aes_gcm::aead::generic_array::typenum::UInt<
                    aes_gcm::aead::generic_array::typenum::UTerm,
                    aes_gcm::aead::consts::B1,
                >,
                aes_gcm::aead::consts::B1,
            >,
            aes_gcm::aead::consts::B0,
        >,
        aes_gcm::aead::consts::B0,
    >,
>;

fn encrypt(filepath: &PathBuf, key: &GcmKey, nonce: &GcmNonce) {
    let cipher = Aes128Gcm::new(key);

    let input = std::fs::read(filepath).expect("Error reading input file");
    let output = cipher
        .encrypt(nonce, input.as_ref())
        .expect("Failed to encrypt");

    let output = gzip(&output, GzipMode::Compress);

    let previous_extension = filepath.extension();

    if let Some(ext) = previous_extension {
        let newpath = filepath.with_extension(format!("{}.alp", ext.to_string_lossy()));
        std::fs::rename(filepath, &newpath).expect("Failed to rename a file");
        std::fs::write(newpath, output).expect("Failed to write encrypted data");
    } else {
        let newpath = filepath.with_extension("alp");
        std::fs::rename(filepath, &newpath).expect("Failed to rename a file");
        std::fs::write(newpath, output).expect("Failed to write encrypted data");
    };
}

fn decrypt(filepath: &PathBuf, key: &str) {
    let creds: Vec<&str> = key.split('#').collect();
    let key = hex::decode(creds[0]).expect("Malformed key");
    let nonce = hex::decode(creds[1]).expect("Malformed key(nonce)");
    let nonce = aes_gcm::Nonce::from_slice(&nonce);

    let cipher = Aes128Gcm::new_from_slice(&key).expect("Failed to initialize cipher");

    let input = std::fs::read(filepath).expect("Error reading input file");

    let input = gzip(&input, GzipMode::Decompress);
    let plainbytes = cipher
        .decrypt(nonce, input.as_ref())
        .expect("Failed to decrypt");

    let file_extension = filepath.extension();
    if let Some(ext) = file_extension {
        if ext == "alp" {
            let newpath = filepath.with_extension("");
            std::fs::rename(filepath, &newpath).expect("Failed to rename a file");
            std::fs::write(newpath, plainbytes).expect("Failed to write decrypted data");
        }
    } else {
        std::fs::write(filepath, plainbytes).expect("Failed to write decrypted data");
    }
}

#[derive(Deserialize, Serialize)]
struct Schematic {
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,

    filepath: PathBuf,
}

fn main() {
    let arguments = Args::parse();

    match arguments {
        Args::Encrypt { filepath } => {
            if !filepath.exists() {
                panic!("Specified file does not exist.");
            }

            let key = aes_gcm::Aes128Gcm::generate_key(OsRng);
            let nonce = aes_gcm::Aes128Gcm::generate_nonce(OsRng);

            encrypt(&filepath, &key, &nonce);
            println!("Done.\nKey: {}#{}", hex::encode(key), hex::encode(nonce));
        }
        Args::Decrypt { key, filepath } => {
            if !filepath.exists() {
                panic!("Specified file does not exist.");
            }

            decrypt(&filepath, &key);
            println!("Done!");
        }
        Args::LoadSchematic { filepath } => {
            let file = File::open(filepath).expect("Failed to open file");
            let reader = BufReader::new(file);

            // Deserialize YAML data into Vec<Schematic>
            let schematics: Vec<Schematic> =
                serde_yaml::from_reader(reader).expect("Failed to parse YAML");

            // Iterate through the schematics
            schematics.par_iter().for_each(|schematic| {
                match schematic.action.to_uppercase().as_str() {
                    "ENCRYPT" => {
                        let mut filepath = schematic.filepath.clone();
                        if let Some(root) = &schematic.root {
                            match root.to_uppercase().as_str() {
                                "HOME" => {
                                    let homedir = match dirs::home_dir() {
                                        Some(home) => home,
                                        None => return,
                                    }
                                    .join(filepath);

                                    filepath = homedir;
                                }
                                "CONFIG" | "ROAMING" => {
                                    let configdir = match dirs::config_dir() {
                                        Some(config) => config,
                                        None => return,
                                    }
                                    .join(filepath);

                                    filepath = configdir;
                                }
                                "CACHE" | "LOCAL" => {
                                    let cachedir = match dirs::cache_dir() {
                                        Some(cache) => cache,
                                        None => return,
                                    }
                                    .join(filepath);

                                    filepath = cachedir;
                                }
                                "TEMP" | "TMP" => {
                                    filepath = std::env::temp_dir().join(filepath);
                                }
                                _ => {}
                            }
                        }
                        let key = aes_gcm::Aes128Gcm::generate_key(OsRng);
                        let nonce = aes_gcm::Aes128Gcm::generate_nonce(OsRng);

                        encrypt(&filepath, &key, &nonce);
                        println!(
                            "Encrypted \'{}\' with key \'{}#{}\'",
                            filepath.display(),
                            hex::encode(key),
                            hex::encode(nonce)
                        );
                    }
                    "DECRYPT" => {
                        let mut filepath = schematic.filepath.clone();
                        if let Some(root) = &schematic.root {
                            match root.to_uppercase().as_str() {
                                "HOME" => {
                                    let homedir = match dirs::home_dir() {
                                        Some(home) => home,
                                        None => return,
                                    }
                                    .join(filepath);

                                    filepath = homedir;
                                }
                                "CONFIG" | "ROAMING" => {
                                    let configdir = match dirs::config_dir() {
                                        Some(config) => config,
                                        None => return,
                                    }
                                    .join(filepath);

                                    filepath = configdir;
                                }
                                "CACHE" | "LOCAL" => {
                                    let cachedir = match dirs::cache_dir() {
                                        Some(cache) => cache,
                                        None => return,
                                    }
                                    .join(filepath);

                                    filepath = cachedir;
                                }
                                "TEMP" | "TMP" => {
                                    filepath = std::env::temp_dir().join(filepath);
                                }
                                _ => {}
                            }
                        }

                        let key = match &schematic.key {
                            Some(key) => key,
                            None => return,
                        };

                        decrypt(&filepath, key);
                        println!("Decrypted \'{}\'", filepath.display());
                    }
                    _ => println!("Unknown action"),
                }
            });
        }
        Args::MakeSchematic => {
            let filename: String = dialoguer::Input::new()
                .with_prompt("Enter the name of schematic file")
                .interact()
                .unwrap();

            let options = ["Encrypt", "Decrypt"];
            let option_selector = dialoguer::Select::new()
                .with_prompt("Select action")
                .items(&options)
                .interact()
                .unwrap();

            let roots = [
                "NONE",
                "Home",
                "Config/Roaming AppData",
                "Cache/Local AppData",
                "Temp",
            ];
            let roots_selector = dialoguer::Select::new()
                .with_prompt("Select root directory")
                .items(&roots)
                .interact()
                .unwrap();

            let root = match roots[roots_selector] {
                "NONE" => None,
                "Home" => Some("HOME".to_owned()),
                "Config/Roaming AppData" => Some("CONFIG".to_owned()),
                "Cache/Local AppData" => Some("CACHE".to_owned()),
                "Temp" => Some("TEMP".to_owned()),
                _ => panic!("Something went wrong."),
            };

            let dir: String = match root {
                Some(_) => dialoguer::Input::new()
                    .with_prompt(
                        "Enter the file path AFTER your root directory (e.g videos/film.mp4)",
                    )
                    .interact()
                    .unwrap(),
                None => dialoguer::Input::new()
                    .with_prompt("Enter full path of file to encrypt/decrypt")
                    .interact()
                    .unwrap(),
            };

            match options[option_selector] {
                "Encrypt" => {
                    let entry = Schematic {
                        root,
                        action: "Encrypt".to_owned(),
                        key: None,
                        filepath: PathBuf::from(dir),
                    };

                    let yaml = serde_yaml::to_string(&entry).expect("Failed to serialize yaml");
                    let mut formatted_yaml = String::new();

                    for (index, line) in yaml.lines().enumerate() {
                        if index == 0 {
                            formatted_yaml.push_str(&format!("- {}\n", line));
                        } else {
                            formatted_yaml.push_str(&format!("  {}\n", line));
                        }
                    }

                    let mut file = OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open(filename)
                        .unwrap();

                    file.write_all(formatted_yaml.as_bytes())
                        .expect("Error while appending data to a file");
                }
                "Decrypt" => {
                    let key: String = dialoguer::Input::new()
                        .with_prompt("Enter decryption key")
                        .interact()
                        .unwrap();

                    // A little check
                    {
                        let creds: Vec<&str> = key.split('#').collect();
                        hex::decode(creds[0]).expect("Malformed key");
                        hex::decode(creds[1]).expect("Malformed key(nonce)");
                    }

                    let entry = Schematic {
                        root,
                        action: "Decrypt".to_owned(),
                        key: Some(key),
                        filepath: PathBuf::from(dir),
                    };

                    let yaml = serde_yaml::to_string(&entry).expect("Failed to serialize yaml");
                    let mut formatted_yaml = String::new();

                    for (index, line) in yaml.lines().enumerate() {
                        if index == 0 {
                            formatted_yaml.push_str(&format!("- {}\n", line));
                        } else {
                            formatted_yaml.push_str(&format!("  {}\n", line));
                        }
                    }

                    let mut file = OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open(filename)
                        .unwrap();

                    file.write_all(formatted_yaml.as_bytes())
                        .expect("Error while appending data to a file");
                }
                _ => panic!("Something went wrong."),
            }
        }
    }
}
