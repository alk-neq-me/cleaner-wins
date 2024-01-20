use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;

use clap::{Parser, ValueEnum};


#[derive(ValueEnum, Clone, Debug, Default)]
enum CleanType {
    VirusScan,
    #[default]
    CleanCache
}


#[derive(Parser, Debug)]
#[command(
    author = "Aung Koko Lwin", 
    version = "0.1.0", 
)]
struct Args {
    #[arg(short, long)]
    r#type: CleanType,
    #[arg(short, long)]
    scan: Option<String>
}


fn get_cache_paths(user: &str) -> [String; 3] {
    let cache_dir = format!("C:\\Windows\\Prefetch");
    let temp_dir = format!("C:\\Windows\\Temp");
    let more_temp_dir = format!("C:\\Users\\{}\\AppData\\Local\\Temp", user);
    [cache_dir, temp_dir, more_temp_dir]
}


fn get_confirm() -> Result<bool, io::Error> {
    let mut input = String::new();

    print!("remove [y/n]: ");
    io::stdout().flush()?;

    io::stdin().read_line(&mut input)?;

    if input.trim().to_lowercase().eq("y") { return Ok(true) }
    
    Ok(false)
}


fn virus_scan(file_path: &Path) -> Result<(), io::Error> {
    let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    let file_content = fs::read(file_path)?;

    if file_content.iter().any(|&byte| byte == eicar[0]) {
        println!("File {} is infected! Deleting...", file_path.display());
        if get_confirm()? { 
            println!("Deleted: {}", file_path.display());
            fs::remove_file(file_path)?; 
        }
    } else {
        println!("File {} is clean.", file_path.display());
    }

    Ok(())
}


fn scan_dir(path: &Path, r#type: &CleanType) -> Result<(), io::Error> {
    let entires = fs::read_dir(path)?;

    for entry in entires {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            match r#type {
                CleanType::VirusScan => virus_scan(&path)?,
                CleanType::CleanCache => fs::remove_file(&path)?
            }
        } else if path.is_dir() {
            scan_dir(&path, r#type)?;
        }
    }

    Ok(())
}

fn init(user: &str, r#type: &CleanType, scan: Option<&Path>) -> Result<(), io::Error> {
    match r#type {
        CleanType::CleanCache => {
            let [cache_dir, temp_dir, more_temp_dir] = get_cache_paths(&user);

            scan_dir(&Path::new(&cache_dir), &CleanType::CleanCache)?;
            scan_dir(&Path::new(&temp_dir), &CleanType::CleanCache)?;
            scan_dir(&Path::new(&more_temp_dir), &CleanType::CleanCache)?;
        },
        CleanType::VirusScan => {
            if let Some(path) = scan { 
                if path.is_dir() {
                    scan_dir(&path, &CleanType::VirusScan)?;
                } else if path.is_file() {
                    virus_scan(&path)?;
                }
            }
        }
    }

    Ok(())
}


fn main() -> Result<(), io::Error> {
    // if cfg!(target_os = "windows") {
    //     let mut res = winres::WindowsResource::new();
    //     res
    //         .set_icon("../res/soap-and-sanitizer.svg")
    //         .set("InternalName", "wash.exe")
    //         .set_version_info(winres::VersionInfo::PRODUCTVERSION, 0x0001000000000000);
    //     res.compile()?;
    // }

    let Args { r#type, scan } = Args::parse();
    let user = whoami::username();

    println!("{}", user);

    match r#type {
        CleanType::VirusScan => {
            println!("Virus scan...");
            if let Some(scan) = scan { init(&user, &CleanType::VirusScan, Some(&Path::new(&scan)))? }
        },
        CleanType::CleanCache => {
            println!("Clean cache...");
            init(&user, &CleanType::CleanCache, None)?
        }
    }

    println!("\nAll done!");

    Ok(())
}
