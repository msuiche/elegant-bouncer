use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::Read;
use std::collections::HashSet;

lazy_static::lazy_static! {
    static ref FILE_WHITELIST: HashSet<String> = {
        let mut set = HashSet::new();
        // TTF font files
        set.insert("f30e7620766b57a7dc73a43fa415b0ecd81a655684c41255abe5910fc7cd1fdd".to_string());
        set.insert("4f54eb299fccea7f103edeb0d92437359bfd4441811d53222b82b335369f6218".to_string());
        set.insert("ae3d2b9af860ca91a2bbd288dc00172a6cc06a05998c5b1bddd17d22c253bfad".to_string());
        set.insert("ab4dd380c621508d510b80309fd2ecde63818fc4dee9140e36e70d118db18beb".to_string());
        set.insert("b33d76749bbe41ebdffbdfc0330ace133f231d845539063bb2499d6681681a2a".to_string());
        set.insert("7bb99c3a67697fbce15ab66d806d9a2151432ce1dab2eaba4156e1251da486c0".to_string());
        set.insert("9b492b1a29bd3cc7e7d63095b160b30f93aac1deec65ed3680d0f23941b92a45".to_string());
        set.insert("8733fa2693d29fa75de52f6893bdfe0b224349c01a1596cf5b9ba2e3d8e81a40".to_string());
        set.insert("519a78f73cd5ac6286d3b2d820e4ec68dca2169c6930870ab9e5cee1fd4c1804".to_string());
        set.insert("aa7570d12d0bd44ef0d736683b600efa0c6eb28ab118a9261009cce1aa06aa1a".to_string());
        set.insert("1c81ead87ca36eee7d51dbe816c3202ba8052fc88228a46de930339c4ec1df22".to_string());
        set
    };
}

pub fn compute_file_sha256(file_path: &str) -> Result<String, std::io::Error> {
    let mut file = File::open(file_path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];
    
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn is_whitelisted(hash: &str) -> bool {
    FILE_WHITELIST.contains(hash)
}

pub fn is_whitelisted_file(file_path: &str) -> bool {
    match compute_file_sha256(file_path) {
        Ok(hash) => is_whitelisted(&hash),
        Err(_) => false,
    }
}