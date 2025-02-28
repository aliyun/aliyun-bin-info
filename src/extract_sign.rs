use pesign::{utils::DisplayBytes, PeSign};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct CertInfo {
    pub issuer: String,
    pub subject: String,
    pub version: String,
    pub signature_algorithm: String,
    pub signature_value: String,
}

impl CertInfo {
    pub fn display_info(&self) {
        println!("Issuer: {}", self.issuer);
        println!("Subject: {}", self.subject);
        println!("Version: {}", self.version);
        println!("Signature Algorithm: {}", self.signature_algorithm);
        println!("Signature Value: {}", self.signature_value);
    }
}

pub fn extract_pe_sign(file_path: &str) -> anyhow::Result<Option<Vec<CertInfo>>> {
    let ret = PeSign::from_pe_path(file_path)?;
    let Some(pesign) = ret else {
        return Ok(None);
    };

    let mut certs = vec![];

    for cert in pesign.signed_data.cert_list {
        let cert_info = CertInfo {
            issuer: cert.issuer.to_string(),
            subject: cert.subject.to_string(),
            version: cert.version.to_string(),
            signature_algorithm: cert.signature_algorithm.to_string(),
            signature_value: cert.signature_value.to_bytes_string(),
        };
        certs.push(cert_info);
    }

    if certs.is_empty() {
        return Ok(None);
    }
    
    Ok(Some(certs))
}
