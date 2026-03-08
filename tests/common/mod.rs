use tokio::{io, net::TcpListener};

// renew test certificate: 
// openssl req  -nodes -new -x509 -days 397 -keyout tests/crypto/test.key -out tests/crypto/test.cert -addext "basicConstraints = CA:FALSE" -addext "subjectAltName = DNS:localhost" -subj "/CN=localhost" -addext "extendedKeyUsage = serverAuth, clientAuth" -addext "keyUsage = digitalSignature,keyAgreement"
pub const CERT_PATH: &str = "tests/crypto/test.cert";
pub const KEY_PATH: &str = "tests/crypto/test.key";

pub const SECRET: &str = "secret";

pub async fn get_unused_port() -> io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    return Ok(listener.local_addr()?.port());
}