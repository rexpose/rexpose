use core::panic;
use std::{error::Error, process::Stdio, time::Duration};

use predicates::prelude::predicate;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, process::{Child, Command}, sync::mpsc::Receiver, task::JoinHandle, time::{sleep, timeout}};

use crate::common::{get_unused_port, CERT_PATH, KEY_PATH, SECRET};
mod common;

#[tokio::test]
async fn forwarding_tcp_unencrypted() -> Result<(), Box<dyn Error>> {
    let test_string = "test";
    let received = forwarding_tcp(false, false, test_string).await?;
    assert_eq!(test_string, received.as_str());
    Ok(())
}

#[tokio::test]
async fn forwarding_tcp_encrypted() -> Result<(), Box<dyn Error>> {
    let test_string = "test";
    let received = forwarding_tcp(true, true, test_string).await?;
    assert_eq!(test_string, received.as_str());
    Ok(())
}

#[tokio::test]
async fn fail_on_missing_client_encryption() -> Result<(), Box<dyn std::error::Error>> {
    let test_string = "test";
    let result = forwarding_tcp(true, false, test_string).await;
    assert_eq!(result.is_err(), true);
    Ok(())
}

#[tokio::test]
async fn fail_on_missing_server_encryption() -> Result<(), Box<dyn std::error::Error>> {
    let test_string = "test";
    let result = forwarding_tcp(false, true, test_string).await;
    assert_eq!(result.is_err(), true);
    Ok(())
}

#[tokio::test]
async fn do_not_trust_unknown_certificate() -> Result<(), Box<dyn std::error::Error>> {
    let client_port = get_unused_port().await?;
    let mgmt_port = get_unused_port().await?;
    let server_port = get_unused_port().await?;

    let mut server_handle = start_server(server_port, mgmt_port, false)?;
    sleep(Duration::from_millis(1000)).await;

    let mut client_cmd = assert_cmd::cargo::cargo_bin_cmd!();
    client_cmd.arg("-P")
        .arg(SECRET)
        .arg("-p")
        .arg(client_port.to_string())
        .arg("-m")
        .arg(mgmt_port.to_string())
        .arg("-a")
        .arg("localhost");
    client_cmd.assert()
        .failure()
        .stderr(predicate::str::contains("unable to establish connection"));
    server_handle.kill().await?;
    Ok(())
}

#[tokio::test]
async fn wrong_pw_test() -> Result<(), Box<dyn std::error::Error>> {
    let client_port = get_unused_port().await?;
    let mgmt_port = get_unused_port().await?;
    let server_port = get_unused_port().await?;

    let mut server_handle = start_server(server_port, mgmt_port, false)?;
    sleep(Duration::from_millis(1000)).await;

    let mut client_cmd = assert_cmd::cargo::cargo_bin_cmd!();
    client_cmd.arg("-P")
        .arg("wrong")
        .arg("-c")
        .arg(CERT_PATH)
        .arg("-p")
        .arg(client_port.to_string())
        .arg("-m")
        .arg(mgmt_port.to_string())
        .arg("-a")
        .arg("localhost");
    client_cmd.assert()
        .failure();
    server_handle.kill().await?;
    let server_output = server_handle.wait_with_output().await?;
    let error_output = String::from_utf8(server_output.stderr)?;
    assert_eq!(error_output.contains("authorization failed"), true);
    Ok(())
}

#[tokio::test]
async fn close_client_on_server_kill() -> Result<(), Box<dyn std::error::Error>> {
    let client_port = get_unused_port().await?;
    let mgmt_port = get_unused_port().await?;
    let server_port = get_unused_port().await?;

    let mut server_handle = start_server(server_port, mgmt_port, false)?;
    sleep(Duration::from_millis(1000)).await;

    let mut client_cmd = Command::new(assert_cmd::cargo::cargo_bin_cmd!().get_program());
    client_cmd.arg("-P")
        .arg(SECRET)
        .arg("-c")
        .arg(CERT_PATH)
        .arg("-p")
        .arg(client_port.to_string())
        .arg("-m")
        .arg(mgmt_port.to_string())
        .arg("-a")
        .arg("localhost")
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let client_handle = client_cmd.spawn()?;
    sleep(Duration::from_millis(1000)).await;

    server_handle.kill().await?;

    let output = timeout(Duration::from_secs(3), client_handle.wait_with_output()).await??;
    assert_eq!(output.status.success(), false);
    Ok(())
}

async fn forwarding_tcp(encrypted_server: bool, encrypted_client: bool, send: &str) -> Result<String, Box<dyn Error>> {
    let client_port = get_unused_port().await?;
    let mgmt_port = get_unused_port().await?;
    let server_port = get_unused_port().await?;
    
    let mut server_handle = start_server(server_port, mgmt_port, encrypted_server)?;
    sleep(Duration::from_millis(1000)).await;

    let mut client_cmd = Command::new(assert_cmd::cargo::cargo_bin_cmd!().get_program());
    client_cmd.arg("-P")
        .arg(SECRET)
        .arg("-c")
        .arg(CERT_PATH)
        .arg("-p")
        .arg(client_port.to_string())
        .arg("-m")
        .arg(mgmt_port.to_string())
        .arg("-a")
        .arg("localhost")
        .kill_on_drop(true);
    if encrypted_client {
        client_cmd.arg("-e");
    }
    let mut client_handle = client_cmd.spawn()?;

    sleep(Duration::from_millis(1000)).await;

    let (tx, rx) = tokio::sync::mpsc::channel::<String>(1);
    let client_join_handle = accept_and_receive(client_port);
    wait_and_send(rx, server_port);
    tx.send(send.to_string()).await?;
    let received = timeout(Duration::from_secs(1), client_join_handle).await??;

    server_handle.kill().await?;
    client_handle.kill().await?;

    return Ok(received);
}

fn start_server(server_port: u16, mgmt_port: u16, encrypted: bool) -> Result<Child, Box<dyn Error>> {
    let mut server_cmd = Command::new(assert_cmd::cargo::cargo_bin_cmd!().get_program());
    server_cmd.arg("-s")
        .arg("-c")
        .arg(CERT_PATH)
        .arg("-k")
        .arg(KEY_PATH)
        .arg("-P")
        .arg(SECRET)
        .arg("-p")
        .arg(server_port.to_string())
        .arg("-m")
        .arg(mgmt_port.to_string())
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if encrypted {
        server_cmd.arg("-e");
    }
    let server_handle = server_cmd.spawn()?;
    return Ok(server_handle)
}

fn wait_and_send(mut rx: Receiver<String>, port: u16) -> JoinHandle<()> {
    return tokio::spawn(async move {
        let mut stream = TcpStream::connect(format!("localhost:{}", port)).await.unwrap();
        let to_send = rx.recv().await.unwrap();
        stream.write_all(to_send.as_bytes()).await.unwrap();
    });
}

fn accept_and_receive(port: u16) -> JoinHandle<String> {
    return tokio::spawn(async move {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await.unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf: [u8; 256] = [0; 256];
        let size = stream.read(&mut buf).await.unwrap();
        if size == 0 {
            panic!("nothing received");
        }
        return String::from_utf8(std::vec::Vec::from_iter(buf.iter().take_while(|c| **c != 0).map(|c| *c))).unwrap();
    });
}