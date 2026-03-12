use std::error::Error;

use tokio::{io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt}, task::JoinHandle};

const BUF_SIZE: usize = 8 * 1024;

pub fn forward_streams<S1: AsyncWrite + AsyncRead + Send + 'static, S2: AsyncWrite + AsyncRead + Send + 'static>(stream_1: S1, stream_2: S2) -> (JoinHandle<()>, JoinHandle<()>) {
    let (mut stream_read_1, mut stream_write_1) = io::split(stream_1);
    let (mut stream_read_2, mut stream_write_2) = io::split(stream_2);
    let join_handle_1 = tokio::spawn(async move { 
        if let Err(err) = copy(&mut stream_read_1, &mut stream_write_2).await {
            log::debug!("data connection closed because of error: {}", err);
        }
        let _ = stream_write_2.shutdown().await;
    });
    let join_handle_2 = tokio::spawn(async move { 
        if let Err(err) = copy(&mut stream_read_2, &mut stream_write_1).await {
            log::debug!("data connection closed because of error: {}", err);
        }
        let _ = stream_write_1.shutdown().await;
    });
    return (join_handle_1, join_handle_2);
}

async fn copy<R: AsyncRead + Unpin + Send, W: AsyncWrite + Unpin>(src: &mut R, dst: &mut W) -> Result<(), Box<dyn Error>> {
    let mut buf: [u8;BUF_SIZE] = [0;BUF_SIZE];
    loop {
        let size = src.read(&mut buf).await?;
        if size == 0 {
            log::debug!("zero bytes read => closing connection");
            break;
        }
        dst.write_all(&buf[..size]).await?;
        dst.flush().await?
    }
    return Ok(());
}
