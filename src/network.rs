use std::net::{TcpListener, TcpStream};
use std::io::{self, Read, Write};
use std::thread;

// Handle a single client connection (for now, just echo or print the message)
fn handle_client(mut stream: TcpStream) {
    let mut buffer = [0; 512];
    match stream.read(&mut buffer) {
        Ok(size) => {
            println!("Received: {}", String::from_utf8_lossy(&buffer[..size]));
            let response = b"Message received!\n";
            stream.write_all(response).unwrap();
        }
        Err(e) => eprintln!("Error reading stream: {}", e),
    }
}

// Start a server listening for incoming connections
pub fn start_server(addr: &str) -> io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    println!("Server listening on {}", addr);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(|| handle_client(stream));
            }
            Err(e) => eprintln!("Connection failed: {}", e),
        }
    }
    Ok(())
}

// Simple client to send a message to a peer
pub fn send_message(addr: &str, msg: &str) -> io::Result<()> {
    let mut stream = TcpStream::connect(addr)?;
    stream.write_all(msg.as_bytes())?;
    let mut buffer = [0; 512];
    let size = stream.read(&mut buffer)?;
    println!("Server responded: {}", String::from_utf8_lossy(&buffer[..size]));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_message() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let size = stream.read(&mut buf).unwrap();
                assert_eq!(b"ping", &buf[..size]);
                stream.write_all(b"pong").unwrap();
            }
        });

        let res = send_message(&addr.to_string(), "ping");
        assert!(res.is_ok());
        handle.join().unwrap();
    }
}
