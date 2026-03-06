/// Find an available UDP port in [lo, hi] using randomized probing.
pub fn find_available_port(lo: u16, hi: u16) -> Option<u16> {
    use rand::Rng;
    use std::net::UdpSocket;
    let size = (hi as u32) - (lo as u32) + 1;
    let offset: u32 = rand::rng().random_range(0..size);
    for i in 0..size {
        let port = lo + ((offset + i) % size) as u16;
        if UdpSocket::bind(("0.0.0.0", port)).is_ok() {
            return Some(port);
        }
    }
    None
}
