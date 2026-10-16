//! Produces the authoritative first CredSSP `TSRequest` using sspi, the
//! reference CredSSP/SSPI implementation that Devolutions ships and that IronRDP
//! depends on.
//!
//! This is a reference oracle, not a client. It never opens a socket. Its output
//! is by definition a token a Windows RDP server accepts, which makes it the
//! thing to diff this repository's hand-written encoder against.

use sspi::credssp::{ClientMode, CredSspClient, CredSspMode};
use sspi::ntlm::NtlmConfig;

fn main() -> sspi::Result<()> {
    let user = std::env::args().nth(1).unwrap_or_else(|| "user".to_owned());

    let mut ntlm_config = NtlmConfig::default();
    ntlm_config.workstation = Some("RDPCLIENT".to_owned());

    let mut client = CredSspClient::new(
        // The server public key is only consumed on the last leg, when the
        // client proves it is talking to the real host. It is never used for the
        // first token, so a placeholder keeps this a pure encoder.
        vec![0x00],
        sspi::auth_identity::Credentials::new(user, "password", None),
        CredSspMode::Ntlm,
        ClientMode::Ntlm(ntlm_config),
        "TERMSRV/127.0.0.1".to_owned(),
    )?;

    let mut input = Vec::new();
    let (status, output) = client.initialize_security_context_sync(Some(input))?;

    println!("status: {status:?}");
    println!("token:  {} bytes", output.len());

    // Print the whole thing, then the NTLM message alone, because the envelope
    // and the token inside it are separately comparable.
    println!("tsrequest: {}", hex(&output));
    if let Some(ntlm) = find_nego_token(&output) {
        println!("ntlm:      {} bytes", ntlm.len());
        println!("ntlmhex:   {}", hex(ntlm));
    }

    Ok(())
}

/// The `negoToken` is the last OCTET STRING in the envelope. Finding it by
/// searching for the NTLM signature avoids re-implementing the parser.
fn find_nego_token(ts_request: &[u8]) -> Option<Vec<u8>> {
    let signature = b"NTLMSSP\0";
    let start = ts_request
        .windows(signature.len())
        .position(|window| window == signature)?;
    let len = u16::from_le_bytes([ts_request[start + 9], ts_request[start + 10]]) as usize;

    // The message type is followed by the flags, not a length, so the end has to
    // come from the OCTET STRING header that encloses it.
    let header = start.checked_sub(3)?;
    if ts_request[header] != 0x04 {
        return None;
    }

    let mut len_bytes = [0u8; 2];
    len_bytes.copy_from_slice(&ts_request[header + 1..header + 3]);
    let _ = len;
    Some(ts_request[start..].to_vec())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("")
}