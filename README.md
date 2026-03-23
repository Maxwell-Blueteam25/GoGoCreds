# GoGoCreds
GoGoCreds is a Proof-of-Concept (PoC) tool written in Go designed to explore Windows Internals and the mechanics of Pass-the-Hash (PtH) attacks. It demonstrates how to manipulate the Local Security Authority (LSA) to inject NTLM hashes into a sacrificial process.

### How it Works

The tool automates the "surgical" injection process using direct Windows API calls:

- **Process Creation:** Uses `CreateProcessWithLogonW` with `LOGON_NETCREDENTIALS_ONLY` to spawn a `cmd.exe` in a Type 9 logon context.
    
- **Session Identification:** Queries `OpenProcessToken` and `GetTokenInformation` to find the target Logon Session LUID.
    
- **System Impersonation:** Opens a handle to `lsass.exe` and uses `DuplicateTokenEx` / `SetThreadToken` to acquire the `SYSTEM` context.
    
- **LSA Interaction:** Connects via `LsaConnectUntrusted` and retrieves the `msv1_0` package ID using `LsaLookupAuthenticationPackage`.
    
- **Hash Injection:** Executes `LsaCallAuthenticationPackage` (Message Type 10) to perform an `MsV1_0DeriveCredential` request, swapping the dummy credentials with the provided NTLM hash.
    

### Usage

Currently, the tool requires a pre-extracted NTLM hash.

1. Dump hashes using `procdump` or `pypykatz`.
    
2. Run **GoGoCreds** as Administrator.
    
3. Provide the Username, Target LSASS PID, and the stolen NTLM Hash.
    

### Future Roadmap

- Programmatic hash extraction and parsing (removing the need for external tools).
    
- Implementation of Kerberos-based attacks (Pass-the-Ticket).
    
- Hardening and detection evasion techniques.
