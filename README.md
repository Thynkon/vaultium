# Vaultium

This project contains a **client** and a **server**, both written in Rust, along with shared libraries and tooling.

## Report

A detailed report that explains every choice regarding the cryptographic algorithms, nounces, keys size as well as other important information can be found at [report.pdf](./report/report.pdf).

## Repository Layout

```
src/
├── Cargo.lock
├── Cargo.toml
├── client/
├── server/
├── lib/
├── unpacker/
├── packer/
├── data/
└── target/
```

---

## Prerequisites

- Rust toolchain (stable)
- `cargo`
- Linux environment (Unix permissions assumed)

---

## Running the Server

1. Go to the server directory:

```bash
cd src/server
```

2. Build and run the server:

```bash
cargo run --release
```

The server will start and listen on the configured address (by default `http://127.0.0.1:8085`).

---

## Running the Client

1. Go to the client directory:

```bash
cd src/client
```

2. Run the client using `cargo run --release --` followed by the required arguments.

### Required Arguments

| Argument     | Description                                |
| ------------ | ------------------------------------------ |
| `--base-url` | Server base URL                            |
| `--work-dir` | Working directory used to store/read files |
| `--id`       | Client identifier (UUID v4)                |

### Optional Arguments

| Argument            | Description                                                              |
| ------------------- | ------------------------------------------------------------------------ |
| `--dictionnary`     | Path to the dictionary file (required together with `--random-password`) |
| `--random-password` | Generate a random password from the dictionary instead of prompting      |
| `--select-file`     | Parsed but not currently wired to any behaviour (reserved)               |

> ⚠️ The `--id` **must be a UUID v4**. The UUID shown in examples below is **only a placeholder**.

---

## Interactive Mode

The client is **fully interactive** — after launching, it will guide you through the following prompts:

1. **Mode** — choose one of:
   - `encrypt`
   - `decrypt`
   - `change-password`

2. **Target** _(encrypt / decrypt only)_ — choose one of:
   - `file` — pick a single file
   - `directory` — pick a directory (all files inside are processed recursively)

3. **Path selector** — browse and select the target file or directory from your `--work-dir`.

4. **Password prompt** _(encrypt / change-password only)_ — either type a password (minimum 10 characters, confirmed twice) or, if `--random-password` and `--dictionnary` are set, a random passphrase is generated automatically.

---

## Security Notes

- **`change-password` only rotates the Key Encryption Key (KEK).** It does not re-encrypt the Master Encryption Key (MEK) with the new KEK. If you need a full re-key, re-encrypt your files from scratch.
- Keys call `.zeroize()` on drop to clear sensitive material from memory.
- The server's KEM and signing public keys are baked into the client binary at compile time.

---

## Example Invocations

### Encrypt (manual password prompt)

```bash
cargo run --release -- \
  --base-url http://127.0.0.1:8085 \
  --work-dir ./data/files/ \
  --id 2c6fd123-ef03-4246-b020-e61a364168b7
```

Then select **encrypt** in the interactive menu and enter your password when prompted.

---

### Encrypt (random password from dictionary)

```bash
cargo run --release -- \
  --base-url http://127.0.0.1:8085 \
  --work-dir ./data/files/ \
  --id 2c6fd123-ef03-4246-b020-e61a364168b7 \
  --random-password \
  --dictionnary ./data/dictionnary.txt
```

Then select **encrypt** in the interactive menu.

---

### Decrypt

```bash
cargo run --release -- \
  --base-url http://127.0.0.1:8085 \
  --work-dir ./data/files/ \
  --id 2c6fd123-ef03-4246-b020-e61a364168b7
```

Then select **decrypt** in the interactive menu.

---

### Change Password

```bash
cargo run --release -- \
  --base-url http://127.0.0.1:8085 \
  --work-dir ./data/files/ \
  --id 2c6fd123-ef03-4246-b020-e61a364168b7
```

Then select **change-password** in the interactive menu and enter the new password when prompted.

> ⚠️ See [Security Notes](#security-notes) for what `change-password` does and does not do.

---

## Notes

- Always run the **server first**, then the client.
- Use a **new UUID v4** per client instance.
- Paths can be relative or absolute.
- Running `cargo run` without the required arguments will fail.
- Passwords must be at least **10 characters** long.
- `--dictionnary` is only valid when used together with `--random-password`.

---

## Generate a UUID v4

```bash
uuidgen
```

Example output:

```
2c6fd123-ef03-4246-b020-e61a364168b7
```
