# ENS Backend

This is the backend server for an email-based ENS (Ethereum Name Service) system. It handles incoming emails, generates proofs, and interacts with the Ethereum blockchain to manage ENS subdomains.

## Prerequisites

Before you begin, ensure you have the following installed:

- **Rust**: Version 1.88 or later. We recommend using [rustup](https://rustup.rs/) to manage your Rust installation.
- **Build Tools**: A C compiler and development tools are required.
  - On Debian/Ubuntu: `sudo apt-get update && sudo apt-get install build-essential pkg-config libssl-dev`
  - On macOS: `xcode-select --install`
  - On Windows: You can use the "Build Tools for Visual Studio".
- **Docker and Docker Compose (Optional)**: For running the complete stack, including SMTP and IMAP servers.

## Getting Started

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/zkemail/ens-backend.git
    cd ens-backend
    ```

2.  **Install Rust toolchain:**
    If you don't have Rust, install it via rustup:
    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```
    The project uses the 2024 edition, so a recent compiler is needed.

## Configuration

The server requires a `config.json` file in the root directory. A sample is provided.

1.  **Copy the sample configuration:**

    ```bash
    cp config.sample.json config.json
    ```

2.  **Edit `config.json`:**
    Open `config.json` and fill in the required values:

    - `prover.apiKey`: Your API key for the proving service.
    - `prover.blueprintId`: The blueprint ID for the circuit.
    - `rpc[].url`: An RPC endpoint for the desired Ethereum network (e.g., from Alchemy or Infura).
    - `rpc[].privateKey`: The private key of the account that will be used to send transactions. **Warning**: Do not commit this file with your private key.

## Build

To build the application, run:

```bash
cargo build --release
```

The compiled binary will be located at `target/release/ens-backend`.

## Run

After building, you can start the server:

```bash
./target/release/ens-backend
```

The server will start and listen on port 4500 by default.

## Running with Docker (Recommended for full system)

The easiest way to run the backend along with its dependencies (like SMTP and IMAP servers) is by using Docker Compose.

1.  **Ensure Docker is running.**

2.  **Configure `config.json`** as described in the "Configuration" section.

3.  **Create a `.env` file for Docker Compose:**
    The `docker-compose.yaml` file uses environment variables to configure the `smtp` and `imap` services. Create a `.env` file in the root of the project:

    ```bash
    touch .env
    ```

    Add the following variables to the `.env` file, replacing the placeholder values with your actual configuration:

    ```env
    # SMTP Server Configuration
    SMTP_INTERNAL_SERVER_HOST=0.0.0.0
    SMTP_INTERNAL_SERVER_PORT=3000
    SMTP_PORT=3000
    SMTP_DOMAIN_NAME=yourdomain.com
    SMTP_LOGIN_ID=test
    SMTP_LOGIN_PASSWORD=test
    SMTP_MESSAGE_ID_DOMAIN=yourdomain.com

    # IMAP Server Configuration
    IMAP_LOGIN_ID=test
    IMAP_LOGIN_PASSWORD=test
    IMAP_DOMAIN_NAME=yourdomain.com
    IMAP_PORT=143
    IMAP_AUTH_TYPE=PLAIN
    ```

4.  **Start the services:**
    ```bash
    docker-compose up --build
    ```

This command will build the backend image and start the `backend`, `smtp`, and `imap` services. The backend will be available on port 4500 of your local machine.
