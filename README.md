<p align="center">
  <img src="logo/logo.svg" alt="Sendit!" width="400" />
</p>

<p align="center">
  <strong>Self-hosted private sharing for secrets, credentials, and files, heavily inspired by <a href="https://bitwarden.com/products/send/">Bitwarden Send</a>.</strong>
</p>

**Sendit!** is self-hosted software that allows users to send sensitive information securely, ensuring no readable copies are left on the server, in emails, or in messages for future adversaries to discover.

Easily create short-lived links to **send** or **collect** secret text and files. Your recipients open the link right in their browser—no special app required. With a registered account, you get a central dashboard to manage your links, optional two-factor login (TOTP), and advanced security controls like one-time opens, expirations, and enforceable IP address restrictions.

An immutable audit log tracks all actions performed, including the IP addresses interacting with the Sendit! API.

Sendit! comprises of a HTML/JS/CSS front end which can be served by any webserver such as NGINX, Apache etc., and a small .NET 10 Minimal API which runs inside an Alpine docker container and includesan sqlitedb for the back end.

### How privacy works

Nothing sensitive is uploaded in the clear. **Your browser encrypts the content first**, using modern public-key X25519 cryptography combined with AES-256-GCM encryption for data at rest. The server stores only **ciphertext**—garbled data it cannot read—alongside account and link metadata.

The key that unlocks a share remains in the **URL fragment** (the part after the `#`). Browsers do not send this fragment to the server when loading a page, ensuring the host never receives the decryption key with the request. Optional link passwords add another layer of security in the browser. Dashboard-only details (such as private notes) are protected by a key derived from your account password, which is also encrypted on your device; see [`docs/CRYPTO.md`](docs/CRYPTO.md).

You control the deployment; Sendit! does not depend on a third-party “vault in the cloud” for its core design. For more technical details, see [`docs/`](docs/).

### Install

Clone the repo `git clone git@github.com:techfox-au/sendit.git`, then `cd sendit\deploy` and edit the API settings contained within `docker-compose.yml`. Run the API with `docker compose up -d` Then you need to configure your webserver (I recommend NGINX) to serve `sendit\public`.
