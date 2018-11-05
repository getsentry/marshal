<p align="center">
  <a href="https://sentry.io" target="_blank" align="center">
    <img src="https://sentry-brand.storage.googleapis.com/sentry-logo-black.png" width="280">
  </a>
  <br />
</p>

# Marshal - Sentry Annotated Protocol

<p align="center">
  <p align="center">
    <img src="https://github.com/getsentry/marshal/blob/master/artwork/marshal.png?raw=true" alt="marshal" width="480">
  </p>
</p>

Marshal is a support library for [semaphore](https://github.com/getsentry/semaphore).  It implements the
annotated Sentry protocol that supports metadata to be sent alongside.  It also implements a general
processing layer.

## License

Marshal is licensed under the MIT license.

## Development

We're going to settle on using vscode for this project for now. We're targeting
stable rust at the moment.

It depends on branched versions of serde at the moment which are pinned in the
`Cargo.toml`.

