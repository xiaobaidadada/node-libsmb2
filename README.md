# node-libsmb2

Node.js N-API native addon for SMB2/SMB3, built on [libsmb2](https://github.com/sahlberg/libsmb2).

No prebuilt binaries. `npm install` compiles the bundled libsmb2 sources with the system C compiler.

## Features

- **Built from source**: libsmb2 ships in `c-libsmb2/` and is compiled during install
- **SMB2 / SMB3**, **NTLM auth** (user / password / domain)
- **Non-blocking**: all network work runs on the libuv thread pool
- **Range reads**: `read(path, {offset, length})` for seeking and resumable downloads

## Install

```bash
npm install node-libsmb2
```

Requires a C toolchain and Python 3 (used by `node-gyp`):

| Platform | Dependency |
| -------- | ---------- |
| macOS | Xcode Command Line Tools + Python 3 |
| Linux | build-essential + python3 |
| Windows | Visual Studio Build Tools (Desktop C++) + Python 3 |

Use `npm install --ignore-scripts` to skip building (the module will not work).

## Usage

```js
const {Smb2Client} = require('node-libsmb2');

const client = new Smb2Client();

await client.connect({
  server: '192.168.1.10',
  share: 'public',
  user: 'alice',
  password: 'secret',
});

// list a directory
const entries = await client.opendir('/');
console.log(entries);

// read range (video seek / resume)
const buf = await client.read('/movie.mp4', {offset: 0, length: 1 << 20});

await client.disconnect();
```

### List shares

When you don't know the share name yet:

```js
const shares = await client.share_enum({
  server: '192.168.1.10',
  user: 'alice',
  password: 'secret',
});
// [{name: 'public', remark: '', is_ipc: false}, ...]
```

## API

See `js/index.d.ts`.

## License

MIT. Bundled libsmb2 keeps its own license (LGPL-2.1 / BSD-3-Clause), see `c-libsmb2/`.
