# talpa

a cli tool for managing [cloudflare tunnel](https://developers.cloudflare.com/cloudflare-tunnel/) routes on the fly. create and remove public hostnames pointing to local services — no dashboard clicking required.

works with **dashboard-managed tunnels** (remotely-managed via cloudflare api).

## install

```
cargo install talpa
```

## setup

```
talpa setup
```

you'll be prompted for:

- **account id** — found on the cloudflare dashboard sidebar
- **zone id** — found on the domain overview page
- **tunnel id** — found under zero trust → networks → tunnels
- **api token** — create one at [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens) with:
  - `zone : dns : edit`
  - `zone : zone : read`
  - `account : cloudflare tunnel : edit`

credentials are stored in the macos keychain.

## usage

**create a route:**

```
talpa dig app.example.com http://localhost:8080
```

this adds the ingress rule to your tunnel config and creates the cname dns record.

**remove a route:**

```
talpa plug app.example.com
```

removes the ingress rule and deletes the dns record.

**list active routes:**

```
talpa list
```

## license

mit
