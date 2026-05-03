# dnsmesh + mutt example

This directory shows how to wire `dnsmesh` into mutt/neomutt as a
sendmail-compatible transport, so an existing mutt user can send and
receive DMP messages without leaving their MUA.

## One-time setup

```sh
# 1. Initialise an identity (prompts for a passphrase).
dnsmesh init alice --domain mesh.example.com

# 2. (Optional) add a `publish:` block to ~/.dmp/config.yaml so you
#    can publish your identity / prekeys to your authoritative zone:
#
#       publish:
#         zone: dmp.example.com
#         server: 192.0.2.1:53
#         tsig_key_name: dmp-publish
#         tsig_algorithm: hmac-sha256
#         tsig_secret_path: ~/.dmp/tsig.key   # base64 in this file

dnsmesh identity publish
dnsmesh identity refresh-prekeys --count 50

# 3. Pin a contact you want to message.
dnsmesh identity fetch bob@mesh.example.com --add
```

## mutt wiring

Drop `mutt.muttrc` into `~/.muttrc` (or source it from one). The two
load-bearing lines:

```muttrc
set sendmail = "/usr/local/bin/dnsmesh send -t"
set use_envelope_from = yes
```

`dnsmesh send -t` reads RFC 5322 from stdin and pulls the To: header
to pick the recipient — mutt's exact contract for `set sendmail`.

For inbound mail, pull from your mailbox slots into a Maildir mutt
already knows about:

```sh
dnsmesh recv --maildir ~/Mail/dmp --watch --interval 30
```

…or schedule it via cron / systemd if you'd rather avoid a long-lived
process. Each pass writes one file per decrypted message into
`~/Mail/dmp/new/`, with `X-DMP-Sender-SPK`, `X-DMP-Msg-Id`, and
`X-DMP-Timestamp` headers so you can attribute it inside mutt.

## Round-trip smoke

The shortest possible end-to-end test, after both sides are set up and
have pinned each other:

```sh
echo "hello bob" | dnsmesh send bob@mesh.example.com
# on bob's machine:
dnsmesh recv
```
