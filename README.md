keepassxc-agent proof-of-concept
================================

This is a proof-of-concept stub OpenSSH ssh-agent implementation that talks with KeePassHTTP to obtain keys.

Note: Must use keys that have no passphrases, the KeePass database takes care of the encryption.

Screencast from a test session: http://hifi.iki.fi/keepassxc-agent-demo.ogv

**Do not use this exact code if you care about your SSH keys.**

Things that work:

 - OpenSSH RSA keys
 - Single connection only (no select(), fork() or threads)

Things to consider when testing:

 - Bundled AES key is static so it's not only insecure, it's practically unencrypted
 - The UNIX socket is not protected from other local users
 - When prompted for ID at association, type "keepassxc-agent"
 - Entry URL in KPXC needs to be "https://ssh-private-key"
 - Entry must contain an advanced attribute with key "KPH: id_rsa"
 - Attribute value must be the private key in PEM format (OpenSSH default)

Things that need to be done:

 - Rewrite in some sane programming language
 - Support multiple simultaneous agent connections
 - Proper AES key generation and storage
 - Clear keys from memory after each sign or if a timeout occurs after listing (a few seconds)
 - Figure out what is the best way to search and store the keys in the database

If you still think you want to test this, here's what you need to do:

```
php agent.php &>/dev/null &
export SSH_AGENT_SOCK=/tmp/agent.sock
ssh ...
```

The final implementation would require the user to set the sock env variable in `~/.login` or some place similiar and make sure the agent is running in the background. No other setup would be required. Any unlocked KeePass database will be used to search for identities.
