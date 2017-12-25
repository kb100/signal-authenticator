# Verifying releases

Security conscious invididuals can check the GPG signature of all releases
starting from `v0.4`.

If this is your first time verifying a release, you will need to import my GPG key.

```
gpg --keyserver pgp.mit.edu --recv-key 6E59B8E5A268E206A086329E507E1F837C14FFA9
```

Now you can verify releases as follows:

```
# assuming you have cloned the repo into ~/signal-authenticator
cd ~/signal-authenticator
git tag --verify v0.4
```

You should see a message telling you that the signature is good and
signed using the RSA key mentioned above.
It is OK if it says the signature is untrusted.
This just means that we have not verified identities in person and signed each
other's keys.
