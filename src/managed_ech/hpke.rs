//! RFC 9180 HPKE (base mode) over DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256, built on the
//! `ring` provider so rustls can offer Encrypted Client Hello without aws-lc-rs.

use std::fmt;

use hkdf::{Hkdf, HkdfExtract};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
};
use rustls::internal::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
use rustls::internal::msgs::handshake::HpkeSymmetricCipherSuite;
use rustls::Error;
use sha2::digest::Output;
use sha2::Sha256;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

pub static ALL_SUITES: &[&dyn Hpke] = &[
    DH_KEM_X25519_HKDF_SHA256_AES_128,
    DH_KEM_X25519_HKDF_SHA256_CHACHA20_POLY1305,
];

pub static DH_KEM_X25519_HKDF_SHA256_AES_128: &HpkeX25519 = &HpkeX25519 {
    suite: HpkeSuite {
        kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
        sym: HpkeSymmetricCipherSuite {
            kdf_id: HpkeKdf::HKDF_SHA256,
            aead_id: HpkeAead::AES_128_GCM,
        },
    },
    aead: &aead::AES_128_GCM,
};

pub static DH_KEM_X25519_HKDF_SHA256_CHACHA20_POLY1305: &HpkeX25519 = &HpkeX25519 {
    suite: HpkeSuite {
        kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
        sym: HpkeSymmetricCipherSuite {
            kdf_id: HpkeKdf::HKDF_SHA256,
            aead_id: HpkeAead::CHACHA20_POLY_1305,
        },
    },
    aead: &aead::CHACHA20_POLY1305,
};

const HPKE_V1: &[u8] = b"HPKE-v1";
const N_SECRET: usize = 32;

pub struct HpkeX25519 {
    suite: HpkeSuite,
    aead: &'static aead::Algorithm,
}

impl HpkeX25519 {
    fn suite_id(&self) -> Vec<u8> {
        [
            b"HPKE".as_slice(),
            &self.suite.kem.to_array(),
            &self.suite.sym.kdf_id.to_array(),
            &self.suite.sym.aead_id.to_array(),
        ]
        .concat()
    }

    fn setup_sealer_with(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
        sk_e: &StaticSecret,
    ) -> Result<(EncapsulatedSecret, Context), Error> {
        let (shared_secret, enc) = encap(&pub_key.0, sk_e)?;
        Ok((enc, self.key_schedule(&shared_secret, info)?))
    }

    fn key_schedule(&self, shared_secret: &[u8], info: &[u8]) -> Result<Context, Error> {
        let (key, base_nonce) = self.derive_key_and_nonce(shared_secret, info)?;
        Context::new(self.aead, &key, base_nonce)
    }

    fn derive_key_and_nonce(
        &self,
        shared_secret: &[u8],
        info: &[u8],
    ) -> Result<(Vec<u8>, [u8; NONCE_LEN]), Error> {
        let suite_id = self.suite_id();
        let (psk_id_hash, _) = labeled_extract(&suite_id, &[], b"psk_id_hash", &[]);
        let (info_hash, _) = labeled_extract(&suite_id, &[], b"info_hash", info);
        // mode_base = 0x00
        let context = [&[0u8][..], &psk_id_hash, &info_hash].concat();
        let (_, secret) = labeled_extract(&suite_id, shared_secret, b"secret", &[]);

        let mut key = vec![0u8; self.aead.key_len()];
        labeled_expand(&secret, &suite_id, b"key", &context, &mut key)?;
        let mut base_nonce = [0u8; NONCE_LEN];
        labeled_expand(&secret, &suite_id, b"base_nonce", &context, &mut base_nonce)?;
        Ok((key, base_nonce))
    }
}

impl Hpke for HpkeX25519 {
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let (enc, mut sealer) = self.setup_sealer(info, pub_key)?;
        Ok((enc, sealer.seal(aad, plaintext)?))
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), Error> {
        let (enc, context) = self.setup_sealer_with(info, pub_key, &random_secret()?)?;
        Ok((enc, Box::new(context)))
    }

    fn open(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Vec<u8>, Error> {
        self.setup_opener(enc, info, secret_key)?
            .open(aad, ciphertext)
    }

    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener + 'static>, Error> {
        let shared_secret = decap(&enc.0, secret_key.secret_bytes())?;
        Ok(Box::new(self.key_schedule(&shared_secret, info)?))
    }

    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
        let secret = random_secret()?;
        let public = PublicKey::from(&secret);
        Ok((
            HpkePublicKey(public.as_bytes().to_vec()),
            HpkePrivateKey::from(secret.to_bytes().to_vec()),
        ))
    }

    fn suite(&self) -> HpkeSuite {
        self.suite
    }
}

impl fmt::Debug for HpkeX25519 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.suite.fmt(f)
    }
}

struct Context {
    key: LessSafeKey,
    base_nonce: [u8; NONCE_LEN],
    seq: u64,
}

impl Context {
    fn new(
        aead: &'static aead::Algorithm,
        key: &[u8],
        base_nonce: [u8; NONCE_LEN],
    ) -> Result<Self, Error> {
        let key = UnboundKey::new(aead, key).map_err(|_| hpke_error("invalid AEAD key"))?;
        Ok(Self {
            key: LessSafeKey::new(key),
            base_nonce,
            seq: 0,
        })
    }

    fn nonce(&self) -> Result<Nonce, Error> {
        // u64 is far below the RFC limit of 2^96 - 1, so refuse to reach the end of it.
        if self.seq == u64::MAX {
            return Err(hpke_error("message limit reached"));
        }
        let mut nonce = self.base_nonce;
        for (n, s) in nonce[NONCE_LEN - 8..]
            .iter_mut()
            .zip(self.seq.to_be_bytes())
        {
            *n ^= s;
        }
        Ok(Nonce::assume_unique_for_key(nonce))
    }
}

impl HpkeSealer for Context {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.nonce()?;
        let mut buf = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::from(aad), &mut buf)
            .map_err(|_| hpke_error("seal failed"))?;
        self.seq += 1;
        Ok(buf)
    }
}

impl HpkeOpener for Context {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.nonce()?;
        let mut buf = ciphertext.to_vec();
        let len = self
            .key
            .open_in_place(nonce, Aad::from(aad), &mut buf)
            .map_err(|_| hpke_error("open failed"))?
            .len();
        buf.truncate(len);
        self.seq += 1;
        Ok(buf)
    }
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HpkeContext")
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

fn encap(pk_r: &[u8], sk_e: &StaticSecret) -> Result<([u8; N_SECRET], EncapsulatedSecret), Error> {
    let pk_r = x25519_public(pk_r)?;
    let enc = PublicKey::from(sk_e);
    let dh = sk_e.diffie_hellman(&pk_r);
    let kem_context = [enc.as_bytes().as_slice(), pk_r.as_bytes()].concat();
    let shared_secret = extract_and_expand(&dh, &kem_context)?;
    Ok((shared_secret, EncapsulatedSecret(enc.as_bytes().to_vec())))
}

fn decap(enc: &[u8], sk_r: &[u8]) -> Result<[u8; N_SECRET], Error> {
    let pk_e = x25519_public(enc)?;
    let sk_r = <[u8; 32]>::try_from(sk_r)
        .map(StaticSecret::from)
        .map_err(|_| hpke_error("invalid X25519 private key length"))?;
    let dh = sk_r.diffie_hellman(&pk_e);
    let kem_context = [enc, PublicKey::from(&sk_r).as_bytes()].concat();
    extract_and_expand(&dh, &kem_context)
}

fn extract_and_expand(dh: &SharedSecret, kem_context: &[u8]) -> Result<[u8; N_SECRET], Error> {
    if !dh.was_contributory() {
        return Err(hpke_error("X25519 shared secret is all zero"));
    }
    let suite_id = [
        b"KEM".as_slice(),
        &HpkeKem::DHKEM_X25519_HKDF_SHA256.to_array(),
    ]
    .concat();
    let (_, eae_prk) = labeled_extract(&suite_id, &[], b"eae_prk", dh.as_bytes());
    let mut shared_secret = [0u8; N_SECRET];
    labeled_expand(
        &eae_prk,
        &suite_id,
        b"shared_secret",
        kem_context,
        &mut shared_secret,
    )?;
    Ok(shared_secret)
}

fn labeled_extract(
    suite_id: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> (Output<Sha256>, Hkdf<Sha256>) {
    let mut extract = HkdfExtract::<Sha256>::new(Some(salt));
    for part in [HPKE_V1, suite_id, label, ikm] {
        extract.input_ikm(part);
    }
    extract.finalize()
}

fn labeled_expand(
    prk: &Hkdf<Sha256>,
    suite_id: &[u8],
    label: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    let len = u16::try_from(out.len())
        .map_err(|_| hpke_error("expand length too large"))?
        .to_be_bytes();
    prk.expand_multi_info(&[&len, HPKE_V1, suite_id, label, info], out)
        .map_err(|_| hpke_error("expand length too large"))
}

fn x25519_public(bytes: &[u8]) -> Result<PublicKey, Error> {
    <[u8; 32]>::try_from(bytes)
        .map(PublicKey::from)
        .map_err(|_| hpke_error("invalid X25519 public key length"))
}

fn random_secret() -> Result<StaticSecret, Error> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::FailedToGetRandomBytes)?;
    Ok(StaticSecret::from(bytes))
}

fn hpke_error(msg: &str) -> Error {
    Error::General(format!("hpke: {msg}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    struct Vector {
        suite: &'static HpkeX25519,
        sk_em: &'static str,
        pk_rm: &'static str,
        sk_rm: &'static str,
        enc: &'static str,
        shared_secret: &'static str,
        key: &'static str,
        base_nonce: &'static str,
        // (sequence number, aad, nonce, ct)
        encryptions: &'static [(u64, &'static str, &'static str, &'static str)],
    }

    const INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
    const PT: &str = "4265617574792069732074727574682c20747275746820626561757479";

    // RFC 9180 A.1.1
    const A1: Vector = Vector {
        suite: DH_KEM_X25519_HKDF_SHA256_AES_128,
        sk_em: "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
        pk_rm: "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
        sk_rm: "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
        enc: "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
        shared_secret: "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
        key: "4531685d41d65f03dc48f6b8302c05b0",
        base_nonce: "56d890e5accaaf011cff4b7d",
        encryptions: &[
            (0, "436f756e742d30", "56d890e5accaaf011cff4b7d",
             "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"),
            (1, "436f756e742d31", "56d890e5accaaf011cff4b7c",
             "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84"),
            (2, "436f756e742d32", "56d890e5accaaf011cff4b7f",
             "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180"),
            (4, "436f756e742d34", "56d890e5accaaf011cff4b79",
             "583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a09fc0012bc69fccaa251c0246d"),
            (255, "436f756e742d323535", "56d890e5accaaf011cff4b82",
             "7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a"),
            (256, "436f756e742d323536", "56d890e5accaaf011cff4a7d",
             "957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2"),
        ],
    };

    // RFC 9180 A.2.1
    const A2: Vector = Vector {
        suite: DH_KEM_X25519_HKDF_SHA256_CHACHA20_POLY1305,
        sk_em: "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
        pk_rm: "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
        sk_rm: "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
        enc: "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
        shared_secret: "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7",
        key: "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
        base_nonce: "5c4d98150661b848853b547f",
        encryptions: &[
            (0, "436f756e742d30", "5c4d98150661b848853b547f",
             "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"),
            (1, "436f756e742d31", "5c4d98150661b848853b547e",
             "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c"),
            (2, "436f756e742d32", "5c4d98150661b848853b547d",
             "71146bd6795ccc9c49ce25dda112a48f202ad220559502cef1f34271e0cb4b02b4f10ecac6f48c32f878fae86b"),
            (4, "436f756e742d34", "5c4d98150661b848853b547b",
             "63357a2aa291f5a4e5f27db6baa2af8cf77427c7c1a909e0b37214dd47db122bb153495ff0b02e9e54a50dbe16"),
            (255, "436f756e742d323535", "5c4d98150661b848853b5480",
             "18ab939d63ddec9f6ac2b60d61d36a7375d2070c9b683861110757062c52b8880a5f6b3936da9cd6c23ef2a95c"),
            (256, "436f756e742d323536", "5c4d98150661b848853b557f",
             "7a4a13e9ef23978e2c520fd4d2e757514ae160cd0cd05e556ef692370ca53076214c0c40d4c728d6ed9e727a5b"),
        ],
    };

    fn check_vector(v: &Vector) {
        let sk_e = StaticSecret::from(<[u8; 32]>::try_from(hex(v.sk_em)).unwrap());
        let (shared_secret, enc) = encap(&hex(v.pk_rm), &sk_e).unwrap();
        assert_eq!(enc.0, hex(v.enc));
        assert_eq!(shared_secret.to_vec(), hex(v.shared_secret));
        assert_eq!(decap(&enc.0, &hex(v.sk_rm)).unwrap(), shared_secret);

        let (key, base_nonce) = v
            .suite
            .derive_key_and_nonce(&shared_secret, &hex(INFO))
            .unwrap();
        assert_eq!(key, hex(v.key));
        assert_eq!(base_nonce.to_vec(), hex(v.base_nonce));

        let pk_r = HpkePublicKey(hex(v.pk_rm));
        let (_, mut sealer) = v.suite.setup_sealer_with(&hex(INFO), &pk_r, &sk_e).unwrap();
        let mut opener = v.suite.key_schedule(&shared_secret, &hex(INFO)).unwrap();
        for &(seq, aad, nonce, ct) in v.encryptions {
            sealer.seq = seq;
            opener.seq = seq;
            assert_eq!(sealer.nonce().unwrap().as_ref().to_vec(), hex(nonce));
            assert_eq!(
                HpkeSealer::seal(&mut sealer, &hex(aad), &hex(PT)).unwrap(),
                hex(ct),
                "seq {seq}"
            );
            assert_eq!(sealer.seq, seq + 1);
            assert_eq!(
                HpkeOpener::open(&mut opener, &hex(aad), &hex(ct)).unwrap(),
                hex(PT)
            );
        }

        // First encryption through the public trait surface.
        let sk_r = HpkePrivateKey::from(hex(v.sk_rm));
        let (_, aad, _, ct) = v.encryptions[0];
        let pt = v
            .suite
            .open(&enc, &hex(INFO), &hex(aad), &hex(ct), &sk_r)
            .unwrap();
        assert_eq!(pt, hex(PT));
    }

    #[test]
    fn rfc9180_a1_x25519_sha256_aes128gcm() {
        check_vector(&A1);
    }

    #[test]
    fn rfc9180_a2_x25519_sha256_chacha20poly1305() {
        check_vector(&A2);
    }

    #[test]
    fn round_trip_all_suites() {
        for suite in ALL_SUITES {
            let (pk, sk) = suite.generate_key_pair().unwrap();
            assert_eq!(pk.0.len(), 32);
            let (enc, ct) = suite.seal(b"info", b"aad", b"hello", &pk).unwrap();
            assert_eq!(
                suite.open(&enc, b"info", b"aad", &ct, &sk).unwrap(),
                b"hello"
            );
            assert!(suite.open(&enc, b"info", b"bad", &ct, &sk).is_err());
            assert!(suite.open(&enc, b"other", b"aad", &ct, &sk).is_err());
            let mut tampered = ct.clone();
            tampered[0] ^= 1;
            assert!(suite.open(&enc, b"info", b"aad", &tampered, &sk).is_err());

            let (enc, mut sealer) = suite.setup_sealer(b"info", &pk).unwrap();
            let mut opener = suite.setup_opener(&enc, b"info", &sk).unwrap();
            for i in 0..3u8 {
                let ct = sealer.seal(&[i], &[i; 5]).unwrap();
                assert_eq!(opener.open(&[i], &ct).unwrap(), vec![i; 5]);
            }
        }
    }

    #[test]
    fn suites_match_rustls_ids() {
        let ids: Vec<_> = ALL_SUITES
            .iter()
            .map(|s| {
                let s = s.suite();
                (
                    u16::from(s.kem),
                    u16::from(s.sym.kdf_id),
                    u16::from(s.sym.aead_id),
                )
            })
            .collect();
        assert_eq!(ids, vec![(0x20, 1, 1), (0x20, 1, 3)]);
    }

    #[test]
    fn rejects_all_zero_shared_secret() {
        let low_order = HpkePublicKey(vec![0u8; 32]);
        for suite in ALL_SUITES {
            assert!(suite.setup_sealer(b"", &low_order).is_err());
        }
        let (_, sk) = ALL_SUITES[0].generate_key_pair().unwrap();
        assert!(decap(&[0u8; 32], sk.secret_bytes()).is_err());
    }

    #[test]
    fn rejects_bad_key_lengths() {
        let suite = ALL_SUITES[0];
        assert!(suite
            .setup_sealer(b"", &HpkePublicKey(vec![9; 31]))
            .is_err());
        let (pk, _) = suite.generate_key_pair().unwrap();
        let (enc, _) = suite.seal(b"", b"", b"x", &pk).unwrap();
        let short = HpkePrivateKey::from(vec![1; 16]);
        assert!(suite.setup_opener(&enc, b"", &short).is_err());
    }

    #[test]
    fn sequence_overflow_is_an_error() {
        let (pk, _) = ALL_SUITES[0].generate_key_pair().unwrap();
        let sk_e = random_secret().unwrap();
        let (_, mut sealer) = DH_KEM_X25519_HKDF_SHA256_AES_128
            .setup_sealer_with(b"", &pk, &sk_e)
            .unwrap();
        sealer.seq = u64::MAX - 1;
        assert!(HpkeSealer::seal(&mut sealer, b"", b"x").is_ok());
        assert!(HpkeSealer::seal(&mut sealer, b"", b"x").is_err());
    }
}
