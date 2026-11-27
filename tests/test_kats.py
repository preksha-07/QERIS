"""Known Answer Tests (KATs) for S1 Cryptographic Primitives.

This test module verifies cryptographic primitives implemented or used by S1
against official published reference vectors from standards bodies (RFC, NIST).

Coverage:
1. HKDF-SHA256: RFC 5869 Test Case 1 & Test Case 2.
2. Ed25519: RFC 8032 Section 7.1 Test Vector 1 & Test Vector 2.
3. AES-256-GCM: NIST SP 800-38D Test Case 13 & Test Case 14.
4. ML-KEM-512: NIST FIPS 203 / ACVP limitation and parameter verification.
5. ML-DSA-65: NIST FIPS 204 / ACVP limitation and parameter verification.

Note on deterministic PQC KATs:
Full deterministic KAT testing for ML-KEM-512 and ML-DSA-65 requires injecting
deterministic randomness (e.g., NIST ACVP seed/entropy vectors for encapsulation
and signature generation). The underlying C liboqs / liboqs-python bindings and
S1 public wrappers do not expose deterministic seed injection for encapsulation
(oqs.KeyEncapsulation.encap_secret) or signing (oqs.Signature.sign). Per project
requirements, we do not alter crypto wrappers or fabricate pseudorandom vectors;
we document and programmatically verify these API constraints while testing
the deterministic components (e.g., parameter sizes, de-encapsulation, and verification).
"""

import binascii
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from qeris.session_crypto import (
    _hkdf_sha256,
    generate_keypair,
    encapsulate,
    decapsulate,
    KEM_ALGORITHM,
    PUBLIC_KEY_LENGTH,
    SECRET_KEY_LENGTH,
    CIPHERTEXT_LENGTH,
    SHARED_SECRET_LENGTH,
)
from qeris.device_auth import (
    Ed25519DeviceCredential,
    verify_device_signature,
)
from qeris.policy.signed_policy import (
    DEFAULT_SIG_ALG,
    sign_policy,
    verify_policy,
    SignedPolicyEnvelope,
)
import oqs


# =============================================================================
# 1. HKDF-SHA256 — RFC 5869 Reference Vectors
# =============================================================================

class TestHKDFSHA256KAT:
    """HKDF-SHA256 Known Answer Tests from RFC 5869 Section 4.

    Source: RFC 5869, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)"
    Section 4.1: Test Case 1
    Section 4.2: Test Case 2
    """

    def test_rfc5869_test_case_1(self):
        """RFC 5869 Test Case 1: Basic test case with SHA-256.

        Hash = SHA-256
        IKM  = 0x0b * 22
        salt = 0x000102030405060708090a0b0c
        info = 0xf0f1f2f3f4f5f6f7f8f9
        L    = 42 octets
        """
        ikm = bytes([0x0b] * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        length = 42

        # Published RFC 5869 values:
        expected_okm = bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )

        derived_okm = _hkdf_sha256(ikm=ikm, salt=salt, info=info, length=length)
        assert derived_okm == expected_okm, (
            f"RFC 5869 Test Case 1 failure:\n"
            f"Expected: {expected_okm.hex()}\n"
            f"Got:      {derived_okm.hex()}"
        )

    def test_rfc5869_test_case_2(self):
        """RFC 5869 Test Case 2: Test case with longer inputs/outputs.

        Hash = SHA-256
        IKM  = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
               202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
               (80 octets)
        salt = 0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
               808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
               a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
               (80 octets)
        info = 0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf
               d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef
               f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
               (80 octets)
        L    = 82 octets
        """
        ikm = bytes(range(0x00, 0x50))
        salt = bytes(range(0x60, 0xB0))
        info = bytes(range(0xB0, 0x100))
        length = 82

        expected_okm = bytes.fromhex(
            "b11e398dc80327a1c8e7f78c596a4934"
            "4f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09"
            "da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f"
            "1d87"
        )

        derived_okm = _hkdf_sha256(ikm=ikm, salt=salt, info=info, length=length)
        assert derived_okm == expected_okm, (
            f"RFC 5869 Test Case 2 failure:\n"
            f"Expected: {expected_okm.hex()}\n"
            f"Got:      {derived_okm.hex()}"
        )


# =============================================================================
# 2. Ed25519 — RFC 8032 Reference Vectors
# =============================================================================

class TestEd25519KAT:
    """Ed25519 Known Answer Tests from RFC 8032 Section 7.1.

    Source: RFC 8032, "Edwards-Curve Digital Signature Algorithm (EdDSA)"
    Section 7.1: Test Vectors for Ed25519
    """

    def test_rfc8032_vector_1(self):
        """RFC 8032 Section 7.1 Test Vector 1: Empty message.

        SECRET KEY (seed):
          9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
        PUBLIC KEY:
          d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
        MESSAGE:
          (empty)
        SIGNATURE:
          e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155
          5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
        """
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        expected_pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        message = b""
        expected_sig = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )

        cred = Ed25519DeviceCredential.from_private_bytes(seed)

        # 1. Public key derivation matches RFC 8032
        assert cred.public_key_bytes == expected_pub, (
            f"Ed25519 Vector 1 public key mismatch:\n"
            f"Expected: {expected_pub.hex()}\n"
            f"Got:      {cred.public_key_bytes.hex()}"
        )

        # 2. Signing produces exact RFC 8032 signature
        sig = cred._private_key.sign(message)
        assert sig == expected_sig, (
            f"Ed25519 Vector 1 signature mismatch:\n"
            f"Expected: {expected_sig.hex()}\n"
            f"Got:      {sig.hex()}"
        )

        # 3. Verification succeeds with standard Ed25519 public key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pub = Ed25519PublicKey.from_public_bytes(cred.public_key_bytes)
        pub.verify(sig, message)

    def test_rfc8032_vector_2(self):
        """RFC 8032 Section 7.1 Test Vector 2: 1-byte message (0x72).

        SECRET KEY (seed):
          4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
        PUBLIC KEY:
          3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
        MESSAGE:
          72
        SIGNATURE:
          92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da
          085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00
        """
        seed = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
        expected_pub = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        message = bytes.fromhex("72")
        expected_sig = bytes.fromhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        )

        cred = Ed25519DeviceCredential.from_private_bytes(seed)

        assert cred.public_key_bytes == expected_pub
        sig = cred._private_key.sign(message)
        assert sig == expected_sig

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pub = Ed25519PublicKey.from_public_bytes(cred.public_key_bytes)
        pub.verify(sig, message)


# =============================================================================
# 3. AES-256-GCM — NIST SP 800-38D Reference Vectors
# =============================================================================

class TestAES256GCMKAT:
    """AES-256-GCM Known Answer Tests from NIST SP 800-38D.

    Source: NIST Special Publication 800-38D,
    "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)
    and GMAC", Example Test Vectors (AES-256 Key, 96-bit IV).
    """

    def test_nist_sp800_38d_test_case_13(self):
        """NIST SP 800-38D Test Case 13: Zero-length Plaintext & AAD.

        Key: 256 bits (all 0x00)
        IV:  96 bits (all 0x00)
        PT:  0 octets (empty)
        AAD: 0 octets (empty)
        CT:  0 octets (empty)
        Tag: 530f8afbc74536b9a963b4f1c4cb738b
        """
        key = bytes([0x00] * 32)
        iv = bytes([0x00] * 12)
        pt = b""
        aad = b""
        expected_tag = bytes.fromhex("530f8afbc74536b9a963b4f1c4cb738b")

        aesgcm = AESGCM(key)
        # AESGCM.encrypt appends 16-byte tag to ciphertext:
        ct_and_tag = aesgcm.encrypt(iv, pt, aad)
        tag = ct_and_tag[-16:]
        ct = ct_and_tag[:-16]

        assert ct == b"", "Expected empty ciphertext"
        assert tag == expected_tag, (
            f"NIST SP 800-38D Case 13 tag mismatch:\n"
            f"Expected: {expected_tag.hex()}\n"
            f"Got:      {tag.hex()}"
        )

        # Verify decryption recovers empty plaintext
        decrypted = aesgcm.decrypt(iv, ct_and_tag, aad)
        assert decrypted == pt

    def test_nist_sp800_38d_test_case_14(self):
        """NIST SP 800-38D Test Case 14: 16-octet Plaintext (all zeros), no AAD.

        Key: 256 bits (all 0x00)
        IV:  96 bits (all 0x00)
        PT:  16 octets (all 0x00)
        AAD: 0 octets (empty)
        CT:  cea7403d4d606b6e074ec5d3baf39d18
        Tag: d0d1c8a799996bf0265b98b5d48ab919
        """
        key = bytes([0x00] * 32)
        iv = bytes([0x00] * 12)
        pt = bytes([0x00] * 16)
        aad = b""
        expected_ct = bytes.fromhex("cea7403d4d606b6e074ec5d3baf39d18")
        expected_tag = bytes.fromhex("d0d1c8a799996bf0265b98b5d48ab919")

        aesgcm = AESGCM(key)
        ct_and_tag = aesgcm.encrypt(iv, pt, aad)
        ct = ct_and_tag[:-16]
        tag = ct_and_tag[-16:]

        assert ct == expected_ct, (
            f"NIST SP 800-38D Case 14 CT mismatch:\n"
            f"Expected: {expected_ct.hex()}\n"
            f"Got:      {ct.hex()}"
        )
        assert tag == expected_tag, (
            f"NIST SP 800-38D Case 14 Tag mismatch:\n"
            f"Expected: {expected_tag.hex()}\n"
            f"Got:      {tag.hex()}"
        )

        decrypted = aesgcm.decrypt(iv, ct_and_tag, aad)
        assert decrypted == pt


# =============================================================================
# 4. ML-KEM-512 — NIST FIPS 203 KAT & Parameter Verification
# =============================================================================

class TestMLKEM512KAT:
    """ML-KEM-512 Known Answer Tests and FIPS 203 parameter verification.

    Standards Reference:
      NIST FIPS 203, "Module-Lattice-Based Key-Encapsulation Mechanism Standard",
      August 2024. Table 2: ML-KEM Parameter Sets:
      - ML-KEM-512:
          pk size: 800 bytes
          sk size: 1632 bytes
          ct size: 768 bytes
          shared secret size: 32 bytes

    KAT Coverage:
      1. Fixed-vector Decapsulation (supported and deterministic):
         Tested against official NIST ACVP FIPS 203 reference vector:
         usnistgov/ACVP-Server gen-val/json-files/ML-KEM-encapDecap-FIPS203,
         Test Group 4 (function="decapsulation"), Test Case tcId=79.
      2. Fixed-seed Key Generation (supported via liboqs backend):
         Tested against official NIST ACVP FIPS 203 reference vector:
         usnistgov/ACVP-Server gen-val/json-files/ML-KEM-keyGen-FIPS203,
         Test Group 1, Test Case tcId=1.
      3. Parameter Length and Round-Trip Validation (S1 public API).
      4. Deterministic Encapsulation Limitation:
         Documented and verified that liboqs-python encap_secret draws random
         coins internally and lacks a seed injection parameter.
    """

    def test_fips203_ml_kem_512_parameter_lengths(self):
        """Verify that ML-KEM-512 keypair, ciphertext, and shared secret lengths
        conform exactly to NIST FIPS 203 Table 2 specifications.
        """
        assert KEM_ALGORITHM == "ML-KEM-512"

        # Generate keypair using S1 public API
        pk, sk = generate_keypair()

        # FIPS 203 Table 2 constraints
        EXPECTED_PK_LEN = PUBLIC_KEY_LENGTH
        EXPECTED_SK_LEN = SECRET_KEY_LENGTH
        EXPECTED_CT_LEN = CIPHERTEXT_LENGTH
        EXPECTED_SS_LEN = SHARED_SECRET_LENGTH

        assert EXPECTED_PK_LEN == 800
        assert EXPECTED_SK_LEN == 1632
        assert EXPECTED_CT_LEN == 768
        assert EXPECTED_SS_LEN == 32

        assert len(pk) == EXPECTED_PK_LEN, (
            f"FIPS 203 ML-KEM-512 public key length mismatch: "
            f"expected {EXPECTED_PK_LEN}, got {len(pk)}"
        )
        assert len(sk) == EXPECTED_SK_LEN, (
            f"FIPS 203 ML-KEM-512 private key length mismatch: "
            f"expected {EXPECTED_SK_LEN}, got {len(sk)}"
        )

        # Encapsulate using S1 public API
        ct, ss_sender = encapsulate(pk)
        assert len(ct) == EXPECTED_CT_LEN, (
            f"FIPS 203 ML-KEM-512 ciphertext length mismatch: "
            f"expected {EXPECTED_CT_LEN}, got {len(ct)}"
        )
        assert len(ss_sender) == EXPECTED_SS_LEN, (
            f"FIPS 203 ML-KEM-512 shared secret length mismatch: "
            f"expected {EXPECTED_SS_LEN}, got {len(ss_sender)}"
        )

        # Decapsulate using S1 public API
        ss_receiver = decapsulate(ct, sk)
        assert ss_receiver == ss_sender
        assert len(ss_receiver) == EXPECTED_SS_LEN

    def test_nist_acvp_ml_kem_512_decapsulation_reference_vector(self):
        """Test ML-KEM-512 decapsulation against official NIST ACVP FIPS 203 reference vector.

        Source:
          NIST ACVP-Server repository:
          gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json
          Test Group 4 (parameterSet="ML-KEM-512", function="decapsulation")
          Test Case tcId: 79 (valid decapsulation)
        """
        # 768-byte ciphertext (hex)
        ct_hex = (
            "7d1c241dd7cd46173a7fba75342b1c7bb95f781e24151cf85652b40a5a841f6e"
            "7dc8f6c39cdbc371a4bb9fea687d8b05627c81692740a32e6642c490cbdb7065"
            "6e8238db0c4b81e12e42daf25317d53519a9830a7fe6b70a28821dcfb345dc6f"
            "9483c48f6f4a91c2b4d0f1b595f2aa07172678a28dade034f0474ba9e955e276"
            "04701e427780d0125508d8e3de37f615cf9d4791777a6da9a2a85f6de6e08640"
            "c2072668a73ecefc0803d884cbdc622dec2f847318306a96f6a34239388228ce"
            "bce0613c3ad78ef0cbd983edad4e040c0a41fc69a8a10807aa491b4ad99bd390"
            "2fb1653b12e5f03cacfd1e46e7954b50f61f583f4ec786bef876a10cd8a22915"
            "e9feea43ea42bf86f6358c164946da3e09472dd6729b361140bf81485971b8e3"
            "9ba3223746b8da94fabb4517df5aff18971c7d2cee103513bb1ab066ca6b54bd"
            "a758ce0a01c5ed04524f8aa4a1575f03b8161907cf25a0b5fa53fcff31972cae"
            "6f5ec3a576dd56a4be0c91ad6defedad29fb8cdb8999edb8742741a067baad1a"
            "a08f45dbf68156b0bbdacb7d2d4bd1314441c1605a1bdf2efec19be95a874308"
            "6851fe8d714b9a1f7aba878dac90a9971042f53e8850e7acbdfa3bd72081ce68"
            "57be32cc5fb8fce7e7f5c3539acb96d58e3e7b97e8889e46af6efcac20f8b1bc"
            "210907903ad3eb26b014f3794253f4125c9137c7767d4b14d249c6e9b43e3501"
            "01e72692882d2fd15ad83373846072f6ee63aa8d571e4bd621c588d26d21f95d"
            "892fb81d2202d5b2eaee9cd44f35a0b2c812ef00ae14a86c4616a10930b4e05f"
            "17764521d70a2293611aed292ded26f9cda39645bf684a5e6c6dea572a0a4557"
            "81922ba132cf2dd61a1fbefc3e847487f4ce54d5c7395f563444097ba69a79ee"
            "a6b457f95dbb6a54d343c94fb43dec269387654abff982c5dcaa4d2c637f4952"
            "4c6b442d0f2d5eab478e502043e561294528f8fb23eb33e9fa0150bb36f649a5"
            "e827ac841524542f03d4c29dbe4d4ef8f60cbc814f5fa4a4380e99d032c06c44"
            "657a1f8f465b5317e2cd7122f402608ad83146941c4222d932e4607c05eca844"
        )
        # 1632-byte decapsulation key (hex)
        dk_hex = (
            "63c6380f9c31867c543fd82a4bf22cc01a654bca1656b83660402e8c1608196c"
            "4984762679487cae85611e2184a3169333f2a05b23a1037b4ec5da1c0a90212b"
            "8a9a3c1ab0fd1a7effe2a75b857c9fc2a50b28648c07cf2466786bd3718a7c49"
            "d4d8c6d89a7aac04156a380bfc773a71ac03af1327d7360f776a6c16f28e3649"
            "04912931c146000ee49a2293876d07a4d2c8bf84cc540bbc9bdd64b3d75880ca"
            "5317f5b54828026cfeaa0957d520cdf877d937bfffb81787ea8d77c843cb6ca1"
            "67b571c3a7bb34948ee92a8e5586644ec68032d30eff894f3dd6a2301aaafaac"
            "b7f3230e69fa028f1958c6f49fbbcc81907b47e8962376542af14203b59547f2"
            "b4276034b17643c7de3715d15a59b42022e372824e92b4abe3a61364a9941c21"
            "d72b9cf12c971f41808f80167d50a9de92c0c611966177a86b0b528dc674217c"
            "bb15233411bb1b82f87e9c4678b56456591a0c162b15e24a90c39668e549337d"
            "d17a2b41c523f5643c32410e9527a7845066465581f97541062534421a130c18"
            "5702710119acb55125dd6777c05840969438d6719c88671ebc755cf6719154c8"
            "705a272384237e5de312f7b8ccce1799290a831e9832eef3982bcc84f71a7a65"
            "669c019656e8706d44f888153705c727c71bb36176e0b028da9016e9114a686a"
            "2268cea664bb109b89806a55caa13b8b8084be602f7e8227b3820087f2b45918"
            "b21845320ea12c1cd30ce8324fd79420374cc56b22ce9e8827e5f893562193df"
            "d475496b7bc8d1644107870d34bb80491436aabf3eb327fe89adbdd85b37ec39"
            "ee3c2e6028c41acb6cae18c387e9b981f71205d077eb389f8b5686a1e2225b10"
            "62ce487d1e7008f243a94d9b90c0b8cac209516b375b8c911718f98efe4465e6"
            "db93bf557d58f9c6c290ccc7d161e6436f2805af5a119a00c4cde3733bfde901"
            "4284566a2b180dd7ceaed873f051108b74b1658596f82442d06563d4a7996de5"
            "304ffbb5ebd64342a0c0d7431401c1062d7a0e9fdb5086b3ad2b629f47a78aaa"
            "31546f7a5e8fc831cdf2b2bd854c60f65d8139696740ac24a72d6b196f1073a9"
            "eb63a556f134494a5066c99a96e5a70bb1b677539459e0bc28598738d65bbe6c"
            "5de340b37f5a5033d24a33b3c7017c8e52654a3619cd742a2775829b453cc554"
            "0235fcc9bf7f0b71e4f89fcc871376228efcf84030b92c0424c164c3b2c90436"
            "0623506270c1f6427497456657e74778e84ddda22a00460ae26862647a201f37"
            "6c4d218d636c2bfe9c40cc0c62ba25a406cbc7c752032a41be9ba67efc7c58b6"
            "d56c19ccc67624a7bf7a778ad11d74a38ca54b05aca608106c3ad92c627caa9d"
            "a4ca625d8b8a3ee6c7c8426172c9b4f79c9aabe924d8244a265573d81bc5454c"
            "2a3f127a30547b9d3c3f702051db6c9b219b73ba7923f5ca6cc57628950bced9"
            "32b6dfaa36c72677eb52114a4b87d9ec78e484b27cc87a7f15303a7c97d2223c"
            "54809de9f22c9eb6a43d559661816697104356694e969a729bc377f0dac45faa"
            "818d952655500c155284ee79a66cc063a10ab72ec9b724c13cb44b571a2aaf2c"
            "e2bae8bb0392e171eb5a1b98351c8f741bfa8401f0e95a6f536ee7147d6b9a89"
            "df662a65ec554c10c8f36a2b4291a0a1a68e5d423ad025098b60cabdfa34e40c"
            "4337e09b2a698d813a7609c55e8da651e3ab122fbbce44400caf009b20878466"
            "769939a46fb0646f876624599322a8d6b01c374437dbbb21445109330fb8e660"
            "e252148b29292ab072636575081185319a3c2f45712c70117657615100461fa3"
            "24ada763bed7bbc76a8fdddb411ab67f0fc7387669773b923d552a9781a7355b"
            "45bcb5fb479a750d427665beb08cff8ba7204607dfc258bf73ad1f4568c5e049"
            "ed39a68d7b3918b1983c007aeef0303a504ebbe52854dc68bf4a8f0dc28d6f2b"
            "29afdcb74dc1bae979671e21a127c9192ba180aa014d6512a74fd4a9519c8afa"
            "6b3cd723bc4df6cbf0eb8eec5272fcaa3bb3e880f28ab496b380b7a16af68853"
            "0030c75b6a26a50a9eef344fc61ca9b4e57e17dc93fb28c0acec1c84d6aa63d4"
            "560a3240be1837fa63bc47e9179a510a73e6a5f8a22e4bd540b065a061f182af"
            "c0854ff0388140c40af313528712e7b05724a6b03a97b3bcea52ddd0158de2cf"
            "2a0e15d72091383383a767ad7f2e0f4590cfa2aca12d93989f9a7f7967d56ab1"
            "ce10ba02467573d1cb3b7a140a42dc9e993b80a940a94554050997fd64999f8b"
            "5dbbc3bee3e00ae94f0441b44e8951d7e7078816d92a1438482f5de32f4f8145"
        )
        # Expected 32-byte shared secret (hex)
        expected_k_hex = "ea8067e693b368f1e0800deb84dcf2e7304db4ea439e05ddac64aa2358376873"

        ct = bytes.fromhex(ct_hex)
        dk = bytes.fromhex(dk_hex)
        expected_k = bytes.fromhex(expected_k_hex)

        # Execute decapsulation using S1 public API
        shared_secret = decapsulate(ct, dk)

        assert shared_secret == expected_k, (
            f"NIST ACVP ML-KEM-512 decapsulation vector tcId=79 failure:\n"
            f"Expected: {expected_k_hex}\n"
            f"Got:      {shared_secret.hex()}"
        )

    def test_nist_acvp_ml_kem_512_deterministic_keygen_reference_vector(self):
        """Test ML-KEM-512 deterministic key generation against official NIST ACVP reference vector.

        Source:
          NIST ACVP-Server repository:
          gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json
          Test Group 1 (parameterSet="ML-KEM-512")
          Test Case tcId: 1
        """
        d_hex = "47b893474672ba92e4b12ee44fb32953af8e8503b5fb471d1614fb8a021a660a"
        z_hex = "1f8cb39e9e30bc458a0dc5408884b1187fb217018df760fa57317703b844a0a9"
        expected_ek_prefix = "28266a088b3482439bca01afb7ca5c6136a979b5159985a9484b36b679a5f7b9"
        expected_dk_prefix = "89c31d05611aaab258f78bc2de0a80d5914bf80c376a990d33cb97f4f2077ce1"

        d = bytes.fromhex(d_hex)
        z = bytes.fromhex(z_hex)
        seed = d + z
        assert len(seed) == 64

        with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
            pk = kem.generate_keypair_seed(seed)
            sk = kem.export_secret_key()

            assert len(pk) == PUBLIC_KEY_LENGTH == 800
            assert len(sk) == SECRET_KEY_LENGTH == 1632

            assert pk.hex().startswith(expected_ek_prefix), (
                f"NIST ACVP KeyGen public key mismatch:\n"
                f"Expected prefix: {expected_ek_prefix}\n"
                f"Got prefix:      {pk.hex()[:64]}"
            )
            assert sk.hex().startswith(expected_dk_prefix), (
                f"NIST ACVP KeyGen secret key mismatch:\n"
                f"Expected prefix: {expected_dk_prefix}\n"
                f"Got prefix:      {sk.hex()[:64]}"
            )

    def test_ml_kem_512_api_lacks_deterministic_encap_support(self):
        """Verify and document the limitation that liboqs-python KeyEncapsulation
        does not support deterministic encapsulation inputs.
        """
        with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
            # encap_secret signature takes only public_key
            import inspect
            sig = inspect.signature(kem.encap_secret)
            params = list(sig.parameters.keys())
            assert params == ["public_key"], (
                f"Unexpected liboqs-python encap_secret signature: {params}. "
                "Deterministic random coin injection for ACVP KAT is not supported."
            )


# =============================================================================
# 5. ML-DSA-65 — NIST FIPS 204 KAT & Parameter Verification
# =============================================================================

class TestMLDSA65KAT:
    """ML-DSA-65 Known Answer Tests and FIPS 204 parameter verification.

    Standards Reference:
      NIST FIPS 204, "Module-Lattice-Based Digital Signature Standard",
      August 2024. Table 1 & Table 2: ML-DSA Parameter Sets:
      - ML-DSA-65:
          pk size: 1952 bytes
          sk size: 4032 bytes
          signature size: 3309 bytes

    KAT Coverage:
      1. Fixed-vector Signature Verification (supported and deterministic):
         Tested against official Project Wycheproof / NIST FIPS 204 reference vector:
         C2SP/wycheproof testvectors_v1/mldsa_65_verify_test.json,
         Test Case tcId=1 (baseline valid signature).
      2. Tampered Message & Tampered Signature Rejection:
         Verifies strict verification failure against reference vector.
      3. Parameter Length & Domain-Separated Policy Verification (S1 public API).
      4. Deterministic Signing Limitation:
         Documented and verified that liboqs-python Signature operates in randomized
         mode without deterministic seed/random coin injection.
    """

    def test_fips204_ml_dsa_65_parameter_lengths(self):
        """Verify that ML-DSA-65 keypair and signature lengths conform exactly
        to NIST FIPS 204 Table 1 & Table 2 specifications.
        """
        assert DEFAULT_SIG_ALG == "ML-DSA-65"

        EXPECTED_PK_LEN = 1952
        EXPECTED_SK_LEN = 4032
        EXPECTED_SIG_LEN = 3309

        with oqs.Signature(DEFAULT_SIG_ALG) as signer:
            pk = signer.generate_keypair()
            sk = signer.export_secret_key()
            assert len(pk) == EXPECTED_PK_LEN, (
                f"FIPS 204 ML-DSA-65 public key length mismatch: "
                f"expected {EXPECTED_PK_LEN}, got {len(pk)}"
            )
            assert len(sk) == EXPECTED_SK_LEN, (
                f"FIPS 204 ML-DSA-65 secret key length mismatch: "
                f"expected {EXPECTED_SK_LEN}, got {len(sk)}"
            )

            # Test policy signing via S1 wrapper
            raw_policy = {
                "flow_id": "FLOW-KAT-01",
                "sensitivity": "HIGH",
                "minimum_mode": "PQC",
                "policy_version": 1,
                "authority_id": "AUTH-KAT-01",
            }
            _, signature = sign_policy(raw_policy, sk)
            assert len(signature) == EXPECTED_SIG_LEN, (
                f"FIPS 204 ML-DSA-65 signature length mismatch: "
                f"expected {EXPECTED_SIG_LEN}, got {len(signature)}"
            )

            # Verify deterministic verification property via S1 verify_policy
            envelope = SignedPolicyEnvelope(
                policy=raw_policy,
                sig_alg=DEFAULT_SIG_ALG,
                signature=signature,
            )
            result = verify_policy(
                envelope,
                authority_registry={"AUTH-KAT-01": pk},
            )
            assert result.is_valid is True

    def test_nist_fips204_ml_dsa_65_signature_verification_reference_vector(self):
        """Test ML-DSA-65 signature verification against official NIST FIPS 204 reference vector.

        Source:
          Project Wycheproof (C2SP / NIST FIPS 204 validation dataset):
          testvectors_v1/mldsa_65_verify_test.json
          Test Case tcId: 1 (comment: "baseline", result: "valid")
        """
        # 11-byte message: "Hello world" (hex: 48656c6c6f20776f726c64)
        message = bytes.fromhex("48656c6c6f20776f726c64")

        # 1952-byte public key prefix/suffix check (hex)
        pk_hex = (
            "f5408337d0fee65c28851226a5fa81b58464632c78e2a9bef70d330f2e3a5f74"
            "d9cf676aedd1067c91a5dd5d4edc46f868a93ffec9f44e254e44f682a153aead"
            "f228e8db7c5fcfed30cc3408e261ab896876bee56660d2a7c1d7eac20c575425"
            "5206a178f7156295065ce7876f90c48f44bc37f3a00e32eefd3a4bb1e298fe28"
            "3d106eaef92a33a594253a2a0790976a1d04636f8672d28c06c852ea8bb43b84"
            "bff512996e7616963d5b9a2906466a152c7ea9be178be35405683b44367af85d"
            "2daad87630c1e21ba5490154f0141780f5ed0407cb0b975dd56d5930f9b26413"
            "b843b83f3693304b0038bd3e4bb398868060ea18c9c67099376470a50deb052e"
            "4056743fbcdf0341b192663bd1c21ba3b3d5666e0d0e29c4e1ed0759ab0bd9d1"
            "d355011b94e0ff0c049b03ddb7138640667144fcacd7265f55a07e5387f1abd3"
            "0c037cf14d436aa855f827049215440d8007f61460500d943f57ffb6bfee6fed"
            "d2fcec52882d7d8da1aab29e892c8beac3df3234b4a7d2eca3a45c6623c52bbd"
            "d07c1c94314b706988a52029f8f8b06e874b741d72926652c78c6ace2cfd8864"
            "eadb2e4b39cafe6e03e4edbafa2747db9bc42f92af8b031e3e380846b1bfd15a"
            "de88c285d6a6fffe91eafc8b17de6cbc68575f323cc09fc20e49e8efd76f9568"
            "bec486b78df4245428d8d0d5f53873e11de65fda4c770b521a8c67f5c51d48cc"
            "26358954514447881fd9a42e5891dac7e1db5249d7861b322111e5fb929bee9f"
            "f5e9d5a2667ba93e63fc03040d2e82648f89e89dec1d1d2dfb9efeceb7940f7d"
            "cbebeb5a239cc1c54d8f7d52cba220d0634e15df46a58280bc5a48840bd39274"
            "cfde150f9ad9a40f6398d715350925f0e0501944409f32331a362bdaaafb3d8c"
            "e71c964332d6afb7e684f99951246d88081c86744ae68133f22c53a4b5ae258f"
            "230a98491d2d43a79a6d0f4d54a3b62013965ac7c82d0507125a38a0277f81cb"
            "c1d46cef2a131c6f51b88ec0baae0c82a6a0e72831cb06f9116cff5111d597e0"
            "1057d32805a008f52c9aec3311139bfb35982789ff83bdd0c31e9f1080e8ed8e"
            "b99fde66bafb29e3357389fe3785b60c78e229ef073e1b65e34d848bd4d8a4f2"
            "51551e2d38d2546afbc205d3c6dab34d2b962b1afb44f1d22fc10c6744fcd6b6"
            "36afd3cb414b16c2e0d708fe9f51ff19120bde693b028b6d1e6dbe37b4b8b3bc"
            "7c6f7a842701603869d3ded572500f085502efc8d3cc62b30e5cdbcb5e86d9c0"
            "d42973bf755df539cc0aea58f9148386db67bd2bf70cd12ccd96d5c66fb27141"
            "6b772465228dc44b079178f9b766370b66a79b871faca246ca6f8f63be9f0668"
            "297ac446cad5cf4a83318b1b00ecbd283f0eecee60a9a37a27abdbdbe382e307"
            "970002837dfc0bd3934ebd008918fd4bd383c02c9d37f694996e989a49075767"
            "ebc4a2981ef5275455e026cb0bd70946cdd1fadaf251381d324f9efbb860d1b2"
            "80c29685bab97d010676273b45cca12ac3966aae342c84e2357eccf252577743"
            "b8787967b40b07ef2d3d9e6c1a3bcb059cba0fdb7f0d4f815c242b8e14acd337"
            "5e608e9230ba3cf8718f43882a3e1e661a2bbe81830d34741f33473e263b3790"
            "abe67acf29f5df44865b2ffbc96975fd62738a64112deda5a2534fb0a23b3b30"
            "24df986391badf9041c593c313a7ca1e1fcffcb65b07b9a99337b4a4acf616cb"
            "e1553eb9541f38aa6247342905995233a28172ca13396b2a9662970120f82b92"
            "a213f43de7a232ccca3268265c9ce042d50915430a6c455f32277da42f9962fb"
            "9163b623231ebc080fa7b8e9f9021fcf85b98f9c483e4d2226b9326a5bcb2e74"
            "49ef029ae142d3a0f0c28bd4f7e9c51a12e1336f24dfacbc3f808a8f7dd68302"
            "7bc948763b808fb0037394b8b41bc9b2ec7887e67584e03d11b15ca203b2bcb4"
            "3f8881638c4e4eee7f846d09c7f89b7739df22b2c3acc235032ba8f7ae27b5b9"
            "d25733143e80a4cdde6770719c1e66ec2ce683612233e88fafff84c0745a98aa"
            "1254c8219c6c556348c2b5d1beeb61532d6bf7bde153271dc647460beb65fe00"
            "55b33fd6480dcbb9d7d471952cfa5be260c39721a8c5c89b9e966ae2dc903645"
            "1ec9f2c49433b2225e13f23e20c2bfba81a7b3a555883449238f7d48213e9f10"
            "ce19e76f1bdcfc73ee5524bd7d8be0a4b46784e238233c04fb99383ec7726f97"
            "17e1179dd14fba9ad6c2ebd1699f0ab0e57e6cad23875b029e89cfda06f51266"
            "ecd2eed4edafb51e82f2a506d57ba74da611774ca5fa2fff4a976519de425885"
            "e7d09219cf815b1767d4fc5a72c18918991a285086a6a766614a4d245387da50"
            "f28dd778fb33ab88c0918feba3768c55bb1f07aec33cfeed33d6faa4d34fd722"
            "7b365533c1e67dbc89f0b20195cf1cbd480d333ade1c9bb28308085b72ced430"
            "268c1492a27050c43668adc9cf8b8509447cfcd3c8f8d8eb554f704101786aa9"
            "ebca86991d250776a37a1f56fbf7d08e591f978da49c3870625879f70e2418ae"
            "c5cba32fa8c346fa9038baebc35ad0068a4d03537aee14c2e71570a87490377f"
            "a8dd66f995aa044a522f0c7025a7ab2dd5ad30a64268dc112b7f9fa156df64d6"
            "31f55f1d6edc55cec570a9c7372e29e02c8d4867bae249431dcf6ed2794a0183"
            "f0f7501201feca4a81d334c642fc8d38e9a90fa77429665e09e214797dfa455f"
            "f47c4f219d3a2cb0176bc2236455123c1c5da714ad29d580fb194f87173a18dc"
        )
        # 3309-byte signature (hex)
        sig_hex = (
            "69da5aec6d5f58fbf29439c520bd68b966e3dd2ca633b68351c2862344713a1e"
            "9c086a44f9a870a3ccc14de62d6c12b278c354d7197c4d6d7f83d1422b29b250"
            "f5ee3fec118311d905e5db2b4b8b23b8d542202d6652f6dc3f9d7ed51f246308"
            "2d3f145cfd0fa7ac548a47e91c1ccb1a55b215e90ab355bfc6d67154287b1dfa"
            "e0fb530264dbb841a7684b396e5ca0459d795216416a9d232bc89b32e0f9461f"
            "53107c78e66c8e876554e8ddd501867b55dcfc1fb33f102e03373cdd192640f1"
            "027a08ce277b468f6ed0fe80a9d6cd2d6b2f7a3738c8325d95b0ccc6e7b9fb00"
            "0c923b92298e0867d4a9f6dd5513e8001033c633bb1641ee66349487224dd433"
            "86c7fcc29916332066a868100d46e2c5b8354c28f087a024cba27694afc4c166"
            "5e0d72b37686919ad55052cc63a144febe4e2a0c9ae416e064e289f9f69cbb88"
            "3665d1130826b7b74e30c94a2b98b67b471663e3d66326db3b43bebf958e8665"
            "b68eda90e8c5d9494b0c7c9ec48800910dd6d906b1fcd47a0aac462ac87b126d"
            "21b5ba150df61f752257ddf5a063b4a5b150371d625535e3b2874b9fe548960f"
            "f67931cd6c12496e8213e2ace6fff48e6bdc60310e49389f62579db26b92ad73"
            "e9d3f23942cab51784f48b3660b6450caecbb0df2aa4c8e56577f5ea450d2f7f"
            "51aacc0b304a62250bf2cae7b99dcd955b6596625d06da1c67f730b706fdba63"
            "0f00fd891830d251484640b7258ab364d6fd9986878fffa69b7c44b92e43143a"
            "ffae8b098e1d27716850f37553bf266cdfb561abbcdbfeb80752b364434e64b8"
            "0429b54cc88693ce03dc0fa147f0741b215f0728499bdc25140aafc976ac99e9"
            "10ba8a8a50d21b7bddaa28626b3b90a93fd44077068357c81d36e735eda43629"
            "30adead4951a0baa104f384fc70e842a9f329e1868b07b455e9cc3fecd54805c"
            "9052e70f88c3b92fe0fc6a4d7dda18cf5694e5398860e439a1e19d5a66f2fbc0"
            "aacdd1a498711bb16054796c015a715395ef6174e37b04eda589b673c4d5dda7"
            "37817fb52f392caf7a72d7a3e84b2180cb5b75bc8af065bdc05c3e4040435a1b"
            "160081352ac43e09cbf2ead6e09c2b0be0e37894888fe2812f68806f957c13fc"
            "e6ff167bcee21d4f412ec95a4847f3db7bf441223a4d4ca9ed69adb4de8a4b5b"
            "01c775f2721226e6c59ff26fc38e1bb78a384b30e7b55f082e264d8f25e31518"
            "619ddd6b6a9faf8aa6cdb5eab75ed59a33825d5ef8b93bde5d120ada773fcc08"
            "52b918f4f03e2d2a543b15363adb823eb1f6c533b98d940411e1f5c1cf521f9f"
            "63d5454697608326625fffe01bf87f44187dad631df2898effd2c291d98222e5"
            "64abe3b042b75e90c9c54667842fa8ebb68a1244bf8e0c3ae3ee5f97d5ddeefd"
            "986c4bd3f99d877c2cc2381a89abdc61713d38cee58bf69805a485c288d21b15"
            "843147066b4a74c69dc25de878e21d35fdfe6746feb4c166606bf3219e42cf63"
            "581e7e6bd6570f40f8fae590cedf5106fe57037ccb2324b74fca6500f6ed3d07"
            "36cdcc67d04f8fa9e80054a5bd7c8459fc1abb1c4c78677d7f6b325af94a0e5c"
            "9c7db0a748e12c5265e8724947d9b5c4bab1a8b6faec827cc41ec115ef3c2d73"
            "48cddabddfbc8436f3b41765e13f3762b3b45ed23156f085831e726a55d4b838"
            "48b3d1d3352aab9edcc0ac2388f2383f6301ad813b917ee3f23734e057832ae4"
            "cf65e668c9ddd0bdd0f9d8b6693254649668aa91a1fa5eb7c59859bb6ddd36c2"
            "5f4a2223f5d688b480d0388fa307ea69298f9bf7737f6b3dbfda87b331affd75"
            "cd8d88f0460e98ebc2890b217bd6d11000a3a088cd837f4f8859a43f76afaaab"
            "05a0c3007a149d4d6b9155cadc2c9b55003efdec5012b6272b87183694c505f0"
            "446ede55f35b8ab201f9eda974ff840eccb0f004fa3acf753acd0613f66e2a6a"
            "c82e322199d37b4af83cbb3d98371c31be79bb42331e819644cbad2ce27a04e4"
            "c517998692cd8331552892e199a01a6922bda4d38ac4c01f708809e529c3216e"
            "aab399ef25b350ea213ba47126f278140e17391ca7139bd13c56f415e6b74aed"
            "8dbfbf38c95dc6db366fd72aa863a27fa1ebf198716400b978a3709e35039731"
            "930406588ebdffd35fa230a9b75fce41d7acd214ca4f0029896c137495eade0c"
            "f4d10fe621c73f01061acb077de72177ff5dbc6f0c5bec681aa34668ca4fcdd7"
            "27525068b0b0e9072971b84ef6ce11d5c3c6024da40966703dcc2b33ae04f677"
            "677635a55db508f34f1403cdbe37960c8577dac3d848b29f3b5c5c6c56fb74f3"
            "4c8f4634c04b8cce9b218f1760ca00e6de87efd14087c633469c892bf3e31944"
            "3336733bb60cfb44941bfa25229aa24384d812db90fe74e0f93fda005eea8740"
            "0736cabc036f71421b6657b1674d4a8f76cbbf3a8b1c0af82f72973927752257"
            "c532db439d96762ad64f102551a9d03f9ce3d8cc850c393c128bf8054bb55bb9"
            "2ea31ec0706f083a9cf90424c617f8ad2a21225d1913c30e8f47a6b7131304d5"
            "36a85596ebfd987b64b6bf3c51638d6c839214b53c3c10aa52bd9c6eb77fcf80"
            "b5e3b724dec1381d0e02207a6adc73ff53d9d1ffcee1c4a28fa5445ce518eee9"
            "37074ff7a402f5bbcb362ff090415f9dbd93b62ee56dc8c50e4d2e34c6c62165"
            "0c0dffe311484e95d68de77170c909c815828946aeeec7ede56bcf433e22fc63"
            "a33f764ced1f9242f3d26dc7558686e471f30fbe9304d3d56af8b23e72a40889"
            "70b24b2f7e968c1d0392eeeb0b0f0ac8c176547a5383d948ed15484b79e21314"
            "a1f28ed624f61e5aaecf2269e5b027e1910ffddede52fad4e8da224e8a10b079"
            "548fa7cd44172f4991adfd7623d13e5a19c812824bcf990c07c9721ded9093be"
            "6ce7bc7da3ac8c932133a64396b822be92b088844991596df893625a4ef24543"
            "bf75a10d7d17ff70350ef62ce3a7758aebbf9b3977b08becb9ea28376082f607"
            "965f2cded28bbdb39dab7e00833b0488370d221742b66e27d9ee2d9dd07f401b"
            "c22a62c8a9d8d3a290c63804991496aafa47a32578f583cfb53d0c2199055973"
            "440d7535e0da6cb2957f4e04002ecea68f9c3ff76cade27ed15fd7835989d0ab"
            "b197fe32f68636139a42710644bb25860ff33f539200e3ccb8a7738422ca0fa0"
            "c744b4c19d15c5d4a3cb082e20a78e20b5a4965b043595cbcacad500b5adbb6c"
            "d597e6a4b9c5ea6a1f2e653b5474da277f1818048094ac9e0e1e0b20068d1c1c"
            "e5a114a4db7195057a6ce4d221c336fdc29190fee8ff855cae8b7f7c02eec21f"
            "972c827066d9c6dcc4a4179bc44ea9b88abe5124bf78b071e09e9af43f739a6e"
            "1030091fc091e73edc447f25c68bf84b8df7aa8f091ab42662b93e02c27003af"
            "c7b0ca69efcfa60bd53d4d78ceb7c4d2c8fd5ed7e8b35024de849e06400ad145"
            "fdb28348d22b317ccec704c401f88db1af2a5348223f5cefd914e404c9d73805"
            "d0de77211881486f1bf4aadacadd3ae2588f0db7b5e6957fed50a374f541cfe5"
            "e4e923c82ec47e5b3d2c70ad6760c79cd5080b490bdc75f9ef5e1d17f0978b1e"
            "8770775f902b9463e6980e1683b2454751ba2dad4a2e6460924bd60ff49b0323"
            "0cb11fcd04a0388e60874c35d3f6cfc4dd487665e1b16578751eaea89e126bf5"
            "8044596e3188c7a9631017be1f2dcd7d612331832ff8755460dc496aa99a61ea"
            "053c78e72607a18213ff9ef4bb880903b91e9a43e0b1f0ed1511b2eca2f4253f"
            "cfbd7d0faebf3680fbf0a45df231544882c9c46505c726d56905d02fd046c165"
            "2d8fd06d15286a1a8f8b69fbd825ca421fd80f5e9ba1a23f924937ad049adeec"
            "60c78fea1adf9b1ef7e8ac4d1ded18f1a801b0bda8fe9a88098825ff3eef5c1f"
            "c68cbea143310b39543293f3f5fbcf4773b02054c0bc79f00554947c7604b363"
            "89c0c45f597a88f3713456b4cfd83b30cb6520b624aa09c812066a8cd542dc67"
            "e19e4c92b562b4e0f6799fe57d9d4f4f3e0b6fabff4b1fc190bf1e78775ebcbe"
            "3655d370ca6c08f48decf6153a4989eeab6921f8475f85197f51d651e5639942"
            "57df57977e5f219b4879751de57ab0374b407a21adb4ba520bb35e7b7508675b"
            "f49f4e432190451423cbd529fc79b22baae9cb1d8660c3a49c456ac03bc06c0e"
            "f3b02f7d8acd40919315206fb38e715139c9bd6f89a58634fe683df03f5bda71"
            "9764f6c38131bc5ba1c53244472ef73834ade04b86ca08dd753141ac0a9a230e"
            "246735060a044018bc9b75d50134b20e6219c13f8325b5a0201e9453f6f012fe"
            "72e829ee1c637fe30037a9212a31c6e713726a6cd4cf2dd66ffdba77f1e2800e"
            "717940f231d04aa2e4e88dea084754947d848c0271856bfe659922408449858a"
            "81fa6583f062d96898d18ec53664f0067eb9b9c40ad2579ba9802abd8d1bf287"
            "e49d94ae397e784db14b5f7010ee4fc42e6e3c8ba80370afc188fcecaf466ea8"
            "30d7b16362e5c9329980b981decc7174f3ff70a35d8a180ee12ed0cbffd4e8d1"
            "4eb503387e4959f702d4293109e922eb561371f9ab21475821f8555d92f0aa1c"
            "3d841a6f1eabd4e663993636c754ce2b3c3f6a6b6d0b161e777b8296d7dce7fd"
            "162970496494d4f60716244a5a7fb7cee40e1d565e6566697e8f930000000000"
            "0000000000000005101318212b"
        )

        pk = bytes.fromhex(pk_hex)
        sig = bytes.fromhex(sig_hex)

        assert len(pk) == 1952
        assert len(sig) == 3309

        with oqs.Signature(DEFAULT_SIG_ALG) as verifier:
            # 1. Official reference vector verification must succeed
            assert verifier.verify(message, sig, pk) is True, (
                "NIST FIPS 204 ML-DSA-65 reference vector verification failed"
            )

            # 2. Tampered message must be rejected
            tampered_message = message + b"!"
            assert verifier.verify(tampered_message, sig, pk) is False, (
                "ML-DSA-65 verification accepted tampered message"
            )

            # 3. Tampered signature byte must be rejected
            tampered_sig = bytearray(sig)
            tampered_sig[0] ^= 0xFF
            assert verifier.verify(message, bytes(tampered_sig), pk) is False, (
                "ML-DSA-65 verification accepted tampered signature"
            )

    def test_ml_dsa_65_api_lacks_deterministic_sign_support(self):
        """Verify and document the limitation that liboqs-python Signature
        does not support deterministic signing inputs or seed injection.
        """
        with oqs.Signature(DEFAULT_SIG_ALG) as sig_inst:
            import inspect
            sig = inspect.signature(sig_inst.sign)
            params = list(sig.parameters.keys())
            assert params == ["message"], (
                f"Unexpected liboqs-python sign signature: {params}. "
                "Deterministic random coin/seed injection for ACVP KAT is not supported."
            )
            # Verify absence of keypair seeding
            assert not hasattr(sig_inst, "generate_keypair_seed"), (
                "Unexpectedly found generate_keypair_seed on Signature instance."
            )
