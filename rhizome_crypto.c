/*
Serval DNA - Rhizome cryptographic operations
Copyright (C) 2014 Serval Project Inc.
Copyright (C) 2010 Paul Gardner-Stephen
 
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.
 
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
 
You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include <stdlib.h>
#include <ctype.h>
#include <assert.h>

#include "crypto_sign_edwards25519sha512batch.h"
#include "nacl/src/crypto_sign_edwards25519sha512batch_ref/ge.h"
#include "serval.h"
#include "conf.h"
#include "str.h"
#include "rhizome.h"
#include "crypto.h"
#include "keyring.h"
#include "dataformats.h"

int rhizome_manifest_createid(rhizome_manifest *m)
{
  if (crypto_sign_edwards25519sha512batch_keypair(m->cryptoSignPublic.binary, m->cryptoSignSecret))
    return WHY("Failed to create keypair for manifest ID.");
  rhizome_manifest_set_id(m, &m->cryptoSignPublic); // will remove any existing BK field
  m->haveSecret = NEW_BUNDLE_ID;
  return 0;
}

struct signing_key {
  unsigned char Private[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES];
  rhizome_bid_t Public;
};

/* generate a keypair from a given secret key */
static void generate_keypair_from_secret(const rhizome_bk_t *bsk, struct signing_key *key)
{
  bcopy(bsk->binary, key->Private, sizeof bsk->binary); // first 32 bytes
  crypto_sign_compute_public_key(key->Private, key->Public.binary);
  // The last 32 bytes of the private key should be identical to the public key.  This is what
  // crypto_sign_edwards25519sha512batch_keypair() returns, and there is code that depends on it.
  // TODO: Refactor the Rhizome private/public keypair to eliminate this duplication.
  bcopy(key->Public.binary, key->Private + RHIZOME_BUNDLE_KEY_BYTES, sizeof key->Public.binary);
}

/* Generate a new empty manifest from the given keypair.
 */
static void rhizome_new_bundle_from_keypair(rhizome_manifest *m, const struct signing_key *key)
{
  rhizome_manifest_set_id(m, &key->Public); // zerofills m->cryptoSignSecret
  m->haveSecret = NEW_BUNDLE_ID;
  bcopy(key->Private, m->cryptoSignSecret, sizeof m->cryptoSignSecret);
  // Disabled for performance, these asserts should nevertheless always hold.
  //assert(cmp_rhizome_bid_t(&m->cryptoSignPublic, &key->Public) == 0);
  //assert(memcmp(m->cryptoSignPublic.binary, m->cryptoSignSecret + RHIZOME_BUNDLE_KEY_BYTES, sizeof m->cryptoSignPublic.binary) == 0);
}

/* Generate a bundle id deterministically from the given seed.
 * Then either fetch it from the database or initialise a new empty manifest */
int rhizome_get_bundle_from_seed(rhizome_manifest *m, const char *seed)
{
  union {
    unsigned char hash[crypto_hash_sha512_BYTES];
    rhizome_bk_t bsk;
  } u;
  crypto_hash_sha512(u.hash, (unsigned char *)seed, strlen(seed));
  // The first 256 bits (32 bytes) of the hash will be used as the private key of the BID.
  return rhizome_get_bundle_from_secret(m, &u.bsk);
}

/* Generate a bundle id deterministically from the given bundle secret key.
 * Then either fetch it from the database or initialise a new empty manifest
 */
int rhizome_get_bundle_from_secret(rhizome_manifest *m, const rhizome_bk_t *bsk)
{
  struct signing_key key;
  generate_keypair_from_secret(bsk, &key);
  switch (rhizome_retrieve_manifest(&key.Public, m)) {
    case RHIZOME_BUNDLE_STATUS_NEW: 
      rhizome_new_bundle_from_keypair(m, &key);
      break;
    case RHIZOME_BUNDLE_STATUS_SAME:
      m->haveSecret = EXISTING_BUNDLE_ID;
      bcopy(key.Private, m->cryptoSignSecret, sizeof m->cryptoSignSecret);
      break;
    default:
      return -1;
  }
  return 0;
}

/* Generate a bundle id deterministically from the given bundle secret key.
 * Then initialise a new empty manifest.
 */
void rhizome_new_bundle_from_secret(rhizome_manifest *m, const rhizome_bk_t *bsk)
{
  struct signing_key key;
  generate_keypair_from_secret(bsk, &key);
  rhizome_new_bundle_from_keypair(m, &key);
}

/* Given a Rhizome Secret (RS) and bundle ID (BID), XOR a bundle key 'bkin' (private or public) with
 * RS##BID. This derives the first 32-bytes of the secret key.  The BID itself as
 * public key is also the last 32-bytes of the secret key.
 *
 * @author Andrew Bettison <andrew@servalproject.org>
 * @author Paul Gardner-Stephen <paul@servalproject.org>
 */
int rhizome_bk_xor_stream(
  const rhizome_bid_t *bidp,
  const unsigned char *rs,
  const size_t rs_len,
  unsigned char *xor_stream,
  int xor_stream_byte_count)
{
  IN();
  if (rs_len<1||rs_len>65536) RETURN(WHY("rs_len invalid"));
  if (xor_stream_byte_count<1||xor_stream_byte_count>crypto_hash_sha512_BYTES)
    RETURN(WHY("xor_stream_byte_count invalid"));

  int combined_len = rs_len + crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES;
  unsigned char buffer[combined_len];
  bcopy(&rs[0], &buffer[0], rs_len);
  bcopy(&bidp->binary[0], &buffer[rs_len], crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES);
  unsigned char hash[crypto_hash_sha512_BYTES];
  crypto_hash_sha512(hash,buffer,combined_len);
  bcopy(hash,xor_stream,xor_stream_byte_count);

  OUT();
  return 0;
}

/* CryptoSign Secret Keys in cupercop-20120525 onwards have the public key as the second half of the
 * secret key.  The public key is the BID, so this simplifies the BK<-->SECRET conversion processes.
 *
 * Returns 0 if the BK decodes correctly to the bundle secret, 1 if not.  Returns -1 if there is an
 * error.
 */
int rhizome_bk2secret(
  const rhizome_bid_t *bidp,
  const unsigned char *rs, const size_t rs_len,
  /* The BK need only be the length of the secret half of the secret key */
  const unsigned char bkin[RHIZOME_BUNDLE_KEY_BYTES],
  unsigned char secret[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES]
)
{
  IN();
  unsigned char xor_stream[RHIZOME_BUNDLE_KEY_BYTES];
  if (rhizome_bk_xor_stream(bidp, rs, rs_len, xor_stream, RHIZOME_BUNDLE_KEY_BYTES))
    RETURN(WHY("rhizome_bk_xor_stream() failed"));
  /* XOR and store secret part of secret key */
  unsigned i;
  for (i = 0; i != RHIZOME_BUNDLE_KEY_BYTES; ++i)
    secret[i] = bkin[i] ^ xor_stream[i];
  bzero(xor_stream, sizeof xor_stream);
  /* Copy BID as public-key part of secret key */
  bcopy(bidp->binary, secret + RHIZOME_BUNDLE_KEY_BYTES, sizeof bidp->binary);
  RETURN(rhizome_verify_bundle_privatekey(secret, bidp->binary) ? 0 : 1);
  OUT();
}

int rhizome_secret2bk(
  const rhizome_bid_t *bidp,
  const unsigned char *rs, const size_t rs_len,
  /* The BK need only be the length of the secret half of the secret key */
  unsigned char bkout[RHIZOME_BUNDLE_KEY_BYTES],
  const unsigned char secret[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES]
)
{
  IN();
  unsigned char xor_stream[RHIZOME_BUNDLE_KEY_BYTES];
  if (rhizome_bk_xor_stream(bidp,rs,rs_len,xor_stream,RHIZOME_BUNDLE_KEY_BYTES))
    RETURN(WHY("rhizome_bk_xor_stream() failed"));

  int i;

  /* XOR and store secret part of secret key */
  for(i = 0; i != RHIZOME_BUNDLE_KEY_BYTES; i++)
    bkout[i] = secret[i] ^ xor_stream[i];

  bzero(xor_stream, sizeof xor_stream);
  RETURN(0);
  OUT();
}


/* Given a SID, search the keyring for an identity with the same SID and return its Rhizome secret
 * if found.
 *
 * Returns FOUND_RHIZOME_SECRET if the author's rhizome secret is found; '*rs' is set to point to
 * the secret key in the keyring, and '*rs_len' is set to the key length.
 *
 * Returns IDENTITY_NOT_FOUND if the SID is not in the keyring.
 *
 * Returns IDENTITY_HAS_NO_RHIZOME_SECRET if the SID is in the keyring but has no Rhizome Secret.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
enum rhizome_secret_disposition find_rhizome_secret(const sid_t *authorSidp, size_t *rs_len, const unsigned char **rs)
{
  IN();
  keyring_iterator it;
  keyring_iterator_start(keyring, &it);
  if (!keyring_find_sid(&it, authorSidp)) {
    DEBUGF(rhizome, "identity sid=%s is not in keyring", alloca_tohex_sid_t(*authorSidp));
    RETURN(IDENTITY_NOT_FOUND);
  }
  keypair *kp=keyring_identity_keytype(it.identity, KEYTYPE_RHIZOME);
  if (!kp) {
    WARNF("Identity sid=%s has no Rhizome Secret", alloca_tohex_sid_t(*authorSidp));
    RETURN(IDENTITY_HAS_NO_RHIZOME_SECRET);
  }
  int rslen = kp->private_key_len;
  assert(rslen >= 16);
  assert(rslen <= 1024);
  if (rs_len)
    *rs_len = rslen;
  if (rs)
    *rs = kp->private_key;
  RETURN(FOUND_RHIZOME_SECRET);
}

/* Attempt to authenticate the authorship of the given bundle, and set the 'authorship' element
 * accordingly.  If the manifest has no BK field, then no authentication can be performed.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
void rhizome_authenticate_author(rhizome_manifest *m)
{
  IN();
  DEBUGF(rhizome, "authenticate author for bid=%s", m->has_id ? alloca_tohex_rhizome_bid_t(m->cryptoSignPublic) : "(none)");
  if (!m->has_bundle_key) {
    DEBUG(rhizome, "   no BK field");
    RETURNVOID;
  }
  switch (m->authorship) {
    case ANONYMOUS:
      DEBUGF(rhizome, "   manifest[%d] author unknown", m->manifest_record_number);
      rhizome_find_bundle_author_and_secret(m);
      RETURNVOID;
    case AUTHOR_NOT_CHECKED:
    case AUTHOR_LOCAL: {
	DEBUGF(rhizome, "   manifest[%d] authenticate author=%s", m->manifest_record_number, alloca_tohex_sid_t(m->author));
	size_t rs_len;
	const unsigned char *rs;
	enum rhizome_secret_disposition d = find_rhizome_secret(&m->author, &rs_len, &rs);
	switch (d) {
	  case FOUND_RHIZOME_SECRET:
	    DEBUGF(rhizome, "   author has Rhizome secret");
	    switch (rhizome_bk2secret(&m->cryptoSignPublic, rs, rs_len, m->bundle_key.binary, m->cryptoSignSecret)) {
	      case 0:
		DEBUGF(rhizome, "   is authentic");
		m->authorship = AUTHOR_AUTHENTIC;
		if (!m->haveSecret)
		  m->haveSecret = EXISTING_BUNDLE_ID;
		break;
	      case -1:
		DEBUGF(rhizome, "   error");
		m->authorship = AUTHENTICATION_ERROR;
		break;
	      default:
		DEBUGF(rhizome, "   author is impostor");
		m->authorship = AUTHOR_IMPOSTOR;
		break;
	    }
	    RETURNVOID;
	  case IDENTITY_NOT_FOUND:
	    DEBUGF(rhizome, "   author not found");
	    m->authorship = AUTHOR_UNKNOWN;
	    RETURNVOID;
	  case IDENTITY_HAS_NO_RHIZOME_SECRET:
	    DEBUGF(rhizome, "   author has no Rhizome secret");
	    m->authorship = AUTHENTICATION_ERROR;
	    RETURNVOID;
	}
	FATALF("find_rhizome_secret() returned unknown code %d", (int)d);
      }
      break;
    case AUTHENTICATION_ERROR:
    case AUTHOR_UNKNOWN:
    case AUTHOR_IMPOSTOR:
    case AUTHOR_AUTHENTIC:
      // work has already been done, don't repeat it
      RETURNVOID;
  }
  FATALF("m->authorship = %d", (int)m->authorship);
}

/* If the given bundle secret key corresponds to the bundle's ID (public key) then store it in the
 * manifest structure and mark the secret key as known.  Return 1 if the secret key was assigned,
 * 0 if not.
 *
 * This function should only be called on a manifest that already has a public key (ID) and does
 * not have a known secret key.
 * 
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_apply_bundle_secret(rhizome_manifest *m, const rhizome_bk_t *bsk)
{
  IN();
  DEBUGF(rhizome, "manifest[%d] bsk=%s", m->manifest_record_number, bsk ? alloca_tohex_rhizome_bk_t(*bsk) : "NULL");
  assert(m->haveSecret == SECRET_UNKNOWN);
  assert(is_all_matching(m->cryptoSignSecret, sizeof m->cryptoSignSecret, 0));
  assert(m->has_id);
  assert(bsk != NULL);
  assert(!rhizome_is_bk_none(bsk));
  if (rhizome_verify_bundle_privatekey(bsk->binary, m->cryptoSignPublic.binary)) {
    DEBUG(rhizome, "bundle secret verifies ok");
    bcopy(bsk->binary, m->cryptoSignSecret, sizeof bsk->binary);
    bcopy(m->cryptoSignPublic.binary, m->cryptoSignSecret + sizeof bsk->binary, sizeof m->cryptoSignPublic.binary);
    m->haveSecret = EXISTING_BUNDLE_ID;
    RETURN(1);
  }
  RETURN(0);
  OUT();
}

/* Return true if the bundle's BK field combined with the given Rhizome Secret produces the bundle's
 * secret key.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static int rhizome_secret_yields_bundle_secret(rhizome_manifest *m, const unsigned char *rs, size_t rs_len) {
  assert(m->has_bundle_key);
  if (rs_len < 16 || rs_len > 1024) {
    // should a bad key be fatal??
    WARNF("invalid Rhizome Secret: length=%zu", rs_len);
    return 0;
  }
  unsigned char *secretp = m->haveSecret ? alloca(sizeof m->cryptoSignSecret) : m->cryptoSignSecret;
  if (rhizome_bk2secret(&m->cryptoSignPublic, rs, rs_len, m->bundle_key.binary, secretp) == 0) {
    if (m->haveSecret && memcmp(secretp, m->cryptoSignSecret, sizeof m->cryptoSignSecret) != 0)
      FATALF("Bundle secret does not match derived secret");
    return 1; // success
  }
  return 0;
}

/* Discover if the given manifest was created (signed) by any unlocked identity currently in the
 * keyring.
 *
 * If the authorship is already known (ie, not ANONYMOUS) then returns without changing anything.
 * That means this function can be called several times on the same manifest, but will only perform
 * any work the first time.
 *
 * If the manifest has no bundle key (BK) field, then it is anonymous, so leaves 'authorship'
 * unchanged and returns.
 *
 * If an identity is found in the keyring with permission to alter the bundle, then sets the
 * manifest 'authorship' field to AUTHOR_AUTHENTIC, the 'author' field to the SID of the identity,
 * the manifest 'cryptoSignSecret' field to the bundle secret key and the 'haveSecret' field to
 * EXISTING_BUNDLE_ID.
 *
 * If no identity is found in the keyring that combines with the bundle key (BK) field to yield
 * the bundle's secret key, then leaves the manifest 'authorship' field as ANONYMOUS.
 *
 * If an error occurs, eg, the keyring contains an invalid Rhizome Secret or a cryptographic
 * operation fails, then sets the 'authorship' field to AUTHENTICATION_ERROR and leaves the
 * 'author', 'haveSecret' and 'cryptoSignSecret' fields unchanged.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
void rhizome_find_bundle_author_and_secret(rhizome_manifest *m)
{
  IN();
  DEBUGF(rhizome, "Finding author and secret for bid=%s", m->has_id ? alloca_tohex_rhizome_bid_t(m->cryptoSignPublic) : "(none)");
  if (m->authorship != ANONYMOUS) {
    DEBUGF(rhizome, "   bundle author already found");
    RETURNVOID;
  }
  assert(is_sid_t_any(m->author));
  if (!m->has_bundle_key) {
    DEBUGF(rhizome, "   bundle has no BK field");
    RETURNVOID;
  }
  // Optimisation: try 'sender' SID first, if present.
  const sid_t *author_sidp = NULL;
  const unsigned char *sender_rs = NULL;
  if (m->has_sender) {
    size_t rs_len;
    enum rhizome_secret_disposition d = find_rhizome_secret(&m->sender, &rs_len, &sender_rs);
    switch (d) {
      case FOUND_RHIZOME_SECRET:
	DEBUGF(rhizome, "   sender has Rhizome secret");
	if (rhizome_secret_yields_bundle_secret(m, sender_rs, rs_len)) {
	  DEBUGF(rhizome, "   ... that matches!");
	  author_sidp = &m->sender;
	}
	break;
      case IDENTITY_NOT_FOUND:
	DEBUGF(rhizome, "   sender not found");
	break;
      case IDENTITY_HAS_NO_RHIZOME_SECRET:
	DEBUGF(rhizome, "   sender has no Rhizome secret");
	break;
    }
  }
  // If 'sender' SID does not work, try all the other identities in the keyring.
  if (!author_sidp) {
    keyring_iterator it;
    keyring_iterator_start(keyring, &it);
    keypair *kp;
    while ((kp = keyring_next_keytype(&it, KEYTYPE_RHIZOME))) {
      if (kp->private_key == sender_rs)
	continue; // don't try the same identity again
      if (rhizome_secret_yields_bundle_secret(m, kp->private_key, kp->private_key_len)) {
	DEBUGF(rhizome, "   found matching Rhizome secret!");
	keypair *kp_sid = keyring_identity_keytype(it.identity, KEYTYPE_CRYPTOBOX);
	if (kp_sid)
	  author_sidp = (const sid_t *) kp_sid->public_key;
	else
	  DEBUGF(rhizome, "   ... but its identity has no SID");
	break;
      }
    }
  }
  if (author_sidp) {
    m->haveSecret = EXISTING_BUNDLE_ID;
    DEBUGF(rhizome, "   found bundle author sid=%s", alloca_tohex_sid_t(*author_sidp));
    rhizome_manifest_set_author(m, author_sidp);
    m->authorship = AUTHOR_AUTHENTIC;
    // if this bundle is already in the database, update the author.
    if (m->rowid)
      sqlite_exec_void_loglevel(LOG_LEVEL_WARN,
	  "UPDATE MANIFESTS SET author = ? WHERE rowid = ?;",
	  SID_T, &m->author,
	  INT64, m->rowid,
	  END);
  } else {
    DEBUG(rhizome, "   bundle author not found");
    assert(m->authorship == ANONYMOUS);
  }
  OUT();
}

/* Verify the validity of a given secret manifest key.  Return 1 if valid, 0 if not.
 *
 * There is no NaCl API to efficiently test this.  We use a modified version of
 * crypto_sign_keypair() to accomplish this task.
 */
int rhizome_verify_bundle_privatekey(const unsigned char *sk, const unsigned char *pkin)
{
  IN();
  rhizome_bid_t pk;
  crypto_sign_compute_public_key(sk, pk.binary);
  RETURN(bcmp(pkin, pk.binary, sizeof pk.binary) == 0);
}

int rhizome_sign_hash(rhizome_manifest *m, rhizome_signature *out)
{
  IN();
  assert(m->haveSecret);
  int ret = rhizome_sign_hash_with_key(m, m->cryptoSignSecret, m->cryptoSignPublic.binary, out);
  RETURN(ret);
  OUT();
}

int rhizome_sign_hash_with_key(rhizome_manifest *m,const unsigned char *sk,
			       const unsigned char *pk,rhizome_signature *out)
{
  IN();
  unsigned char signatureBuffer[crypto_sign_edwards25519sha512batch_BYTES + crypto_hash_sha512_BYTES];
  unsigned char *hash = m->manifesthash;
  unsigned long long sigLen = 0;
  int mLen = crypto_hash_sha512_BYTES;
  int r = crypto_sign_edwards25519sha512batch(signatureBuffer, &sigLen, &hash[0], mLen, sk);
  if (r)
    RETURN(WHY("crypto_sign_edwards25519sha512batch() failed"));
  /* Here we use knowledge of the internal structure of the signature block
     to remove the hash, since that is implicitly transported, thus reducing the
     actual signature size down to 64 bytes.
     We do then need to add the public key of the signatory on. */
  bcopy(signatureBuffer, &out->signature[1], 64);
  bcopy(pk, &out->signature[65], crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES);
  out->signatureLength = 65 + crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES;
  out->signature[0] = 0x17; // CryptoSign
  RETURN(0);
  OUT();
}

typedef struct manifest_signature_block_cache {
  unsigned char manifest_hash[crypto_hash_sha512_BYTES];
  unsigned char signature_bytes[256];
  int signature_length;
  int signature_valid;
} manifest_signature_block_cache;

#define SIG_CACHE_SIZE 1024
manifest_signature_block_cache sig_cache[SIG_CACHE_SIZE];

static int rhizome_manifest_lookup_signature_validity(const unsigned char *hash, const unsigned char *sig, int sig_len)
{
  IN();
  unsigned int slot=0;
  int i;

  for(i=0;i<crypto_hash_sha512_BYTES;i++) {
    slot=(slot<<1)+(slot&0x80000000?1:0);
    slot+=hash[i];
  }
  for(i=0;i<sig_len;i++) {
    slot=(slot<<1)+(slot&0x80000000?1:0);
    slot+=sig[i];
  }
  slot%=SIG_CACHE_SIZE;

  if (sig_cache[slot].signature_length!=sig_len || 
      memcmp(hash, sig_cache[slot].manifest_hash, crypto_hash_sha512_BYTES) ||
      memcmp(sig, sig_cache[slot].signature_bytes, sig_len)){
    bcopy(hash, sig_cache[slot].manifest_hash, crypto_hash_sha512_BYTES);
    bcopy(sig, sig_cache[slot].signature_bytes, sig_len);
    sig_cache[slot].signature_length=sig_len;

    unsigned char sigBuf[256];
    unsigned char verifyBuf[256];
    unsigned char publicKey[256];

    /* Reconstitute signature by putting manifest hash between the two
       32-byte halves */
    bcopy(&sig[0],&sigBuf[0],64);
    bcopy(hash,&sigBuf[64],crypto_hash_sha512_BYTES);

    /* Get public key of signatory */
    bcopy(&sig[64],&publicKey[0],crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES);

    unsigned long long mlen=0;
    sig_cache[slot].signature_valid=
      crypto_sign_edwards25519sha512batch_open(verifyBuf,&mlen,&sigBuf[0],128,
					       publicKey)
      ? -1 : 0;
  }
  RETURN(sig_cache[slot].signature_valid);
  OUT();
}

int rhizome_manifest_extract_signature(rhizome_manifest *m, unsigned *ofs)
{
  IN();
  DEBUGF(rhizome_manifest, "*ofs=%u m->manifest_all_bytes=%zu", *ofs, m->manifest_all_bytes);
  assert((*ofs) < m->manifest_all_bytes);
  const unsigned char *sig = m->manifestdata + *ofs;
  uint8_t sigType = m->manifestdata[*ofs];
  uint8_t len = (sigType << 2) + 4 + 1;
  if (*ofs + len > m->manifest_all_bytes) {
    WARNF("Invalid signature at offset %u: type=%#02x gives len=%u that overruns manifest size",
	*ofs, sigType, len);
    *ofs = m->manifest_all_bytes;
    RETURN(1);
  }
  *ofs += len;
  assert (m->sig_count <= NELS(m->signatories));
  if (m->sig_count == NELS(m->signatories)) {
    WARN("Too many signature blocks in manifest");
    RETURN(2);
  }
  switch (sigType) {
    case 0x17: // crypto_sign_edwards25519sha512batch()
    {
      assert(len == 97);
      /* Reconstitute signature block */
      int r = rhizome_manifest_lookup_signature_validity(m->manifesthash, sig + 1, 96);
      if (r) {
	WARN("Signature verification failed");
	RETURN(4);
      }
      m->signatureTypes[m->sig_count] = len;
      if ((m->signatories[m->sig_count] = emalloc(crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES)) == NULL)
	RETURN(-1);
      bcopy(sig + 1 + 64, m->signatories[m->sig_count], crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES);
      m->sig_count++;
      DEBUG(rhizome, "Signature verified");
      RETURN(0);
    }
  }
  WARNF("Unsupported signature at ofs=%u: type=%#02x", (unsigned)(sig - m->manifestdata), sigType);
  RETURN(3);
}

// add value to nonce, with the same result regardless of CPU endian order
// allowing for any carry value up to the size of the whole nonce
static void add_nonce(unsigned char *nonce, uint64_t value)
{
  int i=crypto_stream_xsalsa20_NONCEBYTES -1;
  while(i>=0 && value>0){
    int x = nonce[i]+(value & 0xFF);
    nonce[i]=x&0xFF;
    value = (value>>8)+(x>>8);
    i--;
  }
}

/* Encrypt a block of a stream in-place, allowing for offsets that don't align perfectly to block
 * boundaries for efficiency the caller should use a buffer size of (n*RHIZOME_CRYPT_PAGE_SIZE).
 */
int rhizome_crypt_xor_block(unsigned char *buffer, size_t buffer_size, uint64_t stream_offset, 
			    const unsigned char *key, const unsigned char *nonce)
{
  uint64_t nonce_offset = stream_offset & ~(RHIZOME_CRYPT_PAGE_SIZE -1);
  size_t offset=0;
  
  unsigned char block_nonce[crypto_stream_xsalsa20_NONCEBYTES];
  bcopy(nonce, block_nonce, sizeof(block_nonce));
  add_nonce(block_nonce, nonce_offset);
  
  if (nonce_offset < stream_offset){
    size_t padding = stream_offset & (RHIZOME_CRYPT_PAGE_SIZE -1);
    size_t size = RHIZOME_CRYPT_PAGE_SIZE - padding;
    if (size>buffer_size)
      size=buffer_size;
    
    unsigned char temp[RHIZOME_CRYPT_PAGE_SIZE];
    bcopy(buffer, temp + padding, size);
    crypto_stream_xsalsa20_xor(temp, temp, size+padding, block_nonce, key);
    bcopy(temp + padding, buffer, size);
    
    add_nonce(block_nonce, RHIZOME_CRYPT_PAGE_SIZE);
    offset+=size;
  }
  
  while(offset < buffer_size){
    size_t size = buffer_size - offset;
    if (size>RHIZOME_CRYPT_PAGE_SIZE)
      size=RHIZOME_CRYPT_PAGE_SIZE;
    
    crypto_stream_xsalsa20_xor(buffer+offset, buffer+offset, (unsigned long long) size, block_nonce, key);
    
    add_nonce(block_nonce, RHIZOME_CRYPT_PAGE_SIZE);
    offset+=size;
  }
  
  return 0;
}

/* If payload key is known, sets m->payloadKey and m->payloadNonce and returns 1.
 * Otherwise, returns 0;
 */
int rhizome_derive_payload_key(rhizome_manifest *m)
{
  assert(m->payloadEncryption == PAYLOAD_ENCRYPTED);
  unsigned char hash[crypto_hash_sha512_BYTES];
  if (m->has_sender && m->has_recipient) {
    unsigned char *nm_bytes=NULL;
    keyring_iterator it;
    keyring_iterator_start(keyring, &it);
    
    if (!keyring_find_sid(&it, &m->sender)){
      keyring_iterator_start(keyring, &it);
      if (!keyring_find_sid(&it, &m->recipient)){
	WARNF("Neither sender=%s nor recipient=%s is in keyring",
	    alloca_tohex_sid_t(m->sender),
	    alloca_tohex_sid_t(m->recipient));
	return 0;
      }
      nm_bytes = keyring_get_nm_bytes(&m->recipient, &m->sender);
      DEBUGF(rhizome, "derived payload key from recipient=%s* to sender=%s*",
	     alloca_tohex_sid_t_trunc(m->recipient, 7),
	     alloca_tohex_sid_t_trunc(m->sender, 7)
	    );
    }else{
      nm_bytes = keyring_get_nm_bytes(&m->sender, &m->recipient);
      DEBUGF(rhizome, "derived payload key from sender=%s* to recipient=%s*",
	     alloca_tohex_sid_t_trunc(m->sender, 7),
	     alloca_tohex_sid_t_trunc(m->recipient, 7)
	    );
    }
    assert(nm_bytes != NULL);
    crypto_hash_sha512(hash, nm_bytes, crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES);
    
  }else{
    if (!m->haveSecret) {
      WHY("Cannot derive payload key because bundle secret is unknown");
      return 0;
    }
    DEBUGF(rhizome, "derived payload key from bundle secret bsk=%s", alloca_tohex(m->cryptoSignSecret, sizeof m->cryptoSignSecret));
    unsigned char raw_key[9+crypto_sign_edwards25519sha512batch_SECRETKEYBYTES]="sasquatch";
    bcopy(m->cryptoSignSecret, &raw_key[9], crypto_sign_edwards25519sha512batch_SECRETKEYBYTES);
    crypto_hash_sha512(hash, raw_key, sizeof(raw_key));
  }
  bcopy(hash, m->payloadKey, RHIZOME_CRYPT_KEY_BYTES);
  DEBUGF(rhizome_manifest, "SET manifest[%d].payloadKey = %s", m->manifest_record_number, alloca_tohex(m->payloadKey, sizeof m->payloadKey));

  // journal bundles must always have the same nonce, regardless of version.
  // otherwise, generate nonce from version#bundle id#version;
  unsigned char raw_nonce[8 + 8 + sizeof m->cryptoSignPublic.binary];
  uint64_t nonce_version = m->is_journal ? 0 : m->version;
  write_uint64(&raw_nonce[0], nonce_version);
  bcopy(m->cryptoSignPublic.binary, &raw_nonce[8], sizeof m->cryptoSignPublic.binary);
  write_uint64(&raw_nonce[8 + sizeof m->cryptoSignPublic.binary], nonce_version);
  DEBUGF(rhizome, "derived payload nonce from bid=%s version=%"PRIu64, alloca_tohex_sid_t(m->cryptoSignPublic), nonce_version);
  crypto_hash_sha512(hash, raw_nonce, sizeof(raw_nonce));
  bcopy(hash, m->payloadNonce, sizeof(m->payloadNonce));
  DEBUGF(rhizome_manifest, "SET manifest[%d].payloadNonce = %s", m->manifest_record_number, alloca_tohex(m->payloadNonce, sizeof m->payloadNonce));

  return 1;
}
