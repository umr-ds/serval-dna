/*
Serval DNA - Rhizome entry points
Copyright (C) 2012-2013 Serval Project Inc.
Copyright (C) 2011-2012 Paul Gardner-Stephen
 
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

/*
  Portions Copyright (C) 2013 Petter Reinholdtsen
  Some rights reserved

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
  COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdlib.h>
#include <assert.h>
#include "serval.h"
#include "conf.h"
#include "str.h"
#include "rhizome.h"
#include "httpd.h"
#include "dataformats.h"

int is_rhizome_enabled()
{
  return config.rhizome.enable;
}

int is_rhizome_http_enabled()
{
  return config.rhizome.enable
    &&   config.rhizome.http.enable
    &&   rhizome_db;
}

int is_rhizome_mdp_enabled()
{
  return config.rhizome.enable
    &&   config.rhizome.mdp.enable
    &&   rhizome_db;
}

int is_rhizome_mdp_server_running()
{
  return is_rhizome_mdp_enabled();
}

int is_rhizome_advertise_enabled()
{
  return config.rhizome.enable
    &&   config.rhizome.advertise.enable
    &&   rhizome_db
    &&   (is_httpd_server_running() || is_rhizome_mdp_server_running());
}

int rhizome_fetch_delay_ms()
{
  return config.rhizome.fetch_delay_ms;
}

/* Create a manifest structure to accompany adding a file to Rhizome or appending to a journal.
 * This function is used by all application-facing APIs (eg, CLI, RESTful HTTP).  It differs from
 * the import operation in that if the caller does not supply a complete, signed manifest then this
 * operation will create it using the fields supplied.  Also, the caller can supply a clear-text
 * payload with the 'crypt=1' field to cause it to be stored encrypted.
 *
 * - if 'appending' is true then the new bundle will be a journal bundle, otherwise it will be a
 *   normal bundle.  Any existing manifest must be consistent; eg, an append will fail if a bundle
 *   with the same Bundle Id already exists in the store and is not a journal.
 *
 * - 'm' must point to a manifest structure into which any supplied partial manifest has already
 *   been parsed.  If the caller supplied no (partial) manifest at all, then the manifest 'm' will
 *   be blank.
 *
 * - 'mout' must point to a manifest pointer which is updated to hold the constructed manifest.
 *
 * - 'bid' must point to a supplied bundle id parameter, or NULL if none was supplied.
 *
 * - 'bsk' must point to a supplied bundle secret parameter, or NULL if none was supplied.
 *
 * - 'author' must point to a supplied author parameter, or NULL if none was supplied.
 *
 * - 'file_path' can point to a supplied payload file name (eg, if the payload was read from a named
 *   file), or can be NULL.  If not NULL, then the file's name will be used to fill in the 'name'
 *   field of the manifest if it was not explicitly supplied in 'm' or in the existing manifest.
 *
 * - 'nassignments' and 'assignments' describe an array of field assignments that override the
 *   fields supplied in 'm' and also the fields in any existing manifest with the same Bundle Id.
 *
 * - 'reason' may either be NULL or points to a strbuf to which descriptive text is appended if the
 *   manifest creation fails.
 *
 * If the add is successful, modifies '*mout' to point to the constructed Manifest, which might be
 * 'm' or might be another manifest, and returns 0.  It is the caller's responsibility to free
 * '*mout'.
 *
 * If the add fails because of invalid field settings that violate Rhizome semantics (eg, a missing
 * mandatory field, a malformed field name or value), then if 'reason' is not NULL, appends a text
 * string to the 'reason' strbuf that describes the cause of the failure, does not alter '*mout',
 * and returns 1.
 *
 * If the add fails because of a recoverable error (eg, database locking) then if 'reason' is not
 * NULL, appends a text string to the 'reason' strbuf that describes the cause of the failure, does
 * not alter '*mout', and returns 2.
 *
 * If the add fails because of an unrecoverable error (eg, out of memory, i/o failure)
 * then if 'reason' is not NULL, appends a text string to the 'reason' strbuf that describes the
 * cause of the failure, does not alter '*mout', and returns -1.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
enum rhizome_add_file_result rhizome_manifest_add_file(int appending,
                                                       rhizome_manifest *m,
                                                       rhizome_manifest **mout,
                                                       const rhizome_bid_t *bid,
                                                       const rhizome_bk_t *bsk,
                                                       const sid_t *author,
                                                       const char *file_path,
                                                       unsigned nassignments,
                                                       const struct rhizome_manifest_field_assignment *assignments,
                                                       strbuf reason
                                                      )
{
  const char *cause = NULL;
  enum rhizome_add_file_result result = RHIZOME_ADD_FILE_ERROR;
  rhizome_manifest *existing_manifest = NULL;
  rhizome_manifest *new_manifest = NULL;
  assert(m != NULL);
  // Caller must not supply a malformed manifest (but an invalid one is okay because missing
  // fields will be filled in, so we don't check validity here).
  assert(!m->malformed);
  // If appending to a journal, caller must not supply 'version', 'filesize' or 'filehash' fields,
  // because these will be calculated by the journal append logic.
  if (appending) {
    if (m->version)
      DEBUG(rhizome, cause = "Cannot set 'version' field in journal append");
    else if (m->filesize != RHIZOME_SIZE_UNSET)
      DEBUG(rhizome, cause = "Cannot set 'filesize' field in journal append");
    else if (m->has_filehash)
      DEBUG(rhizome, cause = "Cannot set 'filehash' field in journal append");
    if (cause) {
      result = RHIZOME_ADD_FILE_INVALID_FOR_JOURNAL;
      goto error;
    }
  }
  if (bid) {
    DEBUGF(rhizome, "Reading manifest from database: id=%s", alloca_tohex_rhizome_bid_t(*bid));
    if ((existing_manifest = rhizome_new_manifest()) == NULL) {
      WHY(cause = "Manifest struct could not be allocated");
      goto error;
    }
    enum rhizome_bundle_status status = rhizome_retrieve_manifest(bid, existing_manifest);
    switch (status) {
    case RHIZOME_BUNDLE_STATUS_NEW:
      // No manifest with that bundle ID exists in the store, so we are building a bundle from
      // scratch.
      rhizome_manifest_free(existing_manifest);
      existing_manifest = NULL;
      break;
    case RHIZOME_BUNDLE_STATUS_SAME:
      // Found a manifest with the same bundle ID.  If appending to a journal, then keep the
      // existing 'version', 'filesize' and 'filehash' (so they can be verified when the existing
      // payload is copied) and don't allow the supplied manifest to overwrite them.  If not a
      // journal, then unset the 'version', 'filesize' and 'filehash' fields, then overwrite the
      // existing manifest with the supplied manifest.
      if (!appending) {
        rhizome_manifest_del_version(existing_manifest);
        rhizome_manifest_del_filesize(existing_manifest);
        rhizome_manifest_del_filehash(existing_manifest);
      }
      if (rhizome_manifest_overwrite(existing_manifest, m) == -1) {
        WHY(cause = "Existing manifest could not be overwritten");
        goto error;
      }
      new_manifest = existing_manifest;
      existing_manifest = NULL;
      break;
    case RHIZOME_BUNDLE_STATUS_BUSY:
      WARN(cause = "Existing manifest not retrieved due to Rhizome store locking");
      result = RHIZOME_ADD_FILE_BUSY;
      goto error;
    case RHIZOME_BUNDLE_STATUS_ERROR:
      WHY(cause = "Error retrieving existing manifest from Rhizome store");
      goto error;
    case RHIZOME_BUNDLE_STATUS_DUPLICATE:
    case RHIZOME_BUNDLE_STATUS_OLD:
    case RHIZOME_BUNDLE_STATUS_INVALID:
    case RHIZOME_BUNDLE_STATUS_FAKE:
    case RHIZOME_BUNDLE_STATUS_INCONSISTENT:
    case RHIZOME_BUNDLE_STATUS_NO_ROOM:
    case RHIZOME_BUNDLE_STATUS_READONLY:
      FATALF("rhizome_retrieve_manifest() returned %s", rhizome_bundle_status_message(status));
    }
  }
  // If no existing bundle has been identified, we are building a bundle from scratch.
  if (!new_manifest) {
    new_manifest = m;
    // A new journal manifest needs the 'filesize' and 'tail' fields set so that the first append can
    // succeed.
    if (appending) {
      if (new_manifest->filesize == RHIZOME_SIZE_UNSET)
        rhizome_manifest_set_filesize(new_manifest, 0);
      if (new_manifest->tail == RHIZOME_SIZE_UNSET)
        rhizome_manifest_set_tail(new_manifest, 0);
    }
  }
  // Apply the field assignments, overriding the existing manifest fields.
  if (nassignments) {
    unsigned i;
    for (i = 0; i != nassignments; ++i) {
      const struct rhizome_manifest_field_assignment *asg = &assignments[i];
      rhizome_manifest_remove_field(new_manifest, asg->label, asg->labellen);
      if (asg->value) {
        const char *label = alloca_strndup(asg->label, asg->labellen);
        enum rhizome_manifest_parse_status status = rhizome_manifest_parse_field(new_manifest, asg->label, asg->labellen, asg->value, asg->valuelen);
        int status_ok = 0;
        switch (status) {
          case RHIZOME_MANIFEST_ERROR:
            WHYF("Fatal error updating manifest field");
            if (reason)
              strbuf_sprintf(reason, "Fatal error updating manifest field: %s=%s", label, alloca_toprint(-1, asg->value, asg->valuelen));
            goto error;
          case RHIZOME_MANIFEST_OK:
            status_ok = 1;
            break;
          case RHIZOME_MANIFEST_SYNTAX_ERROR:
	    DEBUGF(rhizome, "Manifest syntax error: %s=%s", label, alloca_toprint(-1, asg->value, asg->valuelen));
            if (reason)
              strbuf_sprintf(reason, "Manifest syntax error: %s=%s", label, alloca_toprint(-1, asg->value, asg->valuelen));
            result = RHIZOME_ADD_FILE_INVALID;
            goto error;
          case RHIZOME_MANIFEST_DUPLICATE_FIELD:
            // We already deleted the field, so if this happens, its a nasty bug
            FATALF("Duplicate field should not occur: %s=%s", label, alloca_toprint(-1, asg->value, asg->valuelen));
          case RHIZOME_MANIFEST_INVALID:
	    DEBUGF(rhizome, "Manifest invalid field: %s=%s", label, alloca_toprint(-1, asg->value, asg->valuelen));
            if (reason)
              strbuf_sprintf(reason, "Manifest invalid field: %s=%s", label, alloca_toprint(-1, asg->value, asg->valuelen));
            result = RHIZOME_ADD_FILE_INVALID;
            goto error;
          case RHIZOME_MANIFEST_MALFORMED:
	    DEBUGF(rhizome, "Manifest malformed field: %s=%s", label, alloca_toprint(-1, asg->value, asg->valuelen));
            if (reason)
              strbuf_sprintf(reason, "Manifest malformed field: %s=%s", label, alloca_toprint(-1, asg->value, asg->valuelen));
            result = RHIZOME_ADD_FILE_INVALID;
            goto error;
          case RHIZOME_MANIFEST_OVERFLOW:
	    DEBUGF(rhizome, "Too many fields in manifest at: %s=%s", label, alloca_toprint(-1, asg->value, asg->valuelen));
            if (reason)
              strbuf_sprintf(reason, "Too many fields in manifest at: %s=%s", label, alloca_toprint(-1, asg->value, asg->valuelen));
            result = RHIZOME_ADD_FILE_INVALID;
            goto error;
        }
        if (!status_ok)
          FATALF("status = %d", status);
      }
    }
  }
  if (appending && !new_manifest->is_journal) {
    cause = "Cannot append to a non-journal";
    DEBUG(rhizome, cause);
    result = RHIZOME_ADD_FILE_REQUIRES_JOURNAL;
    goto error;
  }
  if (!appending && new_manifest->is_journal) {
    cause = "Cannot add a journal bundle (use append instead)";
    DEBUG(rhizome, cause);
    result = RHIZOME_ADD_FILE_INVALID_FOR_JOURNAL;
    goto error;
  }
  if (bsk) {
    if (new_manifest->has_id) {
      if (!rhizome_apply_bundle_secret(new_manifest, bsk)) {
        WHY(cause = "Supplied bundle secret does not match Bundle Id");
        result = RHIZOME_ADD_FILE_WRONG_SECRET;
        goto error;
      }
    } else {
      rhizome_new_bundle_from_secret(new_manifest, bsk);
    }
  }
  // TODO: one day there will be no default service, but for now if no service
  // is specified, it defaults to 'file' (file sharing).
  if (new_manifest->service == NULL) {
    WARNF("Manifest 'service' field not supplied - setting to '%s'", RHIZOME_SERVICE_FILE);
    rhizome_manifest_set_service(new_manifest, RHIZOME_SERVICE_FILE);
  }
  if ((cause = rhizome_fill_manifest(new_manifest, file_path, author ? author : NULL)) != NULL)
    goto error;
  *mout = new_manifest;
  return RHIZOME_ADD_FILE_OK;
error:
  assert(result != RHIZOME_ADD_FILE_OK);
  if (cause && reason)
    strbuf_puts(reason, cause);
  if (new_manifest && new_manifest != m && new_manifest != existing_manifest)
    rhizome_manifest_free(new_manifest);
  if (existing_manifest)
    rhizome_manifest_free(existing_manifest);
  return result;
}

/* Import a bundle from a pair of files, one containing the manifest and the optional other
 * containing the payload.  The work is all done by rhizome_bundle_import() and
 * rhizome_store_manifest().
 */
enum rhizome_bundle_status rhizome_bundle_import_files(rhizome_manifest *m, rhizome_manifest **mout, const char *manifest_path, const char *filepath)
{
  DEBUGF(rhizome, "(manifest_path=%s, filepath=%s)",
	 manifest_path ? alloca_str_toprint(manifest_path) : "NULL",
	 filepath ? alloca_str_toprint(filepath) : "NULL");
  
  size_t buffer_len = 0;
  int ret = 0;
  
  // manifest has been appended to the end of the file.
  if (strcmp(manifest_path, filepath)==0){
    unsigned char marker[4];
    FILE *f = fopen(filepath, "r");
    
    if (f == NULL)
      return WHYF_perror("Could not open manifest file %s for reading.", filepath);
    if (fseek(f, -sizeof(marker), SEEK_END))
      ret=WHY_perror("Unable to seek to end of file");
    if (ret==0){
      ret = fread(marker, 1, sizeof(marker), f);
      if (ret==sizeof(marker))
	ret=0;
      else
	ret=WHY_perror("Unable to read end of manifest marker");
    }
    if (ret==0){
      if (marker[2]!=0x41 || marker[3]!=0x10)
	ret=WHYF("Expected 0x4110 marker at end of file");
    }
    if (ret==0){
      buffer_len = read_uint16(marker);
      if (buffer_len < 1 || buffer_len > MAX_MANIFEST_BYTES)
	ret=WHYF("Invalid manifest length %zu", buffer_len);
    }
    if (ret==0){
      if (fseek(f, -(buffer_len+sizeof(marker)), SEEK_END))
	ret=WHY_perror("Unable to seek to end of file");
    }
    if (ret == 0 && fread(m->manifestdata, buffer_len, 1, f) != 1) {
      if (ferror(f))
	ret = WHYF("fread(%p,%zu,1,%s) error", m->manifestdata, buffer_len, alloca_str_toprint(filepath));
      else if (feof(f))
	ret = WHYF("fread(%p,%zu,1,%s) hit end of file", m->manifestdata, buffer_len, alloca_str_toprint(filepath));
    }
    fclose(f);
  } else {
    ssize_t size = read_whole_file(manifest_path, m->manifestdata, sizeof m->manifestdata);
    if (size == -1)
      ret = -1;
    buffer_len = (size_t) size;
  }
  if (ret)
    return ret;
  m->manifest_all_bytes = buffer_len;
  if (   rhizome_manifest_parse(m) == -1
      || !rhizome_manifest_validate(m)
      || !rhizome_manifest_verify(m)
  )
    return RHIZOME_BUNDLE_STATUS_INVALID;
  enum rhizome_bundle_status status = rhizome_manifest_check_stored(m, mout);
  if (status != RHIZOME_BUNDLE_STATUS_NEW)
    return status;
  enum rhizome_payload_status pstatus = rhizome_import_payload_from_file(m, filepath);
  switch (pstatus) {
    case RHIZOME_PAYLOAD_STATUS_EMPTY:
    case RHIZOME_PAYLOAD_STATUS_STORED:
    case RHIZOME_PAYLOAD_STATUS_NEW:
      if (rhizome_store_manifest(m) == -1)
	return -1;
      return status;
    case RHIZOME_PAYLOAD_STATUS_TOO_BIG:
    case RHIZOME_PAYLOAD_STATUS_EVICTED:
      return RHIZOME_BUNDLE_STATUS_NO_ROOM;
    case RHIZOME_PAYLOAD_STATUS_ERROR:
    case RHIZOME_PAYLOAD_STATUS_CRYPTO_FAIL:
      return -1;
    case RHIZOME_PAYLOAD_STATUS_WRONG_SIZE:
    case RHIZOME_PAYLOAD_STATUS_WRONG_HASH:
      return RHIZOME_BUNDLE_STATUS_INCONSISTENT;
  }
  FATALF("rhizome_import_payload_from_file() returned status = %d", pstatus);
}

/* Sets the bundle key "BK" field of a manifest.  Returns 1 if the field was set, 0 if not.
 *
 * This function must not be called unless the bundle secret is known.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_manifest_add_bundle_key(rhizome_manifest *m)
{
  IN();
  assert(m->haveSecret);
  switch (m->authorship) {
    case ANONYMOUS: // there can be no BK field without an author
    case AUTHOR_UNKNOWN: // we already know the author is not in the keyring
    case AUTHENTICATION_ERROR: // already tried and failed to get Rhizome Secret
      break;
    case AUTHOR_NOT_CHECKED:
    case AUTHOR_LOCAL:
    case AUTHOR_AUTHENTIC:
    case AUTHOR_IMPOSTOR: {
	/* Set the BK using the provided author.  Serval Security Framework defines BK as being:
	*    BK = privateKey XOR sha512(RS##BID)
	* where BID = cryptoSignPublic, 
	*       RS is the rhizome secret for the specified author. 
	* The nice thing about this specification is that:
	*    privateKey = BK XOR sha512(RS##BID)
	* so the same function can be used to encrypt and decrypt the BK field.
	*/
	const unsigned char *rs;
	size_t rs_len = 0;
	enum rhizome_secret_disposition d = find_rhizome_secret(&m->author, &rs_len, &rs);
	switch (d) {
	  case FOUND_RHIZOME_SECRET: {
	      rhizome_bk_t bkey;
	      if (rhizome_secret2bk(&m->cryptoSignPublic, rs, rs_len, bkey.binary, m->cryptoSignSecret) == 0) {
		rhizome_manifest_set_bundle_key(m, &bkey);
		m->authorship = AUTHOR_AUTHENTIC;
		RETURN(1);
	      } else
		m->authorship = AUTHENTICATION_ERROR;
	    }
	    break;
	  case IDENTITY_NOT_FOUND:
	    m->authorship = AUTHOR_UNKNOWN;
	    break;
	  case IDENTITY_HAS_NO_RHIZOME_SECRET:
	    m->authorship = AUTHENTICATION_ERROR;
	    break;
	  default:
	    FATALF("find_rhizome_secret() returned unknown code %d", (int)d);
	    break;
	}
      }
      break;
    default:
      FATALF("m->authorship = %d", (int)m->authorship);
  }
  rhizome_manifest_del_bundle_key(m);
  switch (m->authorship) {
    case AUTHOR_UNKNOWN:
      WHYF("Cannot set BK because author=%s is not in keyring", alloca_tohex_sid_t(m->author));
      break;
    case AUTHENTICATION_ERROR:
      WHY("Cannot set BK due to error");
      break;
    default:
      break;
  }
  RETURN(0);
}

/* Test the status of a given manifest 'm' (id, version) with respect to the Rhizome store, and
 * return a code which indicates whether 'm' should be stored or not, setting *mout to 'm' or
 * to point to a newly allocated manifest.  The caller is responsible for freeing *mout if *mout !=
 * m.  If the caller passes mout==NULL then no new manifest is allocated.
 *
 *  - If the store contains no manifest with the given id, sets *mout = m and returns
 *    RHIZOME_BUNDLE_STATUS_NEW, ie, the manifest 'm' should be stored.
 *
 *  - If the store contains a manifest with the same id and an older version, sets *mout to the
 *    stored manifest and returns RHIZOME_BUNDLE_STATUS_NEW, ie, the manifest 'm' should be
 *    stored.
 *
 *  - If the store contains a manifest with the same id and version, sets *mout to the stored
 *    manifest and returns RHIZOME_BUNDLE_STATUS_SAME.  The caller must compare *m and *mout, and
 *    if they are not identical, must decide what to do.
 *
 *  - If the store contains a manifest with the same id and a later version, sets *mout to the
 *    stored manifest and returns RHIZOME_BUNDLE_STATUS_OLD, ie, the manifest 'm' should NOT be
 *    stored.
 *
 *  - If there is an error querying the Rhizome store or allocating a new manifest structure, logs
 *    an error and returns -1.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
enum rhizome_bundle_status rhizome_manifest_check_stored(rhizome_manifest *m, rhizome_manifest **mout)
{
  assert(m->has_id);
  assert(m->version != 0);
  rhizome_manifest *stored_m = rhizome_new_manifest();
  if (stored_m == NULL)
    return -1;
  enum rhizome_bundle_status result = rhizome_retrieve_manifest(&m->cryptoSignPublic, stored_m);
  if (result==RHIZOME_BUNDLE_STATUS_SAME){
    const char *what = "same as";
    if (m->version < stored_m->version) {
      result = RHIZOME_BUNDLE_STATUS_OLD;
      what = "older than";
    }
    if (m->version > stored_m->version) {
      what = "newer than";
      result = RHIZOME_BUNDLE_STATUS_NEW;
    }
    DEBUGF(rhizome, "Bundle %s:%"PRIu64" is %s stored version %"PRIu64, alloca_tohex_rhizome_bid_t(m->cryptoSignPublic), m->version, what, stored_m->version);
    if (mout)
      *mout = stored_m;
    else
      rhizome_manifest_free(stored_m);
  }else{
    rhizome_manifest_free(stored_m);
    DEBUGF(rhizome, "No stored manifest with id=%s", alloca_tohex_rhizome_bid_t(m->cryptoSignPublic));
    if (mout)
      *mout = m;
  }
  return result;
}

/* Insert the manifest 'm' into the Rhizome store.  This function encapsulates all the invariants
 * that a manifest must satisfy before it is allowed into the store, so it is used by both the sync
 * protocol and the application layer.
 *
 *  - If the manifest is not valid then returns RHIZOME_BUNDLE_STATUS_INVALID.  A valid manifest is
 *    one with all the core (transport) fields present and consistent ('id', 'version', 'filesize',
 *    'filehash', 'tail'), all mandatory application fields present and consistent ('service',
 *    'date') and any other service-dependent mandatory fields present (eg, 'sender', 'recipient').
 *
 *  - If the manifest's signature does not verify, then returns RHIZOME_BUNDLE_STATUS_FAKE.
 *
 *  - If the manifest has a payload (filesize != 0) but the payload is not present in the store
 *    (filehash), then returns an internal error RHIZOME_BUNDLE_STATUS_ERROR (-1).
 *
 *  - If the store will not accept the manifest because there is already the same or a newer
 *    manifest in the store, then returns RHIZOME_BUNDLE_STATUS_SAME or RHIZOME_BUNDLE_STATUS_OLD.
 *
 * This function then attempts to store the manifest.  If this fails due to an internal error,
 * then returns RHIZOME_BUNDLE_STATUS_ERROR (-1), otherwise returns RHIZOME_BUNDLE_STATUS_NEW to
 * indicate that the manifest was successfully stored.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
enum rhizome_bundle_status rhizome_add_manifest(rhizome_manifest *m, rhizome_manifest **mout)
{
  if (mout == NULL)
    DEBUGF(rhizome, "rhizome_add_manifest(m=manifest[%d](%p), mout=NULL)", m->manifest_record_number, m);
  else
    DEBUGF(rhizome, "rhizome_add_manifest(m=manifest[%d](%p), *mout=manifest[%d](%p))", m->manifest_record_number, m, *mout ? (*mout)->manifest_record_number : -1, *mout);
  if (!m->finalised && !rhizome_manifest_validate(m))
    return RHIZOME_BUNDLE_STATUS_INVALID;
  assert(m->finalised);
  if (!m->selfSigned && !rhizome_manifest_verify(m))
    return RHIZOME_BUNDLE_STATUS_FAKE;
  assert(m->filesize != RHIZOME_SIZE_UNSET);
  if (m->filesize > 0 && !rhizome_exists(&m->filehash))
    return WHY("Payload has not been stored");
  enum rhizome_bundle_status status = rhizome_manifest_check_stored(m, mout);

  if(status == RHIZOME_BUNDLE_STATUS_NEW)
    rhizome_apply_filter(m);

      
  if (status == RHIZOME_BUNDLE_STATUS_NEW && rhizome_store_manifest(m) == -1)
    return -1;
  return status;
}

void rhizome_apply_filter(rhizome_manifest *m){
    
    if (config.rhizome.contentfilter.extension.ac == 0)
        return;

    if (0 == strcmp("file", m->service)){
        unsigned int i;
        
        char *bundle_file_ext;
        char *last_dot = strrchr(m->name, '.');
        if (!last_dot || last_dot == m->name)
            return;
        else {
            last_dot = last_dot + 1;
            bundle_file_ext = malloc(strlen(last_dot));
            for(i = 0; last_dot[i]; i++){
                bundle_file_ext[i] = tolower(last_dot[i]);
            }
            bundle_file_ext[i] = 0;
        }
        
        DEBUGF(rhizome, "Bundle file ext: %s", bundle_file_ext);
        char exportpath[255];
        sprintf(exportpath, "/tmp/%s_%s", alloca_tohex_rhizome_bid_t(m->filehash), m->name);
        
        for(i = 0; i < config.rhizome.contentfilter.extension.ac; i++){
            char *config_ext = config.rhizome.contentfilter.extension.av[i].key;
            
            if(0 == strcmp(bundle_file_ext, config_ext)){
                char *bin = config.rhizome.contentfilter.extension.av[i].value;
                DEBUGF(rhizome, "File Extension matched; attempting to executing filter: %s", bin);
                
                if( access( exportpath, F_OK ) != -1 ) {
                    DEBUGF(rhizome, "File already exported: %s", exportpath);
                    // file exists do nothing
                } else {
                    enum rhizome_payload_status extract_status = rhizome_extract_file(m, exportpath);
                    chmod(exportpath, (S_IRUSR | S_IRGRP | S_IROTH));
                    DEBUGF(rhizome, "File exported: %s; status: %s", exportpath, rhizome_payload_status_message(extract_status));
                }
                
                pid_t pid = fork();
                int status;
                if (pid == 0) {
                    // We're in the child process
                    execlp(bin, bin, exportpath, NULL);
                    // if exec() was successful, this won't be reached
                    DEBUGF(rhizome, "exec binary went wrong: %s", strerror(errno));
                }
                
                if (pid > 0) {
                    // parent process calls waitpid() on the child
                    if (waitpid(pid, &status, 0) > 0) {
                        
                        if (WIFEXITED(status)){
                            DEBUGF(rhizome, "Filter binary executed successfully, exitstatus: %i", WEXITSTATUS(status));
                            
                            // "...Programs that perform comparison use a different convention: they use status 1 to indicate a mismatch, and status 2 to indicate an inability to compare."
                            if(WEXITSTATUS(status) == 2){
                                DEBUGF(rhizome, "Filter %s couldn't be applied, skipping.", bin);
                            } else {
                                m->active &= WEXITSTATUS(status);
                            }
                        } else {
                            WARNF("Executing filter %s went wrong, skipping.", strerror(errno));
                        }
                        
                    } else {
                        WARNF("Error waiting for child process.");
                    }
                } else {
                    WARNF("Couldn't fork, skipped filter %s.", bin);
                }
            }
        }
        
        free(bundle_file_ext);
        
        if( access( exportpath, F_OK ) != -1 ) {
            // file exists
            if ( 0 != remove(exportpath) ){
                // removing file failed
                WARNF("Couldn't remove file: %s", exportpath);
            } else {
                DEBUGF(rhizome, "File deleted: %s", exportpath);
            }
        }
    }
}

/* When voice traffic is being carried, we need to throttle Rhizome down
   to a more sensible level.  Or possibly even supress it entirely.
 */
time_ms_t rhizome_voice_timeout = -1;
int rhizome_saw_voice_traffic()
{
  /* We are in "voice mode" for a second after sending a voice frame */
  rhizome_voice_timeout=gettime_ms()+1000;
  return 0;
}

const char *rhizome_bundle_status_message(enum rhizome_bundle_status status)
{
  switch (status) {
    case RHIZOME_BUNDLE_STATUS_NEW:          return "Bundle new to store";
    case RHIZOME_BUNDLE_STATUS_SAME:         return "Bundle already in store";
    case RHIZOME_BUNDLE_STATUS_DUPLICATE:    return "Duplicate bundle already in store";
    case RHIZOME_BUNDLE_STATUS_OLD:          return "Newer bundle already in store";
    case RHIZOME_BUNDLE_STATUS_INVALID:      return "Invalid manifest";
    case RHIZOME_BUNDLE_STATUS_FAKE:         return "Manifest signature does not verify";
    case RHIZOME_BUNDLE_STATUS_INCONSISTENT: return "Manifest inconsistent with supplied payload";
    case RHIZOME_BUNDLE_STATUS_NO_ROOM:      return "No room in store for bundle";
    case RHIZOME_BUNDLE_STATUS_READONLY:     return "Bundle is read-only";
    case RHIZOME_BUNDLE_STATUS_BUSY:         return "Internal error";
    case RHIZOME_BUNDLE_STATUS_ERROR:        return "Internal error";
  }
  return NULL;
}

const char *rhizome_bundle_status_message_nonnull(enum rhizome_bundle_status status)
{
  const char *message = rhizome_bundle_status_message(status);
  return message ? message : "Invalid";
}

const char *rhizome_payload_status_message(enum rhizome_payload_status status)
{
  switch (status) {
    case RHIZOME_PAYLOAD_STATUS_NEW:         return "Payload new to store";
    case RHIZOME_PAYLOAD_STATUS_STORED:      return "Payload already in store";
    case RHIZOME_PAYLOAD_STATUS_EMPTY:       return "Payload empty";
    case RHIZOME_PAYLOAD_STATUS_TOO_BIG:     return "Payload size exceeds store";
    case RHIZOME_PAYLOAD_STATUS_EVICTED:     return "Payload evicted";
    case RHIZOME_PAYLOAD_STATUS_WRONG_SIZE:  return "Payload size contradicts manifest";
    case RHIZOME_PAYLOAD_STATUS_WRONG_HASH:  return "Payload hash contradicts manifest";
    case RHIZOME_PAYLOAD_STATUS_CRYPTO_FAIL: return "Incorrect bundle secret";
    case RHIZOME_PAYLOAD_STATUS_ERROR:       return "Internal error";
  }
  return NULL;
}

const char *rhizome_payload_status_message_nonnull(enum rhizome_payload_status status)
{
  const char *message = rhizome_payload_status_message(status);
  return message ? message : "Invalid";
}
