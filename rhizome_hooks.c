#include "serval.h"
#include "debug.h"
#include "conf.h"
#include <sys/wait.h>

/*
 exports a blob, if not existing in filesystem
 writes a path to the exported or existing blob in path_buffer
 returns RHIZOME_PAYLOAD_STATUS_STORED, if file was written in /tmp/serval
 returns RHIZOME_PAYLOAD_STATUS_TOO_BIG, if file from rhizome store is recycled
 */
enum rhizome_payload_status rhizome_export_or_link_blob(rhizome_manifest *m, char *return_buffer){

    char buffer[1024];

    // If blob already exists in rhizome blobs, just return its path
    if (!FORMF_RHIZOME_STORE_PATH(buffer, "%s/%s", RHIZOME_BLOB_SUBDIR, alloca_tohex_rhizome_filehash_t(m->filehash)))
        return RHIZOME_PAYLOAD_STATUS_ERROR;

    if (access(buffer, R_OK) == 0 ) {
        DEBUGF(rhizome, "File exists already as blob: %s", buffer);
        memcpy(return_buffer, buffer, 1024);
        return RHIZOME_PAYLOAD_STATUS_TOO_BIG;
    }

    // generate tmp export path
    if (!FORMF_SERVAL_TMP_PATH(buffer, "%s", alloca_tohex_rhizome_filehash_t(m->filehash)))
        return RHIZOME_PAYLOAD_STATUS_ERROR;

    // if file already exists in tmp, return the path
    if( access( buffer, R_OK ) == 0 ) {
        DEBUGF(rhizome, "File was already exported: %s", buffer);
        memcpy(return_buffer, buffer, 1024);
        return RHIZOME_PAYLOAD_STATUS_STORED;
    }

    // export file to tmp path
    DEBUGF(rhizome, "File %s does not exist in blob nor in tmp", buffer);
    enum rhizome_payload_status extract_status = rhizome_extract_file(m, buffer);
    if (extract_status != RHIZOME_PAYLOAD_STATUS_STORED) {
        WARNF("File could not be extracted: %s.", rhizome_payload_status_message(extract_status));
        return extract_status;
    }

    chmod(buffer, (S_IRUSR | S_IRGRP | S_IROTH));
    DEBUGF(rhizome, "File exported: %s; status: %s", buffer, rhizome_payload_status_message(extract_status));

    memcpy(return_buffer, buffer, 1024);
    return extract_status;
}


/*
 exports a bundle manifest
 */
enum rhizome_payload_status rhizome_export_manifest(rhizome_manifest *m, char *return_buffer){

    char buffer[1024];

    // generate tmp export path
    if (!FORMF_SERVAL_TMP_PATH(buffer, "%s.manifest", alloca_tohex_rhizome_filehash_t(m->filehash)))
        return RHIZOME_PAYLOAD_STATUS_ERROR;

    // if file already exists in tmp, return the path
    if( access( buffer, R_OK ) == 0 ) {
        DEBUGF(rhizome, "Manifest was already exported: %s", buffer);
        memcpy(return_buffer, buffer, 1024);
        return RHIZOME_PAYLOAD_STATUS_STORED;
    }

    // export file to tmp path
    DEBUGF(rhizome, "Manifest %s does not exist in tmp", buffer);
    enum rhizome_payload_status extract_status;
    if ( 0 != rhizome_write_manifest_file(m, buffer, 0) ){
        extract_status = RHIZOME_PAYLOAD_STATUS_ERROR;
    } else {
        extract_status = RHIZOME_PAYLOAD_STATUS_STORED;
    }
    chmod(buffer, (S_IRUSR | S_IRGRP | S_IROTH));
    DEBUGF(rhizome, "Manifest exported: %s; status: %s", buffer, rhizome_payload_status_message(extract_status));

    memcpy(return_buffer, buffer, 1024);
    return extract_status;
}

enum rhizome_hook_return {
    HOOK_MATCH = 0,
    HOOK_MISTMATCH = 1,
    HOOK_UNAPPLICABLE = 2,
    HOOK_ERROR = 4
};

/*
 excecutes hook binary bin following the Hooks Calling Conventions
 if successful, the return value is binary anded to manifest status.
 returns nothing, hooks are not applied if failing
 */
enum rhizome_hook_return rhizome_excecute_hook_binary(const char bin[1024], rhizome_manifest *m, char *param2){

    int status;
    pid_t pid = vfork();

    if (pid == 0) {
        // We're in the child process
        execlp(bin, bin, m->manifestdata, param2, NULL);
        // if exec() was successful, this won't be reached, else print error and exit the child
        WARNF("executing hook binary went wrong: %s", strerror(errno));
		exit(1);
    }

    if (pid > 0) {
        // parent process calls waitpid() on the child
        if (waitpid(pid, &status, 0)) {

            if (WIFEXITED(status)){
                DEBUGF(rhizome, "Hook binary executed successfully, exited: %i, status: %i", WIFEXITED(status), WEXITSTATUS(status));

                // "...Programs that perform comparison use a different convention: they use status 1 to indicate a mismatch, and status 2 to indicate an inability to compare."
                if(WEXITSTATUS(status) == HOOK_UNAPPLICABLE){
                    WARNF("Hook %s indicated inability to be applied on given data (exit 2).", bin);

                } else if (WEXITSTATUS(status) == HOOK_MISTMATCH || WEXITSTATUS(status) == HOOK_MATCH){
                    DEBUGF(rhizome, "Hook %s returned %i", bin, WEXITSTATUS(status));
                    return WEXITSTATUS(status);

                } else {
                    WARNF("Hook %s returned unknown status: %i", bin, WEXITSTATUS(status));
                }
            } else {
                WARNF("Executing hook %s went wrong, skipping.", strerror(errno));
            }
        } else {
            WARNF("Error waiting for child process.");
        }
    } else {
        WARNF("Couldn't fork, skipped hook %s.", bin);
    }

    return HOOK_ERROR;
}

int rhizome_apply_download_hook(rhizome_manifest *m) {
	// if hook is unset return positivly
	if (strlen(config.rhizome.download_hook) == 0) 
		return 1;
	
	return rhizome_excecute_hook_binary(config.rhizome.download_hook, m, NULL);
}

int rhizome_apply_content_hook(rhizome_manifest *m) {
    enum rhizome_payload_status filestatus = RHIZOME_PAYLOAD_STATUS_NEW;
    char filepath[1024] = "";

	// if hook is unset return positivly
	if (strlen(config.rhizome.content_hook) == 0) 
		return 1;
	
    filestatus = rhizome_export_or_link_blob(m, filepath);
    if ( filestatus == RHIZOME_PAYLOAD_STATUS_ERROR ){
        WARNF("Rhizome file %s couldn't be exported.", m->name);
		return 1;
    }
	
	int ret = rhizome_excecute_hook_binary(config.rhizome.content_hook, m, filepath);
	
    if (config.rhizome.hook_cleanup) {
        // remove potentially created file
        if( filestatus == RHIZOME_PAYLOAD_STATUS_STORED ) {
            // file exists
            if ( 0 != remove(filepath) ){
                // removing file failed
                WARNF("Couldn't remove file: %s", filepath);
            } else {
                DEBUGF(rhizome, "File deleted: %s", filepath);
            }
        }
    }
	
	return ret;
}

// simple linked list to save the results of the executed announce hooks
typedef struct announce_cache_s {
    struct announce_cache_s *prev;
    sign_public_t bundle_id;
    sid_t sid;
    int announce;
} announce_cache_t;

announce_cache_t *announce_cache;

int rhizome_apply_announce_hook(rhizome_manifest *m, struct subscriber *peer) {
    // don't announce inactive manifests
    if (!m->active) {
        return 0;
    }

	// if hook is unset return positivly
	if (strlen(config.rhizome.announce_hook) == 0) {
		return 1;
    }

    announce_cache_t *cache;
    
    // run over all cache elements
    for(cache = announce_cache; cache; cache = cache->prev ){
        if ( !memcmp( &cache->sid,       &peer->sid,             sizeof(sid_t)) &&
             !memcmp( &cache->bundle_id, &m->keypair.public_key, sizeof(sign_public_t)) ){
            
            DEBUGF(rhizome, "Rhizome announce hook cache hit for bid:%s, %s to sid:%s.",
                alloca_tohex_sid_t(peer->sid),
                cache->announce?"announce":"retain",
                alloca_tohex_sid_t(peer->sid));
            return cache->announce;
        }
    }

    cache = malloc(sizeof(announce_cache_t));
    if (announce_cache) {
        cache->prev = announce_cache;
    } else {
        cache->prev = NULL;
    }

    announce_cache = cache;

    cache->bundle_id = m->keypair.public_key;
    cache->sid = peer->sid;
	cache->announce = rhizome_excecute_hook_binary(config.rhizome.announce_hook, m, alloca_tohex_sid_t(peer->sid));

    return cache->announce;
}
