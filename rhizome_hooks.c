#include "serval.h"
#include "debug.h"
#include "conf.h"
#include <sys/wait.h>
#include <errno.h>

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
        DEBUGF(rhizome_hooks, "File exists already as blob: %s", buffer);
        memcpy(return_buffer, buffer, 1024);
        return RHIZOME_PAYLOAD_STATUS_TOO_BIG;
    }

    // generate tmp export path
    if (!FORMF_SERVAL_TMP_PATH(buffer, "%s", alloca_tohex_rhizome_filehash_t(m->filehash)))
        return RHIZOME_PAYLOAD_STATUS_ERROR;

    // if file already exists in tmp, return the path
    if( access( buffer, R_OK ) == 0 ) {
        DEBUGF(rhizome_hooks, "File was already exported: %s", buffer);
        memcpy(return_buffer, buffer, 1024);
        return RHIZOME_PAYLOAD_STATUS_STORED;
    }

    // export file to tmp path
    DEBUGF(rhizome_hooks, "File %s does not exist in blob nor in tmp", buffer);
    enum rhizome_payload_status extract_status = rhizome_extract_file(m, buffer);
    if (extract_status != RHIZOME_PAYLOAD_STATUS_STORED) {
        WARNF("File could not be extracted: %s.", rhizome_payload_status_message(extract_status));
        return extract_status;
    }

    chmod(buffer, (S_IRUSR | S_IRGRP | S_IROTH));
    DEBUGF(rhizome_hooks, "File exported: %s; status: %s", buffer, rhizome_payload_status_message(extract_status));

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
        DEBUGF(rhizome_hooks, "Manifest was already exported: %s", buffer);
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
    DEBUGF(rhizome_hooks, "Manifest exported: %s; status: %s", buffer, rhizome_payload_status_message(extract_status));

    memcpy(return_buffer, buffer, 1024);
    return extract_status;
}

enum rhizome_hook_return {
    HOOK_NOWAIT = -1,
    HOOK_MATCH = 0,
    HOOK_MISTMATCH = 1,
    HOOK_UNAPPLICABLE = 2,
    HOOK_ERROR = 4,
};

/*
 excecutes hook binary bin following the Hooks Calling Conventions
 if successful, the return value is binary anded to manifest status.
 returns nothing, hooks are not applied if failing
 */
enum rhizome_hook_return rhizome_excecute_hook_binary(char **argv){

    int status;
    pid_t pid = vfork();

    if (pid == 0) {
        // We're in the child process
        // execlp(bin, bin, m->manifestdata, param2, NULL);
        execvp(argv[0], argv);
        // if exec() was successful, this won't be reached, else print error and exit the child
        WARNF("executing hook binary \"%s\" went wrong: %s", argv[0], strerror(errno));
		exit(1);
    }

    if (pid > 0) {
        // parent process calls waitpid() on the child
        if (waitpid(pid, &status, 0)) {

            if (WIFEXITED(status)){
                DEBUGF(rhizome_hooks, "Hook binary executed successfully, exited: %i, status: %i", WIFEXITED(status), WEXITSTATUS(status));

                // "...Programs that perform comparison use a different convention: they use status 1 to indicate a mismatch, and status 2 to indicate an inability to compare."
                if(WEXITSTATUS(status) == HOOK_UNAPPLICABLE){
                    WARNF("Hook %s indicated inability to be applied on given data (exit 2).", argv[0]);

                } else if (WEXITSTATUS(status) == HOOK_MISTMATCH || WEXITSTATUS(status) == HOOK_MATCH){
                    DEBUGF(rhizome_hooks, "Hook %s returned %i", argv[0], WEXITSTATUS(status));
                    return WEXITSTATUS(status);

                } else {
                    WARNF("Hook %s returned unknown status: %i", argv[0], WEXITSTATUS(status));
                }
            } else {
                WARNF("Executing hook %s went wrong, skipping.", strerror(errno));
            }
        } else {
            WARNF("Error waiting for child process.");
        }
    } else {
        WARNF("Couldn't fork, skipped hook %s.", argv[0]);
    }

    return HOOK_ERROR;
}

enum rhizome_hook_return rhizome_call_hook_socket(char **argv){
    int socket_fd;

    if ( (socket_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        DEBUG(rhizome_hooks, "Couldn't open rhizome hook socket.");
        return HOOK_ERROR;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, config.rhizome.hook_socket, sizeof(addr.sun_path));

    if (connect(socket_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        DEBUG(rhizome_hooks, "Couldn't connect to rhizome hook socket.");
        return HOOK_ERROR;
    }

    int bytes = 0;
    for (int i = 0; argv[i] != '\0'; i++) {
        DEBUGF(rhizome_hooks, "Writing bytes to sock: %s", argv[i]);
        bytes += write(socket_fd, argv[i], strlen(argv[i]));
        bytes += write(socket_fd, " ", 1);
    }

    DEBUGF(rhizome_hooks, "Written %i bytes, now reading from socket...", bytes);
    char ret_byte[5] = "\0";
    int bytes_read = read(socket_fd, ret_byte, 4);

    if (bytes_read == -1) {
	WARNF("Read returned %s", strerror(errno));
	return HOOK_ERROR;
    }

    if (bytes_read == 0) {
        WARN("Read 0 bytes, hook failed...");
	return HOOK_ERROR;
    }

    ret_byte[bytes_read + 1] = '\0';

    int ret_value = atoi(ret_byte);
    DEBUGF(rhizome_hooks, "Hook %s returned %i", argv[0], ret_value);

    return ret_value;
}


/*
 Data structure to keep hook return values. The elements are supposed to be in ordered by timeout.
 */
typedef struct cache_s {
    struct cache_s *next;
    time_s_t timeout;
    union {
        char raw;
        struct {rhizome_bid_t bundle_id; sid_t sid; int ret;} announce;
        struct {sid_t sid; u_int8_t found; } encounter;
    };
} cache_t;

/*
 Iterates through a cache and checks if the entry with key is present.
 After one timed out element is found, all following are deleted.
 */
cache_t* cache_check(cache_t **cache, char *key, unsigned int keylen) {
    time_s_t now = gettime();

    // keeps the last inspected cache elem, can either be NULL (direct timeout) or the last valid elem
    cache_t *ci_last = NULL;
    cache_t *cache_hit = NULL;

    cache_t *ci = *cache;
    while (ci) {
        // remove elem if timed out
        if ( ci->timeout < now ) {
            if (ci == *cache){
                *cache = ci->next;
                free(ci);
                ci = *cache;
                continue;
            }

            ci_last->next = ci->next;
            free(ci);
            ci = ci_last->next;

            continue;
        }

        // remember elem if key matches
        if ( !memcmp( &ci->raw, key, keylen) ){
            cache_hit = ci;
        }

        // remember last valid item
        ci_last = ci;
        ci = ci->next;
    }

    return cache_hit;
} 

cache_t* cache_add(cache_t **cache, cache_t *stub, time_s_t timeout) {
    // create new cache entry, and copy the stub.
    cache_t *cache_new = malloc(sizeof(cache_t));
    if (!cache_new) {
        WARN("Hook cache malloc failed, not caching...");
        return NULL;
    }
    memcpy(cache_new, stub, sizeof(cache_t));
    cache_new->timeout = gettime() + timeout;

    // link the old cache head and set the new
    cache_new->next = *cache;
    *cache = cache_new;

    return cache_new;
}

cache_t *encounter_cache = NULL;
#define ENCOUNTER_CACHE_TIMEOUT_S (10)

void rhizome_apply_encounter_hook(struct subscriber *peer, u_int8_t found) {
    // if hook is unset return 
	if (strlen(config.rhizome.encounter_hook) == 0) 
		return;

    // use stack local cache elem to check for cache hit
    cache_t cache_elem;
    cache_elem.encounter.sid = peer->sid;
    cache_elem.encounter.found = found;

    // check if this key already has an entry
    cache_t *cache_hit = cache_check(&encounter_cache, &cache_elem.raw, sizeof(sid_t));
    if (cache_hit) {
        DEBUGF(rhizome_hooks, "Encounter hook, cache hit, sid:%s", alloca_tohex_sid_t(peer->sid));

        cache_hit->timeout = gettime() + ENCOUNTER_CACHE_TIMEOUT_S;

        if (cache_hit->encounter.found == found) {
            return;
        }

        cache_hit->encounter.found = found;
    }

    DEBUGF(rhizome_hooks, "Encounter hook, sid:%s, found:%i", alloca_tohex_sid_t(peer->sid), found);
    
    char* found_str = calloc(10, sizeof(char));
    snprintf(found_str, 2, "%i", found);
    char *argv[] = {config.rhizome.encounter_hook, alloca_tohex_sid_t(peer->sid), found_str, NULL};
    rhizome_call_hook_socket(argv);
    free(found_str);


    if (!cache_hit) {
        cache_add(&encounter_cache, &cache_elem, ENCOUNTER_CACHE_TIMEOUT_S);
    }

    return;
}

int rhizome_apply_download_hook(rhizome_manifest *m) {
	// if hook is unset return positivly
	if (strlen(config.rhizome.download_hook) == 0) 
		return 1;
    
    DEBUGF(rhizome_hooks, "Download hook, bid:%s", alloca_tohex_rhizome_bid_t(m->cryptoSignPublic));
    char *argv[] = {config.rhizome.download_hook, (char *) m->manifestdata, NULL};
	return rhizome_call_hook_socket(argv);
}

int rhizome_apply_content_hook(rhizome_manifest *m) {
    enum rhizome_payload_status filestatus = RHIZOME_PAYLOAD_STATUS_NEW;
    char filepath[1024] = "";

	// if hook is unset return positivly
	if (strlen(config.rhizome.content_hook) == 0) 
		return 1;

    char *argv[] = {config.rhizome.content_hook, (char *) m->manifestdata, filepath, NULL};
	
    filestatus = rhizome_export_or_link_blob(m, filepath);
    if ( filestatus == RHIZOME_PAYLOAD_STATUS_ERROR ){
        WARNF("Rhizome file %s couldn't be exported.", m->name);
        argv[3] = "";
    }
	
    DEBUGF(rhizome_hooks, "Content hook, bid:%s", alloca_tohex_rhizome_bid_t(m->cryptoSignPublic));
	int ret = rhizome_call_hook_socket(argv);
	
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

cache_t *announce_cache = NULL;
#define ANNOUNCE_CACHE_TIMEOUT_S (10)

int rhizome_apply_announce_hook(rhizome_manifest *m, struct subscriber *peer) {

    if (strlen((char *) m->manifestdata) == 0) {
        WARN("Announce hook failed: empty manifest, skipping.");
        return 1;
    }

    // don't announce inactive manifests
    if (!m->active) {
        return 0;
    }

	// if hook is unset return positivly
	if (strlen(config.rhizome.announce_hook) == 0) {
		return 1;
    }

    // use stack local cache elem to check for cache hit
    cache_t cache_elem;
    cache_elem.announce.bundle_id = m->cryptoSignPublic;
    cache_elem.announce.sid = peer->sid;

    // check if this key already has an entry
    cache_t *cache_hit = cache_check(&announce_cache, &cache_elem.raw, sizeof(rhizome_bid_t)+sizeof(sid_t));
    if (cache_hit) {
        DEBUGF(rhizome_hooks, "Announce hook, cache hit, sid:%s", alloca_tohex_sid_t(peer->sid));
        return cache_hit->announce.ret;
    }

    DEBUGF(rhizome_hooks, "Announce hook, sid:%s, %i", alloca_tohex_sid_t(peer->sid), strlen((char *) m->manifestdata));
    char *argv[] = {config.rhizome.announce_hook, (char *) m->manifestdata, alloca_tohex_sid_t(peer->sid), NULL};
    
    cache_t *cache_new = cache_add(&announce_cache, &cache_elem, ANNOUNCE_CACHE_TIMEOUT_S);

    if (!cache_new) {
        WARN("Announce hook cache malloc failed, not caching...");
        return rhizome_call_hook_socket(argv);
    } else {
        // execute the filter
        cache_new->announce.ret = rhizome_call_hook_socket(argv);
    }

    return cache_new->announce.ret;
}
