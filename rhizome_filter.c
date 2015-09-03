#include "rhizome_filter.h"
#include "serval.h"
#include "rhizome.h"
#include "log.h"
#include "conf.h"

#define FILEHASH_SIZE 128

int get_number_of_files() {
	  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
	  sqlite3_stmt *statement  = sqlite_prepare(&retry, "SELECT count(filehash) FROM manifests WHERE service==\"file\"");

	  int file_count = 0;

	  while(sqlite_step_retry(&retry, statement)==SQLITE_ROW){
		  file_count = sqlite3_column_int64(statement, 0);
	  }

	  sqlite3_finalize(statement);

	  return file_count;
}

char ** get_files() {
	  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
	  sqlite3_stmt *statement  = sqlite_prepare(&retry, "SELECT filehash FROM manifests WHERE service==\"file\"");

	  int file_count = get_number_of_files();
	  char **file_hashes = malloc(sizeof (char *) * file_count);

	  int i = 0;
	  while(sqlite_step_retry(&retry, statement)==SQLITE_ROW){
		  file_hashes[i] = malloc(FILEHASH_SIZE+1);
		  const char *file_hash = sqlite3_column_blob(statement, 0);
		  strncpy(file_hashes[i], file_hash,FILEHASH_SIZE);
		  i++;
	  }

	  sqlite3_finalize(statement);

	  return file_hashes;
}

