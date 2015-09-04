#include "rhizome_filter.h"
#include "serval.h"
#include "rhizome.h"
#include "log.h"
#include "conf.h"

#define FILEHASH_SIZE 128
#define FILENAME_SIZE 255

static int get_number_of_results(char *query);
static char ** get_blob_sql_query_results(char *query, int entry_size);

static int get_number_of_results(char *query) {
	char *sql_string = malloc(1024);
	sprintf(sql_string, "SELECT count(*) FROM (%s)", query);

	sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
	sqlite3_stmt *statement  = sqlite_prepare(&retry, query);

	int file_count = 0;

	while(sqlite_step_retry(&retry, statement)==SQLITE_ROW){
		file_count = sqlite3_column_int64(statement, 0);
	}

	sqlite3_finalize(statement);

	return file_count;
}

static char ** get_blob_sql_query_results(char *query, int entry_size) {
	sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
	sqlite3_stmt *statement  = sqlite_prepare(&retry, query);

	int result_count = get_number_of_results(query);

	if(result_count > 0) {
		char **results = malloc(sizeof (char *) * result_count);

		int i = 0;
		while(sqlite_step_retry(&retry, statement)==SQLITE_ROW){
			results[i] = malloc(entry_size+1);
			const char *result = sqlite3_column_blob(statement, 0);
			WARN(result);
			sprintf(results[i], "%s", result);
			i++;
		}

		sqlite3_finalize(statement);

		return results;
	} else {
		sqlite3_finalize(statement);

		return NULL;
	}
}

char ** get_all_files() {
	return get_blob_sql_query_results("SELECT filehash FROM manifests WHERE service==\"file\"", FILEHASH_SIZE);
}

char ** get_extension_files(char *filter_extension) {
	char *sql_query = malloc(512);
	sprintf(sql_query, "SELECT filehash FROM manifests WHERE service==\"file\" AND name GLOB \"*.%s\"", filter_extension);
	return get_blob_sql_query_results(sql_query, FILEHASH_SIZE);
}

char * get_name(char *file_hash) {
	char *sql_query = malloc(1024);
	sprintf(sql_query, "SELECT name FROM manifests WHERE filehash==\"%s\"", file_hash);
	char ** query_results = get_blob_sql_query_results(sql_query, FILENAME_MAX);

  if(query_results != NULL) {
	  size_t i = 0;
	  for (i = 0; query_results[i] != NULL; ++i) {
		  WARN(query_results[i]);
	  }
  }
	return "";
}
