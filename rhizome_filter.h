/*
 * rhizome_filter.h
 *
 *  Created on: 02.09.2015
 *      Author: ruby
 */

#ifndef RHIZOME_FILTER_H_
#define RHIZOME_FILTER_H_

char ** get_all_files();
char ** get_extension_files(char *filter_extension);
char * get_name(char *file_hash);

#endif /* RHIZOME_FILTER_H_ */
