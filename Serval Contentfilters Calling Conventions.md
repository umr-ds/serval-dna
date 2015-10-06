### Serval Contentfilters Calling Conventions SC3v1 ###

- Don't modify files, provided in argv$2
- Return value as supposed by POSIX Standard:
	0: match (file is not annouced afterwards)
	1: mismatch (file is still announced)
	2: error matching (eg. grep on a binary file)
	
args:

0: binary name (by convention)
1: path to file content
2: orginal filename
3: filesize (bytes)
4: filehash (hex characters)
5: own SID (hex characters) - only if defined in rhizome.contentfilters.sid=...