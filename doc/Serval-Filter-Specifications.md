# Serval Filter Specification #

In Serval you can specify three kinds of filters. All of them are controlled by the serval.conf file. To find it run the command

```
servald config paths
```
You will see a bunch of paths. To find the config follow the ETC-path.

## Announcefilters ##
The first kind of filters are announcefilters. If you set one or more of them, the mathing files won't be announced and other serval clients won't know that you have this files.
*Note 1: We have BLACKLIST semantics. That means, if a filter matches, this file will NOT be announced.*
*Note 2: The parentheses indicate the type of the field, the square brackets the represented unit and in the arrow brackets are the default values. --req indicates, that this flag is required.*

```
rhizome.filter.announcetime=(uint64_scaled) [sec] <0>
rhizome.filter.filename=(str_nonempty) [regex] <"">
rhizome.filter.maxfilesize=(uint64_scaled) [byte] <0>
rhizome.filter.private=(boolean) [bool] <false>
rhizome.filter.public=(boolean) [bool] <false>
rhizome.filter.service=(str_nonempty) [file | MeshMS2] <"">
```
With `announcetime` you can set a range, how long a file will be announced. This means if you receive a file or add one it will be announced that much seconds.

With `filename` you can specify a regular expression. If a filename matches, this file won't be announced.

`maxfilesize` will filter all files that are larger than the set size in bytes.

`private` will filter all private messages and announce only public.

`public` will filter all public messages and announce only private.

`service` will filter all messages of the given service and announce only the other services.

##### Examples #####
`rhizome.filter.announcetime=3600`: The file will be announced for one hour after adding it to the store.

`rhizome.filter.filename=.*\.jpg` will filter all files with the .jpg extension.

`rhizome.filter.maxfilesize=1024` will filter all files larger than 1 kB.

## Predownloadfilters ##
Predownloadfilters are mostly the same as announcefilters. The difference is, that you can decide whether you want to download a file or not.

```
rhizome.prefilter.filename=(str_nonempty) [regex] <"">
rhizome.prefilter.maxfilesize=(uint64_scaled) [byte] <0>
rhizome.prefilter.private=(boolean) [bool] <false>
rhizome.prefilter.public=(boolean) [bool] <false>
rhizome.prefilter.service=(str_nonempty) [file | MeshMS2] <"">
rhizome.prefilter.sender.[uint]=(sid) [sid] <000000000000000000000000000000000000000000000000000000000000000>
rhizome.prefilter.refresh_time=(uint64_scaled) [seconds] <60>
```

The rules are the same as in the announcefilters.

The only difference is the sender. Here you can set an array with sid you do not want to download. This does not mean that you won't download files from this sid, but you won't download files, if the originator of this files has this sid.

##### Examples #####
`rhizome.prefilter.filename=.*\.jpg`: No .jpg files will be downloaded.

`rhizome.prefilter.sender.[0]=CB54C16A87E832F6AC87B396A2B3484A5200C5BD2DBB587F7B88C1942DEEDA09`: No files with this sender sid will be downloaded.

## Contentfilters ##
Both, the announcefilters and the prefilters are filters, with decide on metadata like filesize. With contentfilters you have the option to filter files by content or alter it.

```
rhizome.contentfilters.[uint].author=(sid) [sid] <000000000000000000000000000000000000000000000000000000000000000> --req
rhizome.contentfilters.[uint].bin=(str_nonempty) [path/to/bin] <""> --req
rhizome.contentfilters.[uint].extensions.[uint]=(str) [file-extension] <"">
rhizome.contentfilters.[uint].match_noextension=(boolean) [bool] <false>
rhizome.contentfilters.[uint].max_size=(uint64_scaled) [max filesize] <INT64_MAX>
rhizome.contentfilters.[uint].min_size=(uint64_scaled) [min filesize] <0>
rhizome.contentfilters.[uint].regex=(str_nonempty) [regex] <"">
```

This syntax differs from the two above. Here you can not only set one value per config flag but an array of different filters. Let's explain it with an example:

```
rhizome.contentfilters.0.author=CB54C16A87E832F6AC87B396A2B3484A5200C5BD2DBB587F7B88C1942DEEDA09
rhizome.contentfilters.0.bin=path/to/bin1
(rhizome.contentfilters.0.extensions.[uint]=(str) [file-extension])
rhizome.contentfilters.0.match_noextension=true
rhizome.contentfilters.0.max_size=1024
(rhizome.contentfilters.0.min_size=(uint64_scaled) [min filesize])
(rhizome.contentfilters.0.regex=(str_nonempty) [regex])

rhizome.contentfilters.1.author=DD336BC9C49F0D0576E60DF362B9293E828E1A9E3E326D3A8BA117D0F93F66E4
rhizome.contentfilters.1.bin=path/to/bin2
rhizome.contentfilters.1.extensions.0=jpg
rhizome.contentfilters.1.extensions.1=png
(rhizome.contentfilters.1.match_noextension=(boolean) [no extension])
(rhizome.contentfilters.1.max_size=(uint64_scaled) [max filesize])
rhizome.contentfilters.1.min_size=1049000
rhizome.contentfilters.1.regex=.*IMG.*

rhizome.contentfilters.2.author=7F129D389F0E0B59F48AF5DB75FE460818CC86F5E06902303EB8BD1BBE0E3C48
rhizome.contentfilters.2.bin=path/to/bin3
```

In the example above we have defined two filters. The flags in parentheses are not set. In the real config file you would just leave them out. Instead the default values are implicit evaluated.

So, if a file has no file-extension, and is smaller than 1 kB, the binary bin1 will be executed. And if a file has the extensions jpg or png and they are at least 1 MiB large and the name contains the string "IMG", binary bin2 will be executed.

The last filter would match in every file.

### Calling and return convention ###
Your binary has to handle the following parameters:

`filepath, filename, filesize, filehash, author_sid`

Now your binary can evaluate the content of the file and decide whether the file should be announced or not. If it should, you binary has to return `1`, otherwise `0`. If something went wrong, say you expect a picture but get a sound file, and the filter could not handle the file, the binary should return `2`. Attention: in this case, the file will be announced.

If your binary would alter the file, you have to create a new one, since you have only read permissions on the file. And you have to add the new file with the following command:

```
servald rhizome add file --sender=<author_sid> <author_sid> <filepath>
```

Note: You have still to decide what to do with the old one, so you have to return `0` or `1`.
