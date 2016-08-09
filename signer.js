// A simple script to better understand AWS request signing
// http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html

/*
Authorization = "AWS" + " " + AWSAccessKeyId + ":" + Signature;

Signature = Base64( HMAC-SHA1( YourSecretAccessKeyID, UTF-8-Encoding-Of( StringToSign ) ) );

StringToSign = HTTP-Verb + "\n" +
  Content-MD5 + "\n" +
  Content-Type + "\n" +
  Date + "\n" +
  CanonicalizedAmzHeaders +
  CanonicalizedResource;

CanonicalizedResource = [ "/" + Bucket ] +
  <HTTP-Request-URI, from the protocol name up to the query string> +
  [ subresource, if present. For example "?acl", "?location", "?logging", or "?torrent"];

CanonicalizedAmzHeaders = <described below>
 */

const CryptoJS = require('crypto-js');
const AWSAccessKeyId = 'AKIAIOSFODNN7EXAMPLE';
const AWSSecretAccessKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

const request = `
PUT /db-backup.dat.gz HTTP/1.1
User-Agent: curl/7.15.5
Host: static.johnsmith.net:8080
Date: Tue, 27 Mar 2007 21:06:08 +0000

x-amz-acl: public-read
content-type: application/x-download
Content-MD5: 4gJE4saaMU4BqNR0kLY+lw==
X-Amz-Meta-ReviewedBy: joe@johnsmith.net
X-Amz-Meta-ReviewedBy: jane@johnsmith.net
X-Amz-Meta-FileChecksum: 0x02661779
X-Amz-Meta-ChecksumAlgorithm: crc32
Content-Disposition: attachment; filename=database.dat
Content-Encoding: gzip
Content-Length: 5913339
`;

const split = request.split("\n");
const first = (/^(PUT|POST|GET|DELETE) (.+) HTTP/i).exec(split[1]);

const method = first[1].toUpperCase();
var path = first[2].toLowerCase();

const headerRegex = /^([a-z\d\-]+)\:\s*(.+)/i;
const headers = {};
split.forEach(line => {
  if (line.trim() === '') {
    return;
  }

  const match = headerRegex.exec(line);
  if (match) {
    const header = match[1].toLowerCase();
    const value = match[2].trim();
    if (typeof headers[header] !== 'undefined') {
      headers[header] = headers[header] + ',' + value;
    } else {
      headers[header] = value;
    }
  }
});

path = (/^([^:]+)(:\d+)?/).exec(headers['host'].toLowerCase())[1] + path;
if (path[0] !== '/') {
  path = '/' + path;
}
delete headers['host'];

const contentType = headers['content-type'] || '';
delete headers['content-type'];

const contentMD5 = headers['content-md5'] || '';
delete headers['content-md5'];

const date = headers['date'];
delete headers['date'];

var s2s = `${method}
${contentMD5}
${contentType}
${date}
`;

Object.keys(headers)
  .sort()
  .filter(header => header.match(/^x-amz-/))
  .forEach(header => {
    s2s += header + ':' + headers[header];
    s2s += "\n";
  });

s2s += path;
//s2s += "\n";

const s2sSolution = `PUT
4gJE4saaMU4BqNR0kLY+lw==
application/x-download
Tue, 27 Mar 2007 21:06:08 +0000
x-amz-acl:public-read
x-amz-meta-checksumalgorithm:crc32
x-amz-meta-filechecksum:0x02661779
x-amz-meta-reviewedby:joe@johnsmith.net,jane@johnsmith.net
/static.johnsmith.net/db-backup.dat.gz`;

console.assert(s2s.trim() === s2sSolution.trim(), `
String to sign did not match:

Actual:
${s2s}

Expected:
${s2sSolution}
`);

const hash = CryptoJS.HmacSHA1(s2s, AWSSecretAccessKey); // UTF-8 encode s2s first!
const signature = hash.toString(CryptoJS.enc.Base64);

const authorization = `AWS ${AWSAccessKeyId}:${signature}`;
const expected = 'AWS AKIAIOSFODNN7EXAMPLE:ilyl83RwaSoYIEdixDQcA4OnAnc='

console.assert(authorization === expected, `
Not the expected signature:

Actual:
${authorization}

Expected:
${expected}
`);
