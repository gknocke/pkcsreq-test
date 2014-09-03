use strict;
use warnings;
use Convert::ASN1;
use MIME::Base64;
use Data::Dumper;
$Data::Dumper::Useqq = 1;
my $asn = Convert::ASN1->new();


$asn->prepare(<<ASN1);
pkiMessage ::= SEQUENCE {
      contentType OBJECT IDENTIFIER,
      content [0] EXPLICIT pkcsCertReqSigned}

pkcsCertReqSigned ::= SEQUENCE {
     version INTEGER,
     digestAlgorithms DigestAlgorithmIdentifiers,
     contentInfo ContentInfo,
     certificates [0] SET OF Certificate,
     signerInfos SET OF signerInfo}

Certificate ::= ANY --todo?

DigestAlgorithmIdentifiers ::= SET OF AlgorithmIdentifier

AlgorithmIdentifier ::= SEQUENCE {
      algorithm  OBJECT IDENTIFIER,
      parameters ANY DEFINED BY algorithm OPTIONAL}

ContentInfo ::= SEQUENCE {
    contentType OBJECT IDENTIFIER,
    content [0] EXPLICIT OCTET STRING } --pkcsCertReqEnvelope TODO

-- Enveloped information portion
pkiEnvMessage ::= SEQUENCE {
      contentType OBJECT IDENTIFIER,
      content [0] EXPLICIT pkcsCertReqEnvelope}

pkcsCertReqEnvelope ::= SEQUENCE {   -- PKCS#7
    version INTEGER,
    recipientInfos RecipientInfos,
    encryptedContentInfo EncryptedContentInfo}

RecipientInfos ::= SET OF RecipientInfo

RecipientInfo ::= SEQUENCE {
  version INTEGER,
  issuerAndSerialNumber IssuerAndSerialNumber,
  keyEncryptionAlgorithm  AlgorithmIdentifier,
  encryptedKey OCTET STRING}

EncryptedContentInfo ::= SEQUENCE {
    contentType OBJECT IDENTIFIER,
    contentEncryptionAlgorithm  AlgorithmIdentifier,
    encryptedContent  [0] OCTET STRING} 

signerInfo ::= SEQUENCE {
     version INTEGER,
     issuerAndSerialNumber IssuerAndSerialNumber,
     digestAlgorithm AlgorithmIdentifier,
     authenticatedAttributes [0] ANY OPTIONAL, --should be here but isn't
     digestEncryptionAlgorithm [0] SET OF AlgorithmIdentifier,
     encryptedDigest ANY, --todo?
     unauthenticatedAttributes OCTET STRING} --todo


IssuerAndSerialNumber ::= SEQUENCE {
  issuer        Name, --todo
  serialNumber  INTEGER}

Name ::= SEQUENCE OF RelativeDistinguishedName

RelativeDistinguishedName ::= SET OF AttributeTypeAndValue

AttributeTypeAndValue ::= SEQUENCE {
      type  OBJECT IDENTIFIER,
      value DirectoryString}

DirectoryString ::= CHOICE {
  teletexString   TeletexString,
  printableString PrintableString,
  bmpString       BMPString,
  universalString UniversalString,
  utf8String      UTF8String,
  ia5String       IA5String,
  integer         INTEGER}

Attribute ::= SEQUENCE {
      type   OBJECT IDENTIFIER,
      values SET OF ANY}

ASN1

use Data::Dumper;
use MIME::Base64;

my $file = "MIIKlQYJKoZIhvcNAQcCoIIKhjCCCoICAQExDjAMBggqhkiG9w0CBQUAMIIDKwYJ
KoZIhvcNAQcBoIIDHASCAxgwggMUBgkqhkiG9w0BBwOgggMFMIIDAQIBADGCAREw
ggENAgEAMHYwcTELMAkGA1UEBhMCSVQxGDAWBgNVBAoTD0hhY2ttYXN0ZXJzLm5l
dDEgMB4GA1UEAxMXQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxJjAkBgkqhkiG9w0B
CQEWF3N1cHBvcnRAaGFja21hc3RlcnMubmV0AgEDMA0GCSqGSIb3DQEBAQUABIGA
iXIJtDebJo4KjuHB9I5nSSR0Clhgs/Iuq0SrLKkLjWVUs3bRujLxel/3Uovx8ckX
PLoW2Fm6DrB7d1o1PKY87xf0SZQDqCpTBEXH/G8QVUm8LSbA2nEAFLrZNukh+VNn
DFPs8gcc3df+3BoNRGJQQFsLn//PWJXIV8Ypysrcbs8wggHlBgkqhkiG9w0BBwEw
FAYIKoZIhvcNAwcECPMatPl5jpwjgIIBwALAkH68fv72SX6S/g4B1ydYVqT/7934
O2eSbbVWhgiXnDc8lafywU52EA6lFKZQnMp3tV9THcj9YnLQ3HeO9+ReiPemnrcC
JbDcDJ5Lez0MW/zwtdrHy+5wSY13rYKaRdPrEUIxDwbxfCb0qLGaECW4EXIaZAsm
o70hNXWupaWyShCTFBzNa+jMPh5twn69G4kyHvDjDBRyRv2CcTReKZKtc9YnkTg5
1LuA+N9DCq3KeeUO+CLZORaI2FoIRKjqP4jxVVL8V8ss+mI8KBn4kayQ0lcAjTw+
z5I8kORJhajZnhJ9mhBO5foRu/nJ0NNif2ms91XI2rUYTXn/WFmEA6sKe6LeWFwW
GidlpfANGTlSvmFkBKCINUp+cBjP6AIopEx0lK/J3a7g8pa0sozSZLxpVjIFVFJ4
aujTCg7hlJLl1dPNEI3mst3D6i6P+7bx5czdY8fIfz0WJjxYIs4Zn6b/+ZqVFAml
j+Rp4CtNlsQUYYtd6THoI6x0SRcI021EWLs0MOtPHuZrCTwxVmBH5EhDYAB8uIKm
yiAIoSyLuoG6aKlFgQD+QD13kkUavaDeXzEuwVDn1yL2zQMWtVxkugWgggVDMIIF
PzCCBCegAwIBAgIBAzANBgkqhkiG9w0BAQUFADBxMQswCQYDVQQGEwJJVDEYMBYG
A1UEChMPSGFja21hc3RlcnMubmV0MSAwHgYDVQQDExdDZXJ0aWZpY2F0aW9uIEF1
dGhvcml0eTEmMCQGCSqGSIb3DQEJARYXc3VwcG9ydEBoYWNrbWFzdGVycy5uZXQw
HhcNMDIxMDE3MTE1MTI2WhcNMDMxMDE3MTE1MTI2WjBiMQswCQYDVQQGEwJJVDEY
MBYGA1UEChMPSGFja21hc3RlcnMubmV0MREwDwYDVQQLEwhJbnRlcm5ldDEaMBgG
A1UEAxMRTWFzc2ltaWxpYW5vIFBhbGExCjAIBgNVBAUTATMwgZ8wDQYJKoZIhvcN
AQEBBQADgY0AMIGJAoGBAL32+HnotLHNCjVE6fvZC5ZhtLnQiOKDPLZxwKXgYqeg
Xz9O0u7pLG7sRAa4KssktND1idpiT4b2lMa7zmGCNejkAJdUDv3caxBZ+KUng0cu
Gp82rl5WSlsEA6O24DEdLj5KTsmZ2mXt+JqtPKf9lZyNhe+7CSyOcUkbmN1boYav
AgMBAAGjggJzMIICbzAJBgNVHRMEAjAAMBEGCWCGSAGG+EIBAQQEAwIFoDALBgNV
HQ8EBAMCBeAwKQYDVR0lBCIwIAYIKwYBBQUHAwIGCCsGAQUFBwMEBgorBgEEAYI3
FAICMDIGCWCGSAGG+EIBDQQlFiNVc2VyIENlcnRpZmljYXRlIG9mIEhhY2ttYXN0
ZXJzLm5ldDAdBgNVHQ4EFgQUixrMvf4gJbyrLTjJa5ntcx3lF9QwgZsGA1UdIwSB
kzCBkIAUeOhMo5xx6+Ej5uq8Mm6Z3vgDk9KhdaRzMHExCzAJBgNVBAYTAklUMRgw
FgYDVQQKEw9IYWNrbWFzdGVycy5uZXQxIDAeBgNVBAMTF0NlcnRpZmljYXRpb24g
QXV0aG9yaXR5MSYwJAYJKoZIhvcNAQkBFhdzdXBwb3J0QGhhY2ttYXN0ZXJzLm5l
dIIBADAiBgNVHREEGzAZgRdtYWR3b2xmQGhhY2ttYXN0ZXJzLm5ldDAiBgNVHRIE
GzAZgRdzdXBwb3J0QGhhY2ttYXN0ZXJzLm5ldDBIBglghkgBhvhCAQQEOxY5aHR0
cHM6Ly9nYWxhZHJpZWwubXBuZXQuaGFja21hc3RlcnMubmV0L3B1Yi9jcmwvY2Fj
cmwuY3JsMEgGCWCGSAGG+EIBAwQ7FjlodHRwczovL2dhbGFkcmllbC5tcG5ldC5o
YWNrbWFzdGVycy5uZXQvcHViL2NybC9jYWNybC5jcmwwSgYDVR0fBEMwQTA/oD2g
O4Y5aHR0cHM6Ly9nYWxhZHJpZWwubXBuZXQuaGFja21hc3RlcnMubmV0L3B1Yi9j
cmwvY2FjcmwuY3JsMA0GCSqGSIb3DQEBBQUAA4IBAQC5zD96LzO5IW8nqXlF55UP
vPZfGJC8STr1rZOiRA+VTDXaFs5De/xbAkxEjfxEmlFRGmttuboDpbp2IpXeINAu
ctPjZX+qEBG3crYTZIxvr0F0PIpV+iLfSAWJERUHjZedKw9iKdYoBcq+Uty74cku
Sd2VP8x2oVemyyhO08k2YDX1NY325b93XgsTtxAy8NWkNIouhPByjfTwF+uW2dRX
vwgGN/oFDIQ+y0ZPow46uNfhni124meQHr8LuTODIBQBd4Sez7r7qMsrk3LuKF9G
F/JWGUKuWOHL61Ox2un555or0S92eTaGCfugCmU8KhvvWVlhdN1TEtVYN058b19n
MYIB9TCCAfECAQEwdjBxMQswCQYDVQQGEwJJVDEYMBYGA1UEChMPSGFja21hc3Rl
cnMubmV0MSAwHgYDVQQDExdDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEmMCQGCSqG
SIb3DQEJARYXc3VwcG9ydEBoYWNrbWFzdGVycy5uZXQCAQMwDAYIKoZIhvcNAgUF
AKCB0zASBgpghkgBhvhFAQkCMQQTAjE5MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
BwEwHAYJKoZIhvcNAQkFMQ8XDTE0MDgyOTExMTgzNVowHwYJKoZIhvcNAQkEMRIE
ELwBkNZBa9NWCzSBTM8xraowIAYKYIZIAYb4RQEJBTESBBBQ5uu9psBrchbwf5qx
AsQHMCAGCmCGSAGG+EUBCQYxEgQQAhzI8R+H7TVZOYYFI9BZJjAgBgpghkgBhvhF
AQkHMRITEJM4v9FmRY2TP3OMBssKT2swDQYJKoZIhvcNAQEBBQAEgYBfBh5zve69
yLrDS17ZyicsOgbDy3vJqBtgTm17RHNVRRIOoibI5yu/8kbPhihzLXlXnoZ/xiTk
kV6So6eRqMhQUO/WkI88JzH3BkV+c0+g5UAQhKakPwG9zccy7j/jT293NCg2Plzm
K7NAXlkXy9ecoZWF70lFyfPnjpbw8IuadA==";
my $der = decode_base64($file);
#open( FILE, '>>data.txt');
#print FILE $der;
      # my $data=Test->new($der) or die;
      # #print $data->{'content'};
      # print Dumper($data);
      # $data->{'signedData'} = delete $data->{'content'} if delete $data->{'contentType'} eq '1.2.840.113549.1.7.2'; # pkcs7 signed data
      # $data->{'signedData'}->{'digestAlgorithm'} = $data->{'signedData'}->{'digestAlgorithms'}->[0]->{'algorithm'}; # hash algorithm
      # delete $data->{'signedData'}->{'digestAlgorithms'}; #cleanup
      # $data->{'signedData'}->{'signerInfo'} = $data->{'signedData'}->{'signerInfos'}->[0];
      # delete $data->{'signedData'}->{'signerInfos'};
      # $data->{'signedData'}->{'certificate'} = delete $data->{'signedData'}->{'certificate'}->[0];

      # #print Dumper($data);
      # my $enveloped = $data->{'signedData'}->{'contentInfo'}->{'content'};
      # my $node = $asn->find('ContentInfo');
      # my $ds = $node->decode($enveloped);
      # $node =  $asn->find('EnvelopedData') if $ds->{'contentType'} eq '1.2.840.113549.1.7.3';
      # $ds = $node->decode($ds->{'content'}) or die;
      # #print Dumper($ds);


my $foo = $asn->find('pkiMessage') or die $asn->error;
my $test = $foo->decode($der) or die $asn->error;;
#print Dumper($test);
my $content = $asn->find('pkiEnvMessage') or die $asn->error;
#my $test2 = $content->decode($test->{'content'}->{'contentInfo'}->{'content'}) or die $asn->error;;
#print Dumper($test->{'content'}->{'contentInfo'}->{'content'});
$test->{'content'}->{'contentInfo'}->{'content'} = $content->decode($test->{'content'}->{'contentInfo'}->{'content'}) or die $asn->error;
#$content = $asn->find('UnauthenticatedAttributes') or die $asn->error;
#my $test2 = $content->decode($test->{'content'}->{'signerInfos'}->[0]->{'unauthenticatedAttributes'}) or die $asn->error;
print Dumper($test);
#print Dumper($test->{'content'}->{'signerInfos'});