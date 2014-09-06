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
    content [0] EXPLICIT OCTET STRING }

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
     authenticatedAttributes [0] IMPLICIT SET OF Attribute OPTIONAL,
     digestEncryptionAlgorithm AlgorithmIdentifier,
     encryptedDigest OCTET STRING}


IssuerAndSerialNumber ::= SEQUENCE {
  issuer        Name,
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
      values SET OF AnyButWantToGetItParsed}

AnyButWantToGetItParsed ::= CHOICE {
  printableString PrintableString,
  octetString OCTET STRING,
  utctime UTCTime,
  oid OBJECT IDENTIFIER}

ASN1

use Data::Dumper;
use MIME::Base64;

my $file = "MIIK2QYJKoZIhvcNAQcCoIIKyjCCCsYCAQExDjAMBggqhkiG9w0CBQUAMIIE0AYJ
KoZIhvcNAQcBoIIEwQSCBL0wggS5BgkqhkiG9w0BBwOgggSqMIIEpgIBADGCAY4w
ggGKAgEAMHIwbTELMAkGA1UEBhMCU0QxDTALBgNVBAgMBHNkZmcxDTALBgNVBAcM
BHNkZmcxDTALBgNVBAoMBHNkZmcxDTALBgNVBAsMBHNkZmcxDTALBgNVBAMMBHNk
ZmcxEzARBgkqhkiG9w0BCQEWBHNkZmcCAQEwDQYJKoZIhvcNAQEBBQAEggEAx87/
ck2VKmPSFbwLAj3zJ2WXxekJw2KHWxKqGOnPjQi6Fh7ewiy2Veae7pMN1tn94e7V
Tz1+iczpesDk+WcNFy8t148tVTIOwBSnbC2wfyMQq6OeNUaW/dXpUMVam9+LFmCy
FzlKtbU1R81aZpwO7ziRhlBwMR6rn1SQTnf+HIDqBO7md/e41damO4+3MG/IUKG3
6nIEfOaGc9mC2/p72XiLCtnHnpEKZnaKxJuNdlf82R81LhjdYemoj4GwUkE3os6v
2sAmGdMVGxAxd06+4wR9iVJIizgHs9Hw7yEhh8ATmRUFh0fMszXFNUzc5dOzURmx
VUcX7kE2Y0NfXLlhoTCCAw0GCSqGSIb3DQEHATAUBggqhkiG9w0DBwQI/VkoqAIx
zUuAggLoCJ86Khb8gX0jRM/M1/4LR81uGQFXiVFrXI1HrZESGyhXrrSA2hDLH05Q
cMbeU2DIlwXXHvvzGlewtai6vUPMpSch9R+yTSIiFIkdTAiWa+qjVwOTCUxBLIMa
0wNwZ/f0EzHB1Bvt8YUUv2SRi1vH5VoSMa5wb8HqiQVciqGZc3mMvBHrxA8GTStm
QnAWdxhVRUMPPONNRqLc9MckcZ1oT71GK3PK5HRvJLor937KlEMoNBisnk9zaUlC
XKFMMkzDrfDIOJY6ukFUoevXURfhlbLiAE37p2kPllANDdE/00m3g4usqDb+mqrp
zzNJX29Ko1xDWZsdZH1HiknmHrSlDZbQ5zUSCi2MB52S6HWVnJzQIiFcChRnGYDv
SbMbGErXLRw1ONg1om6gIVF0cQ7qxja5vn5m2KLlS0ZPNocoz+VbHjZ1pT5eZz0D
jdBU2gKtkAjd7Xid3VHizQqV08wFtD9hu2auyY4nAFuxkyq6gNcoSmzBh99KjBuy
rkHKzwnEf2BN8744f7IWOTBOfl7Edj4UP5W7YA4/HDdC5m8KqueUquoF8SaXY1Pn
pzT+ikAyst0riQ8OqHk2B/52XjHnRKQwSlRYxNXbwHAqpPS1XV6gqMlaX0wwHcUw
/uo8mgI/FH+lF2F7pnVfc+3rheeXQ73pfCnx/pbvari6MuGCxziY3wCr7W8cG5A/
C9UOTaTvld5zh+j4s8qXVUG/tJvIT0TRNYPi+NF/a2JDTJW1wkbtnR7ERyRiz33B
38f5M9eraAe78/4ehSO9sV1YGgt4x9ayYvcSn9gn6Nc+UaCvP1IN43gQ/LCYjJxM
lazYY3jHHdDzUr/f46ajBnjq80uYcebWFQ+x2uNQi6lcl6rO37DLAuBnfsqSKXgA
0lNRWfWz5FhhVC6vOsNh28Pa+Kr89StUpvflvRFF83KUo6eWMJDYeijSCXZ0uvur
x13YnNSRdyeqkfBYR0NETYAq7fi6h47jOy05Nn+roIIDUjCCA04wggI2AgEBMA0G
CSqGSIb3DQEBBQUAMG0xCzAJBgNVBAYTAlNEMQ0wCwYDVQQIDARzZGZnMQ0wCwYD
VQQHDARzZGZnMQ0wCwYDVQQKDARzZGZnMQ0wCwYDVQQLDARzZGZnMQ0wCwYDVQQD
DARzZGZnMRMwEQYJKoZIhvcNAQkBFgRzZGZnMB4XDTE0MDkwNTExMjMzMVoXDTE1
MDgyNzExMjMzMVowbTELMAkGA1UEBhMCQVMxDTALBgNVBAgMBGFzZGYxDTALBgNV
BAcMBGFzZGYxDTALBgNVBAoMBGFzZGYxDTALBgNVBAsMBGFzZGYxDTALBgNVBAMM
BGFzZGYxEzARBgkqhkiG9w0BCQEWBGFzZGYwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDWHFQuKDYAKqZxX/qmMRUue0SNxAZIylIr1ljBoWAIXGSxBYCx
4M3Ucea4/O1lYiSwxmlV5mbfMUTl7mY8RvkH76bQOmjGuvTsxcaMsE7saIqEH9Ci
/dIyRqI5ILkwt7VRLC/3BJr9ZTe8faZquYWETh+QU9z9Se0+ACWdDLEDs21sNTH0
MO2WatAyLcCU2QsOS2y4P4f19hAMU0R0zeaSP65lZ0qyDEUN00qa+QwFFdKxzWDt
TDg4Hu6S/hm1TOkt+rau03nIidwe9agD7fp9Cr/GvnqT1LS5z5s5Rxmo8KL6y6lY
XvulgO9naxIu6/Vp7jZasztLskXo7WTMMzNfAgMBAAEwDQYJKoZIhvcNAQEFBQAD
ggEBAGM/OejzFClI8iNHi4lJpMaWMfkG3/L9Xh8WEaDahjGWUiAtPwAUQmGRS6V5
DJkhZHpps3eJklOrcnFf0dwWVc0mCOED8h9uJNeZLwgT/3dai/4koHgKkxCH8s6t
ygv9mtIBtKFww/LaZpTEfGJXKdubg3Q1UrswEDDXVcI/w1n24LJlhqCjiJZkYGJe
HYgQwl+CX4VJnTJH851ty0s4XbpvGbuJfVNmoB4zC3s4fEHzSKJvNBmV4EoqVBft
UQa6ZGtBLifJoO9yi+6qDgJHsvNPBPmLRAQNvM7O2jZV0Vj+CKFmsUs9YxnMSx/f
J+0LJQkvLcEH904zdAo+6lKz+yUxggKFMIICgQIBATByMG0xCzAJBgNVBAYTAlNE
MQ0wCwYDVQQIDARzZGZnMQ0wCwYDVQQHDARzZGZnMQ0wCwYDVQQKDARzZGZnMQ0w
CwYDVQQLDARzZGZnMQ0wCwYDVQQDDARzZGZnMRMwEQYJKoZIhvcNAQkBFgRzZGZn
AgEBMAwGCCqGSIb3DQIFBQCggeYwEQYKYIZIAYb4RQEJAzEDEwEzMBIGCmCGSAGG
+EUBCQIxBBMCMTkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0B
CQUxDxcNMTQwOTA1MTEyNTMzWjAfBgkqhkiG9w0BCQQxEgQQmcCpcPQ23UWT8wVl
v38f1jAgBgpghkgBhvhFAQkFMRIEEHNTAzrHTahUOciu/GNuKRwwIAYKYIZIAYb4
RQEJBjESBBBhdVAlSA3tqobPRaGideffMCAGCmCGSAGG+EUBCQcxEhMQPfWCpb3s
+ggjzkTUFhs+3DANBgkqhkiG9w0BAQEFAASCAQAv4mzzewQ71W/yu23RP/EzWaOw
E15ygwWeizV/A8X142BI51y3IJ9V9no5XJX3s5MwZb8IO3pOk86Kwd60xUYcxYcG
QNyzdkU53CyOkpPZDbrOGbF3Drj8Vj7HOhDCH36co8AKGvXPUm0pqXJep8wyILoe
lc+6g8ULoj+0tt7dbvDnC1HnxaO0waOPCdKlBqMbEp7P3CBLcdVujgVrVXvdqEiP
beWBkzlX4WgRWHHy0/vdbmnsi1cjmFGahz1SWxOE2n1iaFa00UM93S3QfvpVtvfl
aTVB24hMhdwGN0wMTw1OTh+LWmEvwuGnheRg/8Ilp8za08oEl79iNzOxR58R";
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
my $test = $foo->decode($der) or die $asn->error;
#print Dumper($test);
my $test3 = $foo->encode($test) or die $asn->error;
my $content = $asn->find('pkiEnvMessage') or die $asn->error;
#my $test2 = $content->decode($test->{'content'}->{'contentInfo'}->{'content'}) or die $asn->error;;
#print Dumper($test->{'content'}->{'contentInfo'}->{'content'});
$test->{'content'}->{'contentInfo'}->{'content'} = $content->decode($test->{'content'}->{'contentInfo'}->{'content'}) or die $asn->error;
#$content = $asn->find('UnauthenticatedAttributes') or die $asn->error;
#my $test2 = $content->decode($test->{'content'}->{'signerInfos'}->[0]->{'unauthenticatedAttributes'}) or die $asn->error;
#print Dumper($test);
#print Dumper($test->{'content'}->{'signerInfos'});

my $i = " " x 4;
print "SCEP Message:", $/;
print $i, "Message Type: ", $test->{'content'}->{'signerInfos'}->[0]->{'authenticatedAttributes'}->[0]->{'values'}->[0]->{'printableString'} , $/; #oid check, instead of array, translation of number


print $i, "Signed Data:", $/;
print $i x 2, "Singer Info:", $/;
print $i x 3, "Serial Number: ", $test->{'content'}->{'signerInfos'}->[0]->{'issuerAndSerialNumber'}->{'serialNumber'}, $/; #hex?
my $rdn = $test->{'content'}->{'signerInfos'}->[0]->{'issuerAndSerialNumber'}->{'issuer'}; #Subject missing?
print  $i x 4, "Subject: Not implemented", $/;
print $i x 4,  "Issuer: ";
foreach (@{$rdn}) {print values $_->[0]->{'value'}, ", "}
print $/;
print $i x 2, "Signed Attributes", $/;
print $i x 3, "Message Type: ", values $test->{'content'}->{'signerInfos'}->[0]->{'authenticatedAttributes'}->[1]->{'values'}->[0], $/;
print $i x 3, "Transaction ID: ";
my $id = $test->{'content'}->{'signerInfos'}->[0]->{'authenticatedAttributes'}->[4]->{'values'}->[0];
my @values = values $id;
print unpack('H*', $values[0]), $/;
print $i x 3, "PKI Status: ", values $test->{'content'}->{'signerInfos'}->[0]->{'authenticatedAttributes'}->[0]->{'values'}->[0], $/;
@values = values $test->{'content'}->{'signerInfos'}->[0]->{'authenticatedAttributes'}->[7]->{'values'}->[0];
my $nonce = unpack('H*', $values[0]);
$nonce =~ s/..\K(?=.)/:/g;
print $i x 3, "Sender Nonce: ", $nonce, " just experimenting w/another representation, something wrong here", $/;
@values = values $test->{'content'}->{'signerInfos'}->[0]->{'authenticatedAttributes'}->[6]->{'values'}->[0];
print $i x 3, "Recipient Nonce: ", unpack('H*', $values[0]), $/;
print $i, "Enveloped Data:", $/;
print $i x 2, "Recipient Info: ", '[', $test->{'content'}->{'contentInfo'}->{'content'}->{'content'}->{'recipientInfos'}->[0]->{'version'}, "]", $/; #right?
print $i x 3, "Serial Number: ", $test->{'content'}->{'contentInfo'}->{'content'}->{'content'}->{'recipientInfos'}->[0]->{'issuerAndSerialNumber'}->{'serialNumber'}, $/;

$rdn = $test->{'content'}->{'contentInfo'}->{'content'}->{'content'}->{'recipientInfos'}->[0]->{'issuerAndSerialNumber'}->{'issuer'}; #Subject missing?
print $i x 4,  "RelativeDistinguishedName: ";
foreach (@{$rdn}) {print values $_->[0]->{'value'}, ", "}
print $/;

my $encBytes = unpack('H*', $test->{'content'}->{'contentInfo'}->{'content'}->{'content'}->{'recipientInfos'}->[0]->{'encryptedKey'});
$encBytes =~ s/..\K(?=.)/:/g;
print $i x 2, "Encrypted Bytes (DER), somehow just partially", $/, $i x 3;
print $encBytes, $/;
#print unpack('H*', $test->{'content'}->{'certificates'}->[0]);
#print $i x 2, "Encrypted: ", '[', $test->{'content'}->{'contentInfo'}->{'content'}->{'content'}->{'recipientInfos'}->[0]->{'version'}, "]", $/; #right?

#Encrypted bytes starts with the regular certificate :(
#open(my $fh, '>extract.der');
#print $fh $test->{'content'}->{'certificates'}->[0];


#################### experiments ########################
# my $asn2 = Convert::ASN1->new;
# $asn2->prepare(q<

# pkiMessage ::= SEQUENCE {
#       contentType INTEGER,
#       content [0] EXPLICIT ANY}

# >);
# my $pdu = $asn2->encode( contentType => 9, content => "string") or die $asn2->error;
#print $pdu;
 open(my $fh, '>extract3.asn');
 print $fh $test3;

 #certificates = cert.der;
 