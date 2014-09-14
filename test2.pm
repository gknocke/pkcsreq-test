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
    content [0] EXPLICIT OCTET STRING OPTIONAL} --optional because this is what we want to add

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
     authenticatedAttributes [0] IMPLICIT SET OF Attribute OPTIONAL, --openssl 4, real live 8 (5x scep attrs missing vs 1 x smime capabilities missing)
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
  oid OBJECT IDENTIFIER,
  ...} --added because i dont care about smimecapabilities 

ASN1

use Data::Dumper;
use MIME::Base64;

#this is signed message w/o message
my $file1 = "MIIGAAYJKoZIhvcNAQcCoIIF8TCCBe0CAQExDjAMBggqhkiG9w0CBQUAMAsGCSqG
SIb3DQEHAaCCA1IwggNOMIICNgIBATANBgkqhkiG9w0BAQUFADBtMQswCQYDVQQG
EwJTRDENMAsGA1UECAwEc2RmZzENMAsGA1UEBwwEc2RmZzENMAsGA1UECgwEc2Rm
ZzENMAsGA1UECwwEc2RmZzENMAsGA1UEAwwEc2RmZzETMBEGCSqGSIb3DQEJARYE
c2RmZzAeFw0xNDA5MDUxMTIzMzFaFw0xNTA4MjcxMTIzMzFaMG0xCzAJBgNVBAYT
AkFTMQ0wCwYDVQQIDARhc2RmMQ0wCwYDVQQHDARhc2RmMQ0wCwYDVQQKDARhc2Rm
MQ0wCwYDVQQLDARhc2RmMQ0wCwYDVQQDDARhc2RmMRMwEQYJKoZIhvcNAQkBFgRh
c2RmMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1hxULig2ACqmcV/6
pjEVLntEjcQGSMpSK9ZYwaFgCFxksQWAseDN1HHmuPztZWIksMZpVeZm3zFE5e5m
PEb5B++m0Dpoxrr07MXGjLBO7GiKhB/Qov3SMkaiOSC5MLe1USwv9wSa/WU3vH2m
armFhE4fkFPc/UntPgAlnQyxA7NtbDUx9DDtlmrQMi3AlNkLDktsuD+H9fYQDFNE
dM3mkj+uZWdKsgxFDdNKmvkMBRXSsc1g7Uw4OB7ukv4ZtUzpLfq2rtN5yIncHvWo
A+36fQq/xr56k9S0uc+bOUcZqPCi+supWF77pYDvZ2sSLuv1ae42WrM7S7JF6O1k
zDMzXwIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBjPzno8xQpSPIjR4uJSaTGljH5
Bt/y/V4fFhGg2oYxllIgLT8AFEJhkUuleQyZIWR6abN3iZJTq3JxX9HcFlXNJgjh
A/IfbiTXmS8IE/93Wov+JKB4CpMQh/LOrcoL/ZrSAbShcMPy2maUxHxiVynbm4N0
NVK7MBAw11XCP8NZ9uCyZYago4iWZGBiXh2IEMJfgl+FSZ0yR/OdbctLOF26bxm7
iX1TZqAeMwt7OHxB80iibzQZleBKKlQX7VEGumRrQS4nyaDvcovuqg4CR7LzTwT5
i0QEDbzOzto2VdFY/gihZrFLPWMZzEsf3yftCyUJLy3BB/dOM3QKPupSs/slMYIC
czCCAm8CAQEwcjBtMQswCQYDVQQGEwJTRDENMAsGA1UECAwEc2RmZzENMAsGA1UE
BwwEc2RmZzENMAsGA1UECgwEc2RmZzENMAsGA1UECwwEc2RmZzENMAsGA1UEAwwE
c2RmZzETMBEGCSqGSIb3DQEJARYEc2RmZwIBATAMBggqhkiG9w0CBQUAoIHUMBgG
CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE0MDkxNDE1
NDYwNlowHwYJKoZIhvcNAQkEMRIEEI8x8ps/NVj2Z9ZYONIVGywweQYJKoZIhvcN
AQkPMWwwajALBglghkgBZQMEASowCwYJYIZIAWUDBAEWMAsGCWCGSAFlAwQBAjAK
BggqhkiG9w0DBzAOBggqhkiG9w0DAgICAIAwDQYIKoZIhvcNAwICAUAwBwYFKw4D
AgcwDQYIKoZIhvcNAwICASgwDQYJKoZIhvcNAQEBBQAEggEAJ5F+KttOKAzZIFEP
NTRtlj9TX0+ImYrbxd//63hMTmzI1vE5GO/C1nl1RjSFSg7EI2NjI8EQoglWX87Y
FDLHNJMyG9bmylE8DRUCW6RfU60wuAAORMj09UsXYVsPzgIdi9CX3CAzlBVoh4bS
R5CHm3AQJ/2dNmsh+2q9aIci4lRUCOA7cao6FVJJ7Zm4admUYXMKyUyeDVhVdp3W
U3rIpTalAyNvd9sgVn67GL+unzivb2yjABHmI2PzB/NRc6u4JNS+z2H53xNLWBsN
WSOMtY38wh3KySYYCkYXrb95uIKz2KOwh5kte29C6YnnZOSmvuVi/oyKpvHzPVYp
ZujdcA==
";
my $der = decode_base64($file1);

#this is the encrypted pkcs7 message
my $file2 = "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";

my $der2 = decode_base64($file2);
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

      # #print Dumper($data);encod
      # my $enveloped = $data->{'signedData'}->{'contentInfo'}->{'content'};
      # my $node = $asn->find('ContentInfo');
      # my $ds = $node->decode($enveloped);
      # $node =  $asn->find('EnvelopedData') if $ds->{'contentType'} eq '1.2.840.113549.1.7.3';
      # $ds = $node->decode($ds->{'content'}) or die;
      # #print Dumper($ds);


my $foo = $asn->find('pkiMessage') or die $asn->error; #signed message
my $foo2 = $asn->find('pkiEnvMessage') or die $asn->error; #encrypted message
my $test = $foo->decode($der) or die;
#my $test2 = $foo2->decode($der2) or die;
        $test->{'content'}->{'contentInfo'}->{'content'} = $der2; # merge to one message
        #print Dumper($test);
        delete $test->{'content'}->{'signerInfos'}->[0]->{'authenticatedAttributes'}->[3]; #ugly, removes smime crap from openssl
        
        use Tie::IxHash;

        #set status to "pending" this is indicated with 3
        my @values1;
        $values1[0] = {"printableString" => "3"};

        tie my %ds1, 'Tie::IxHash';
        $ds1{"values"} = \@values1;
        $ds1{"type"} = "2.16.840.1.113733.1.9.3";
        splice $test->{'content'}->{'signerInfos'}->[0]->{'authenticatedAttributes'}, 0, 0, \%ds1;
        
        #set message type to PKCSreq
        my @values2;
        $values2[0] = {"printableString" => "19"};
        tie my %ds2, 'Tie::IxHash';
        $ds2{"values"} = \@values2;
        $ds2{"type"} = "2.16.840.1.113733.1.9.2";
        splice $test->{'content'}->{'signerInfos'}->[0]->{'authenticatedAttributes'}, 1, 0, \%ds2;

        #set 16 Byte sender nonce, obviously a static variable for testing purposes for now
        my @values3;
        $values3[0] = {"octetString" => pack('H*', "8F31F29B3F3558F667D65838D2151B2C")};
        tie my %ds3, 'Tie::IxHash';
        $ds3{"values"} = \@values3;
        $ds3{"type"} = "2.16.840.1.113733.1.9.5";
        splice $test->{'content'}->{'signerInfos'}->[0]->{'authenticatedAttributes'}, 5, 0, \%ds3;

        #set 16 Byte recipient nonce, obviously a static variable for testing purposes for now
        my @values4;
        $values4[0] = {"octetString" => pack('H*', "4D650370D48ED8D59F819A68DA5FE2DF")};
        tie my %ds4, 'Tie::IxHash';
        $ds4{"values"} = \@values4;
        $ds4{"type"} = "2.16.840.1.113733.1.9.6";
        splice $test->{'content'}->{'signerInfos'}->[0]->{'authenticatedAttributes'}, 6, 0, \%ds4;

         #set 16 Byte transaction ID, obviously a static variable for testing purposes for now
        my @values5;
        $values5[0] = {"printableString" => pack('H*', "D93C711405ECBFD12C257355F76E8343")};
        tie my %ds5, 'Tie::IxHash';
        $ds5{"values"} = \@values5;
        $ds5{"type"} = "2.16.840.1.113733.1.9.7";
        splice $test->{'content'}->{'signerInfos'}->[0]->{'authenticatedAttributes'}, 7, 0, \%ds5;


       print Dumper($test->{'content'}->{'signerInfos'}->[0]->{'authenticatedAttributes'});
        #print %{$test2};
       
my $test3 = $foo->encode($test) or die $asn->error;    # ds back to asn1
my $output = encode_base64($test3);
print $output;

        #print Dumper($test->{'content'}->{'contentInfo'})
        # my $test3 = $foo->encode($test) or die $asn->error;
        # my $content = $asn->find('pkiEnvMessage') or die $asn->error;
        # #my $test2 = $content->decode($test->{'content'}->{'contentInfo'}->{'content'}) or die $asn->error;;
        # #print Dumper($test->{'content'}->{'contentInfo'}->{'content'});
        # $test->{'content'}->{'contentInfo'}->{'content'} = $content->decode($test->{'content'}->{'contentInfo'}->{'content'}) or die $asn->error;
        # #$content = $asn->find('UnauthenticatedAttributes') or die $asn->error;
        # #my $test2 = $content->decode($test->{'content'}->{'signerInfos'}->[0]->{'unauthenticatedAttributes'}) or die $asn->error;
        # print Dumper($test);
        # #print Dumper($test->{'content'}->{'signerInfos'});

        # my $i = " " x 4;
        # print "SCEP Message:", $/;
        # print $i, "Message Type: ", $test->{'content'}->{'signerInfos'}->[0]->{'authenticatedAttributes'}->[0]->{'values'}->[0]->{'printableString'} , $/; #oid check, instead of array, translation of number


        # print $i, "Signed Data:", $/;
        # print $i x 2, "Singer Info:", $/;
        # print $i x 3, "Serial Number: ", $test->{'content'}->{'signerInfos'}->[0]->{'issuerAndSerialNumber'}->{'serialNumber'}, $/; #hex?
        # my $rdn = $test->{'content'}->{'signerInfos'}->[0]->{'issuerAndSerialNumber'}->{'issuer'}; #Subject missing?
        # print  $i x 4, "Subject: Not implemented", $/;
        # print $i x 4,  "Issuer: ";
        # foreach (@{$rdn}) {print values $_->[0]->{'value'}, ", "}
        # print $/;
        # print $i x 2, "Signed Attributes", $/;
        # print $i x 3, "Message Type: ", values $test->{'content'}->{'signerInfos'}->[0]->{'authenticatedAttributes'}->[1]->{'values'}->[0], $/;
        # print $i x 3, "Transaction ID: ";
        # my $id = $test->{'content'}->{'signerInfos'}->[0]->{'authenticatedAttributes'}->[4]->{'values'}->[0];
        # my @values = values $id;
        # print unpack('H*', $values[0]), $/;
        # print $i x 3, "PKI Status: ", values $test->{'content'}->{'signerInfos'}->[0]->{'authenticatedAttributes'}->[0]->{'values'}->[0], $/;
        # @values = values $test->{'content'}->{'signerInfos'}->[0]->{'authenticatedAttributes'}->[7]->{'values'}->[0];
        # my $nonce = unpack('H*', $values[0]);
        # $nonce =~ s/..\K(?=.)/:/g;
        # print $i x 3, "Sender Nonce: ", $nonce, " just experimenting w/another representation, something wrong here", $/;
        # @values = values $test->{'content'}->{'signerInfos'}->[0]->{'authenticatedAttributes'}->[6]->{'values'}->[0];
        # print $i x 3, "Recipient Nonce: ", unpack('H*', $values[0]), $/;
        # print $i, "Enveloped Data:", $/;
        # print $i x 2, "Recipient Info: ", '[', $test->{'content'}->{'contentInfo'}->{'content'}->{'content'}->{'recipientInfos'}->[0]->{'version'}, "]", $/; #right?
        # print $i x 3, "Serial Number: ", $test->{'content'}->{'contentInfo'}->{'content'}->{'content'}->{'recipientInfos'}->[0]->{'issuerAndSerialNumber'}->{'serialNumber'}, $/;

        # $rdn = $test->{'content'}->{'contentInfo'}->{'content'}->{'content'}->{'recipientInfos'}->[0]->{'issuerAndSerialNumber'}->{'issuer'}; #Subject missing?
        # print $i x 4,  "RelativeDistinguishedName: ";
        # foreach (@{$rdn}) {print values $_->[0]->{'value'}, ", "}
        # print $/;

        # my $encBytes = unpack('H*', $test->{'content'}->{'contentInfo'}->{'content'}->{'content'}->{'recipientInfos'}->[0]->{'encryptedKey'});
        # $encBytes =~ s/..\K(?=.)/:/g;
        # print $i x 2, "Encrypted Bytes (DER), somehow just partially", $/, $i x 3;
        # print $encBytes, $/;
        # #print unpack('H*', $test->{'content'}->{'certificates'}->[0]);
        # #print $i x 2, "Encrypted: ", '[', $test->{'content'}->{'contentInfo'}->{'content'}->{'content'}->{'recipientInfos'}->[0]->{'version'}, "]", $/; #right?

        # #Encrypted bytes starts with the regular certificate :(
        # #open(my $fh, '>extract.der');
        # #print $fh $test->{'content'}->{'certificates'}->[0];


        # #################### experiments ########################
        # # my $asn2 = Convert::ASN1->new;
        # # $asn2->prepare(q<

        # # pkiMessage ::= SEQUENCE {
        # #       contentType INTEGER,
        # #       content [0] EXPLICIT ANY}

        # # >);
        # # my $pdu = $asn2->encode( contentType => 9, content => "string") or die $asn2->error;
        # #print $pdu;
        #  open(my $fh, '>extract4.asn');
        #  print $fh $test->{'content'}->{'contentInfo'}->{'content'};

        #  #certificates = cert.der;