if (typeof require === "function") {var asn1 = require('./asn1');var utils = require('./Utils');var ByteArray = require('pp-bytearray');}

var pki = {};
var x509 = pki.x509 = {};
var pkcs6 = pki.pkcs6 = {};
var pkcs7 = pki.pkcs7 = {};
var oids = pki.oids = {};

x509.CERT_VERSION_V1 = 0;
x509.CERT_VERSION_V2 = 1;
x509.CERT_VERSION_V3 = 2;

oids = {
    PKCS7_DATA: '1.2.840.113549.1.7.1',
    PKCS7_SIGNED_DATA: '1.2.840.113549.1.7.2',
};

x509.AlgorithmIdentifier = (function() {
    "use strict";

    function AlgorithmIdentifier() {
        asn1.der.Constructive.apply(this, arguments);
    
        this.algorithm = new asn1.der.Primitive({
            tag: asn1.der.TAG_VALUE_OBJECT_IDENTIFIER
        });
        this.parameters = new asn1.der.Primitive({
            tag: asn1.der.TAG_VALUE_NULL
        });

        // 加入到elements中
        this.elements.push(this.algorithm);
        this.elements.push(this.parameters);
    }

    utils.extend(AlgorithmIdentifier, asn1.der.Constructive);

    AlgorithmIdentifier.prototype.toJson = function() {
        return {algorithm: this.algorithm.value, parameters: this.parameters.toJson()};
    };

    return AlgorithmIdentifier;
})();

x509.AttributeTypeAndValue = (function() {
    "use strict";
    
    function AttributeTypeAndValue() {
        asn1.der.Constructive.apply(this, arguments);

        this.type = new asn1.der.Primitive({
            tag: asn1.der.TAG_VALUE_OBJECT_IDENTIFIER
        });
        this.value = new asn1.der.Primitive();

        // 加入到elements中
        this.elements.push(this.type);
        this.elements.push(this.value);
    }

    utils.extend(AttributeTypeAndValue, asn1.der.Constructive);

    AttributeTypeAndValue.prototype.toJson = function() {
        return {type: this.type.value, parameters: this.value.value};
    };

    return AttributeTypeAndValue;
})();

x509.RelativeDistinguishedName = (function() {
    "use strict";

    function RelativeDistinguishedName() {
        asn1.der.Constructive.apply(this, arguments);

        this.attributes = new asn1.der.Set({
            elementCreator: function() {return new x509.AttributeTypeAndValue();}
        });

        // 加入到elements中
        this.elements.push(this.attributes);
    }

    utils.extend(RelativeDistinguishedName, asn1.der.Constructive);

    RelativeDistinguishedName.prototype.toJson = function() {
        return this.attributes.toJson();
    };

    return RelativeDistinguishedName;
})();

x509.Validity = (function() {
    "use strict";

    function Validity() {
        asn1.der.Constructive.apply(this, arguments);

        this.notBefore = new asn1.der.Primitive({
            tag: asn1.der.TAG_VALUE_UTC_TIME
        });
        this.notAfter = new asn1.der.Primitive({
            tag: asn1.der.TAG_VALUE_UTC_TIME
        });

        // 加入到elements中
        this.elements.push(this.notBefore);
        this.elements.push(this.notAfter);
    }

    utils.extend(Validity, asn1.der.Constructive);

    Validity.prototype.encode = function(baBuf) {
        asn1.der.updateUtcTime(this.notBefore);
        asn1.der.updateUtcTime(this.notAfter);
        asn1.der.Constructive.prototype.encode.call(this, baBuf);
    };

    Validity.prototype.toJson = function() {
        return {notBefore: this.notBefore.value, notAfter: this.notAfter.value};
    };

    return Validity;
})();

x509.SubjectPublicKeyInfo = (function() {
    "use strict";

    function SubjectPublicKeyInfo() {
        asn1.der.Constructive.apply(this, arguments);

        this.algorithm = new x509.AlgorithmIdentifier();
        this.subjectPublicKey = new asn1.der.Primitive({
            tag: asn1.der.TAG_VALUE_BIT_STRING
        });

        // 加入到elements中
        this.elements.push(this.algorithm);
        this.elements.push(this.subjectPublicKey);
    }

    utils.extend(SubjectPublicKeyInfo, asn1.der.Constructive);

    SubjectPublicKeyInfo.prototype.toJson = function() {
        return {algorithm: this.algorithm.toJson(), subjectPublicKey: asn1.der.toHex(this.subjectPublicKey.value)};
    };

    return SubjectPublicKeyInfo;
})();

x509.Extension = (function() {
    "use strict";

    function Extension() {
        asn1.der.Constructive.apply(this, arguments);

        this.extnID = new asn1.der.Primitive({
            tag: asn1.der.TAG_VALUE_OBJECT_IDENTIFIER
        });
        this.critical = new asn1.der.Primitive({
            tag: asn1.der.TAG_VALUE_BOOLEAN,
            optional: true,
            present: false,
            value: false
        });
        this.extnValue = new asn1.der.Primitive({
            tag: asn1.der.TAG_VALUE_OCTET_STRING
        });

        // 加入到elements中
        this.elements.push(this.extnID);
        this.elements.push(this.critical);
        this.elements.push(this.extnValue);
    }

    utils.extend(Extension, asn1.der.Constructive);

    Extension.prototype.toJson = function() {
        return {extnID: this.extnID.value, critical: this.critical.value, extnValue: asn1.der.toHex(this.extnValue.value)};
    };

    return Extension;
})();

x509.Extensions = (function() {
    "use strict";

    function Extensions() {
        asn1.der.Constructive.apply(this, arguments);

        this.extensions = new asn1.der.Set({
            elementCreator: function() {return new x509.Extension();},
            sequence: true
        });

        // 加入到elements中
        this.elements.push(this.extensions);
    }

    utils.extend(Extensions, asn1.der.Constructive);

    Extensions.prototype.toJson = function() {
        return this.extensions.toJson();
    };

    return Extensions;
})();

x509.TBSCertificate = (function() {
    "use strict";
    
    function TBSCertificate() {
        asn1.der.Constructive.apply(this, arguments);

        this.version = new asn1.der.Primitive({
            tag: {
                tagType: asn1.der.TAG_TYPE_EXPLICIT,
                value: asn1.der.TAG_VALUE_INTEGER
            },
            value: x509.CERT_VERSION_V3,
            explicitTag: new asn1.der.Tag({
                class: asn1.der.CLASS_CONTEXT_SPECIFIC,
                type: asn1.der.TYPE_CONSTRUCTED,
                value: 0
            })
        });
        this.serialNumber = new asn1.der.Primitive({
            tag: asn1.der.TAG_VALUE_INTEGER
        });
        this.signature = new x509.AlgorithmIdentifier();
        this.issuer = new x509.RelativeDistinguishedName();
        this.validity = new x509.Validity();
        this.subject = new x509.RelativeDistinguishedName();
        this.subjectPublicKeyInfo = new x509.SubjectPublicKeyInfo();
        this.issuerUniqueID = new asn1.der.Primitive({
            tag: {
                value: asn1.der.TAG_VALUE_BIT_STRING,
                tagValue: 1,
                tagType: asn1.der.TAG_TYPE_IMPLICIT
            },
            optional: true
        });
        this.subjectUniqueID = new asn1.der.Primitive({
            tag: {
                value: asn1.der.TAG_VALUE_BIT_STRING,
                tagValue: 2,
                tagType: asn1.der.TAG_TYPE_IMPLICIT
            },
            optional: true
        });
        this.extensions = new x509.Extensions({
            tag: {
                class: asn1.der.CLASS_UNIVERSAL,
                type: asn1.der.TYPE_CONSTRUCTED,
                value: asn1.der.TAG_VALUE_SEQUENCE,
                tagType: asn1.der.TAG_TYPE_EXPLICIT
            },
            explicitTag: new asn1.der.Tag({
                class: asn1.der.CLASS_CONTEXT_SPECIFIC,
                type: asn1.der.TYPE_CONSTRUCTED,
                value: 3
            }),
            optional: true
        });

        // 加入到elements中
        this.elements.push(this.version);
        this.elements.push(this.serialNumber);
        this.elements.push(this.signature);
        this.elements.push(this.issuer);
        this.elements.push(this.validity);
        this.elements.push(this.subject);
        this.elements.push(this.subjectPublicKeyInfo);
        this.elements.push(this.issuerUniqueID);
        this.elements.push(this.subjectUniqueID);
        this.elements.push(this.extensions);
    }

    utils.extend(TBSCertificate, asn1.der.Constructive);

    TBSCertificate.prototype.toJson = function() {
        return {
            version: this.version.value,
            serialNumber: asn1.der.toHex(this.serialNumber.value),
            signature: this.signature.toJson(),
            issuer: this.issuer.toJson(),
            validity: this.validity.toJson(),
            subject: this.subject.toJson(),
            subjectPublicKeyInfo: this.subjectPublicKeyInfo.toJson(),
            issuerUniqueID: this.issuerUniqueID.present ? asn1.der.toHex(this.issuerUniqueID.value) : '',
            subjectUniqueID: this.subjectUniqueID.present ? asn1.der.toHex(this.subjectUniqueID.value) : '',
            extensions: this.extensions.toJson()
        };
    };

    return TBSCertificate;
})();

x509.SignatureInfo = (function() {
    "use strict";

    function SignatureInfo() {
        asn1.der.Constructive.apply(this, arguments);

        this.algorithm = new x509.AlgorithmIdentifier();
        this.encryptedDigest = new asn1.der.Primitive({
            tag: asn1.der.TAG_VALUE_OCTET_STRING
        });

        // 加入到elements中
        this.elements.push(this.algorithm);
        this.elements.push(this.encryptedDigest);
    }

    utils.extend(SignatureInfo, asn1.der.Constructive);

    SignatureInfo.prototype.toJson = function() {
        return {algorithm: this.algorithm.toJson(), encryptedDigest: asn1.der.toHex(this.encryptedDigest.value)};
    };

    return SignatureInfo;
})();

x509.Certificate = (function() {
    "use strict";
    
    function Certificate() {
        asn1.der.Constructive.apply(this, arguments);

        this.tbsCertificate = new x509.TBSCertificate();
        this.signatureAlgorithm = new x509.AlgorithmIdentifier();
        this.signatureValue = new asn1.der.Primitive({
            tag: asn1.der.TAG_VALUE_BIT_STRING
        });

        // 加入到elements中
        this.elements.push(this.tbsCertificate);
        this.elements.push(this.signatureAlgorithm);
        this.elements.push(this.signatureValue);
    }

    utils.extend(Certificate, asn1.der.Constructive);

    Certificate.prototype.toJson = function() {
        return {
            tbsCertificate: this.tbsCertificate.toJson(),
            signatureAlgorithm: this.signatureAlgorithm.toJson(),
            signatureValue: asn1.der.toHex(this.signatureValue.value)
        };
    };

    return Certificate;
})();

pkcs6.Attribute = (function() {
    "use strict";
    
    function Attribute() {
        asn1.der.Constructive.apply(this, arguments);

        this.type = new asn1.der.Primitive({
            tag: asn1.der.TAG_VALUE_OBJECT_IDENTIFIER
        });
        this.values = new asn1.der.Set({
            elementCreator: function() {return new asn1.der.Primitive();}
        });

        // 加入到elements中
        this.elements.push(this.type);
        this.elements.push(this.values);
    }

    utils.extend(Attribute, asn1.der.Constructive);

    Attribute.prototype.toJson = function() {
        var v = [];
        this.values.elements.forEach(function(element) {
            v.push(element.value);
        });

        return {type: this.type.value, values: v};
    };

    return Attribute;
})();

pkcs6.ExtendedCertificateInfo = (function() {
    "use strict";
    
    function ExtendedCertificateInfo() {
        asn1.der.Constructive.apply(this, arguments);

        this.version = new asn1.der.Primitive({
            tag: asn1.der.TAG_VALUE_INTEGER
        });
        this.certificate = new x509.Certificate();
        this.attributes = new asn1.der.Set({
            elementCreator: function() {return new pkcs6.Attribute();}
        });

        // 加入到elements中
        this.elements.push(this.version);
        this.elements.push(this.certificate);
        this.elements.push(this.attributes);
    }

    utils.extend(ExtendedCertificateInfo, asn1.der.Constructive);

    ExtendedCertificateInfo.prototype.toJson = function() {
        return {
            version: this.version.value,
            certificate: this.certificate.toJson(),
            attributes: this.attributes.toJson()
        };
    };

    return ExtendedCertificateInfo;
})();

pkcs6.ExtendedCertificate = (function() {
    "use strict";
    
    function ExtendedCertificate() {
        asn1.der.Constructive.apply(this, arguments);

        this.extendedCertificateInfo = new pkcs6.ExtendedCertificateInfo();
        this.signatureAlgorithm = new x509.AlgorithmIdentifier();
        this.signature = new asn1.der.Primitive({
            tag: asn1.der.TAG_VALUE_BIT_STRING
        });

        // 加入到elements中
        this.elements.push(this.extendedCertificateInfo);
        this.elements.push(this.signatureAlgorithm);
        this.elements.push(this.signature);
    }

    utils.extend(ExtendedCertificate, asn1.der.Constructive);

    ExtendedCertificate.prototype.toJson = function() {
        return {
            extendedCertificateInfo: this.extendedCertificateInfo.toJson(),
            signatureAlgorithm: this.signatureAlgorithm.toJson(),
            signature: asn1.der.toHex(this.signature.value)
        };
    };

    return ExtendedCertificate;
})();

pkcs7.ExtendedCertificateOrCertificate = (function() {
    "use strict";
    
    function ExtendedCertificateOrCertificate() {
        asn1.der.Constructive.apply(this, arguments);

        this.certificate = new x509.Certificate();
        this.extendedCertificate = new pkcs6.ExtendedCertificate();

        // 加入到elements中
        //this.elements.push(this.extendedCertificateInfo);
        //this.elements.push(this.signatureAlgorithm);
    }

    utils.extend(ExtendedCertificateOrCertificate, asn1.der.Constructive);

    ExtendedCertificateOrCertificate.prototype.encode = function(baBuf) {
        if (!this.present) return;

        var baMsg = this.tag.tagType === asn1.der.TAG_TYPE_EXPLICIT ? new ByteArray() : baBuf;
        // 子原始编码
        var sub = 0 === this.tag.tagValue ? this.extendedCertificate : this.certificate;
        sub.encode(baMsg);

        if (this.tag.tagType === asn1.der.TAG_TYPE_EXPLICIT) {
            var vv = baMsg.getBytes();
            // explicit tag
            this.explicitTag.encode(baBuf);
            // Length
            new der.Length(vv.length).encode(baBuf);
            // Value
            baBuf.appendBytes(vv);
        }
    };

    ExtendedCertificateOrCertificate.prototype.decode = function(baBuf, start, end) {
        end = typeof end === 'undefined' ? baBuf.length : end;
        start = start || 0;
        var etaglen = 0;
    
        if (this.tag.tagType === asn1.der.TAG_TYPE_EXPLICIT) {
            var istart = start;
            start += this.explicitTag.decode(baBuf, start, end);
            start += new der.Length().decode(baBuf, start, end);
            etaglen = start - istart;
        }
        // 子元素解码
        this.tag.decode(baBuf, start, end);
        var sub = 0 === this.tag.tagValue ? this.extendedCertificate : this.certificate;
        var elen = sub.decode(baBuf, start, end);
        this.present = true;

        return etaglen + elen;
    };

    ExtendedCertificateOrCertificate.prototype.toJson = function() {
        return 0 === this.tag.tagValue ? this.extendedCertificate.toJson() : this.certificate.toJson();
    };

    return ExtendedCertificateOrCertificate;
})();

pkcs7.CRLEntry = (function() {
    "use strict";
    
    function CRLEntry() {
        asn1.der.Constructive.apply(this, arguments);

        this.userCertificate = new asn1.der.Primitive({ // 证书序列号
            tag: asn1.der.TAG_VALUE_INTEGER
        });
        this.revocationDate = new asn1.der.Primitive({
            tag: asn1.der.TAG_VALUE_UTC_TIME
        });

        // 加入到elements中
        this.elements.push(this.userCertificate);
        this.elements.push(this.revocationDate);
    }

    utils.extend(CRLEntry, asn1.der.Constructive);

    CRLEntry.prototype.toJson = function() {
        return {
            userCertificate: asn1.der.toHex(this.version.value),
            revocationDate: this.revocationDate.value
        };
    };

    return CRLEntry;
})();

pkcs7.CertificateRevocationList = (function() {
    "use strict";
    
    function CertificateRevocationList() {
        asn1.der.Constructive.apply(this, arguments);

        this.signature = new x509.AlgorithmIdentifier();
        this.issuer = new x509.RelativeDistinguishedName();
        this.lastUpdate = new asn1.der.Primitive({
            tag: asn1.der.TAG_VALUE_UTC_TIME
        });
        this.nextUpdate = new asn1.der.Primitive({
            tag: asn1.der.TAG_VALUE_UTC_TIME
        });
        this.revokedCertificates = new pkcs7.CRLEntry({
            optional: true
        });

        // 加入到elements中
        this.elements.push(this.signature);
        this.elements.push(this.issuer);
        this.elements.push(this.lastUpdate);
        this.elements.push(this.nextUpdate);
        this.elements.push(this.revokedCertificates);
    }

    utils.extend(CertificateRevocationList, asn1.der.Constructive);

    CertificateRevocationList.prototype.toJson = function() {
        return {
            signature: this.signature.toJson(),
            issuer: this.issuer.toJson(),
            lastUpdate: this.lastUpdate.value,
            nextUpdate: this.nextUpdate.value,
            revokedCertificates: this.revokedCertificates.toJson()
        };
    };

    return CertificateRevocationList;
})();

pkcs7.IssuerAndSerialNumber = (function() {
    "use strict";
    
    function IssuerAndSerialNumber() {
        asn1.der.Constructive.apply(this, arguments);

        this.issuer = new x509.RelativeDistinguishedName();
        this.serialNumber = new asn1.der.Primitive({ // 证书的序列号
            tag: asn1.der.TAG_VALUE_INTEGER
        });

        // 加入到elements中
        this.elements.push(this.issuer);
        this.elements.push(this.serialNumber);
    }

    utils.extend(IssuerAndSerialNumber, asn1.der.Constructive);

    IssuerAndSerialNumber.prototype.toJson = function() {
        return {
            issuer: this.issuer.toJson(),
            serialNumber: asn1.der.toHex(this.serialNumber.value)
        };
    };

    return IssuerAndSerialNumber;
})();

pkcs7.SignerInfo = (function() {
    "use strict";
    
    function SignerInfo() {
        asn1.der.Constructive.apply(this, arguments);

        this.version = new asn1.der.Primitive({
            tag: asn1.der.TAG_VALUE_INTEGER
        });
        this.issuerAndSerialNumber = new pkcs7.IssuerAndSerialNumber();
        this.digestAlgorithm = new x509.AlgorithmIdentifier();
        this.authenticatedAttributes = new asn1.der.Set({
            elementCreator: function() {return new pkcs6.Attribute();},
            tag: {
                class: asn1.der.CLASS_CONTEXT_SPECIFIC,
                type: asn1.der.TYPE_CONSTRUCTED,
                value: asn1.der.TAG_VALUE_SET,
                tagValue: 0,
                tagType: asn1.der.TAG_TYPE_IMPLICIT
            },
            optional: true
        });
        this.digestEncryptionAlgorithm = new x509.AlgorithmIdentifier();
        this.encryptedDigest = new asn1.der.Primitive({
            tag: asn1.der.TAG_VALUE_OCTET_STRING
        });
        this.unauthenticatedAttributes = new asn1.der.Set({
            elementCreator: function() {return new pkcs6.Attribute();},
            tag: {
                class: asn1.der.CLASS_CONTEXT_SPECIFIC,
                type: asn1.der.TYPE_CONSTRUCTED,
                value: asn1.der.TAG_VALUE_SET,
                tagValue: 1,
                tagType: asn1.der.TAG_TYPE_IMPLICIT
            },
            optional: true
        });

        // 加入到elements中
        this.elements.push(this.version);
        this.elements.push(this.issuerAndSerialNumber);
        this.elements.push(this.digestAlgorithm);
        this.elements.push(this.authenticatedAttributes);
        this.elements.push(this.digestEncryptionAlgorithm);
        this.elements.push(this.encryptedDigest);
        this.elements.push(this.unauthenticatedAttributes);
    }

    utils.extend(SignerInfo, asn1.der.Constructive);

    SignerInfo.prototype.toJson = function() {
        return {
            version: this.version.value,
            issuerAndSerialNumber: this.issuerAndSerialNumber.toJson(),
            digestAlgorithm: this.digestAlgorithm.toJson(),
            authenticatedAttributes: this.authenticatedAttributes.toJson(),
            digestEncryptionAlgorithm: this.digestEncryptionAlgorithm.toJson(),
            encryptedDigest: asn1.der.toHex(this.encryptedDigest.value),
            unauthenticatedAttributes: this.unauthenticatedAttributes.toJson()
        };
    };

    return SignerInfo;
})();

pkcs7.SignedData = (function() {
    "use strict";
    
    function SignedData() {
        asn1.der.Constructive.apply(this, arguments);

        this.version = new asn1.der.Primitive({
            tag: asn1.der.TAG_VALUE_INTEGER
        });
        this.digestAlgorithms = new asn1.der.Set({
            elementCreator: function() {return new x509.AlgorithmIdentifier();}
        });
        this.contentInfo = new pkcs7.ContentInfo();
        this.certificates = new asn1.der.Set({
            elementCreator: function() {return new pkcs7.ExtendedCertificateOrCertificate();},
            tag: {
                class: asn1.der.CLASS_CONTEXT_SPECIFIC,
                type: asn1.der.TYPE_CONSTRUCTED,
                value: asn1.der.TAG_VALUE_SET,
                tagValue: 0,
                tagType: asn1.der.TAG_TYPE_IMPLICIT
            },
            optional: true
        });
        this.crls = new asn1.der.Set({
            elementCreator: function() {return new pkcs7.CertificateRevocationList();},
            tag: {
                class: asn1.der.CLASS_CONTEXT_SPECIFIC,
                type: asn1.der.TYPE_CONSTRUCTED,
                value: asn1.der.TAG_VALUE_SET,
                tagValue: 1,
                tagType: asn1.der.TAG_TYPE_IMPLICIT
            },
            optional: true
        });
        this.signerInfos = new asn1.der.Set({
            elementCreator: function() {return new pkcs7.SignerInfo();}
        });

        // 加入到elements中
        this.elements.push(this.version);
        this.elements.push(this.digestAlgorithms);
        this.elements.push(this.contentInfo);
        this.elements.push(this.certificates);
        this.elements.push(this.crls);
        this.elements.push(this.signerInfos);
    }

    utils.extend(SignedData, asn1.der.Constructive);

    SignedData.prototype.toJson = function() {
        return {
            version: this.version.value,
            digestAlgorithms: this.digestAlgorithms.toJson(),
            contentInfo: this.contentInfo.toJson(),
            certificates: this.certificates.toJson(),
            crls: this.crls.toJson(),
            signerInfos: this.signerInfos.toJson()
        };
    };

    return SignedData;
})();

pkcs7.ContentInfo = (function() {
    "use strict";
    
    function ContentInfo() {
        asn1.der.Constructive.apply(this, arguments);

        this.contentType = new asn1.der.Primitive({
            tag: asn1.der.TAG_VALUE_OBJECT_DESCRIPTION
        });

        // 加入到elements中
        //this.elements.push(this.contentType);
        //this.elements.push(this.content);
    }

    utils.extend(ContentInfo, asn1.der.Constructive);

    ContentInfo.prototype.getContent = function() {
        switch (this.contentType.value) {
            case oids.PKCS7_DATA: {
                this.data = this.data || new asn1.der.Primitive({
                    tag: {
                        class: asn1.der.CLASS_UNIVERSAL,
                        type: asn1.der.TYPE_PRIMITIVE,
                        value: asn1.der.TAG_VALUE_OCTET_STRING,
                        tagType: asn1.der.TAG_TYPE_EXPLICIT
                    },
                    explicitTag: new asn1.der.Tag({
                        class: asn1.der.CLASS_CONTEXT_SPECIFIC,
                        type: asn1.der.TYPE_CONSTRUCTED,
                        value: 0
                    }),
                    optional: true
                });
                return this.data;
            }
            case oids.PKCS7_SIGNED_DATA: {
                this.signedData = this.signedData || new pkcs7.SignedData({
                    tag: {
                        class: asn1.der.CLASS_UNIVERSAL,
                        type: asn1.der.TYPE_CONSTRUCTED,
                        value: asn1.der.TAG_VALUE_SEQUENCE,
                        tagType: asn1.der.TAG_TYPE_EXPLICIT
                    },
                    explicitTag: new asn1.der.Tag({
                        class: asn1.der.CLASS_CONTEXT_SPECIFIC,
                        type: asn1.der.TYPE_CONSTRUCTED,
                        value: 0
                    }),
                    optional: true
                });
                return this.signedData;
            }
        }
        return null;
    };

    ContentInfo.prototype.contentToJson = function() {
        switch (this.contentType.value) {
            case oids.PKCS7_DATA: {
                return this.data ? ByteArray.fromUTF8(this.data.value) : '';
            }
            case oids.PKCS7_SIGNED_DATA: {
                return this.signedData ? this.signedData.toJson() : '';
            }
        }
        return '';
    };

    ContentInfo.prototype.encodeSubField = function(baBuf) {
        this.contentType.encode(baBuf);
        // content
        var content = this.getContent();
        if (content && content.present) content.encode(baBuf);
    };

    ContentInfo.prototype.decodeSubField = function(baBuf, start, end) {
        start += this.contentType.decode(baBuf, start, end);
        // content
        var content = this.getContent();
        if (start === end) {content.present=false;return;}
        var tag = new asn1.der.Tag();
        tag.decode(baBuf, start, end);
        content.present = true;
        if (tag.value === content.explicitTag.value) {
            start += content.decode(baBuf, start, end);
        }
    };

    ContentInfo.prototype.toJson = function() {
        return {
            contentType: this.contentType.value,
            content: this.contentToJson()
        };
    };

    return ContentInfo;
})();

// Node.js check
if (typeof module !== "undefined" && module.hasOwnProperty("exports")) {
    module.exports = pki;
}

// amd check
if (typeof define === "function" && define.amd) {
    define("pki", [], function() {
        return pki;
    });
}