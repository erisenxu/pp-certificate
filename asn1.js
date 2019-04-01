if (typeof require === "function") {var bigInt = require("big-integer");var ByteArray = require('pp-bytearray');var moment = require('moment');}

var asn1 = {};
var der = asn1.der = {};

// class类型
der.CLASS_UNIVERSAL = 0;
der.CLASS_APPLICATION = 1;
der.CLASS_CONTEXT_SPECIFIC = 2;
der.CLASS_PRIVATE = 3;
// type
der.TYPE_PRIMITIVE = 0;
der.TYPE_CONSTRUCTED = 1;
// Universal tag value
der.TAG_VALUE_BOOLEAN = 1;
der.TAG_VALUE_INTEGER = 2;
der.TAG_VALUE_BIT_STRING = 3;
der.TAG_VALUE_OCTET_STRING = 4;
der.TAG_VALUE_NULL = 5;
der.TAG_VALUE_OBJECT_IDENTIFIER = 6;
der.TAG_VALUE_OBJECT_DESCRIPTION = 7;
der.TAG_VALUE_EXTERNAL = 8;
der.TAG_VALUE_REAL = 9;
der.TAG_VALUE_ENUMERATED = 10;
der.TAG_VALUE_EMBEDDED_PDV = 11;
der.TAG_VALUE_UTF8_STRING = 12;
der.TAG_VALUE_SEQUENCE = 16;
der.TAG_VALUE_SET = 17;
der.TAG_VALUE_NUMERIC_STRING = 18;
der.TAG_VALUE_PRINTABLE_STRING = 19;
der.TAG_VALUE_TELETEX_STRING = 20;
der.TAG_VALUE_VIDEO_TEX_STRING = 21;
der.TAG_VALUE_IA5_STRING = 22;
der.TAG_VALUE_UTC_TIME = 23;
der.TAG_VALUE_GENERALIZED_TIME = 24;
der.TAG_VALUE_GRAPHIC_STRING = 25;
der.TAG_VALUE_VISIBLE_STRING = 26;
der.TAG_VALUE_GENERAL_STRING = 27;
der.TAG_VALUE_UNIVERSAL_STRING = 28;
der.TAG_VALUE_CHARACTER_STRING = 29;
der.TAG_VALUE_BMP_STRING = 30;
// Tag type
der.TAG_TYPE_NORMAL = 0;
der.TAG_TYPE_IMPLICIT = 1;
der.TAG_TYPE_EXPLICIT = 2;

der.oid = {};
der.oid.toBytes = function(oid) {
    if (typeof oid !== 'string') {
        throw "OID toBytes error, the oid is not a string";
    }
    var av = oid.split('.');
    var v = [];
    if (av.length < 2) {
        throw "OID toBytes error, the oid is not a valid oid:" + oid;
    }
    v.push(parseInt(av[0]) * 40 + parseInt(av[1]));
    for (var i = 2; i < av.length; i++) {
        var bi = bigInt(av[i]);
        if (bi.gt(127)) {
            var ba = bi.toArray(0x80).value;
            for (var j = 0; j < ba.length; j++) {
                if (j === ba.length - 1) {
                    v.push(ba[j]);
                } else {
                    v.push(0x80 | ba[j]);
                }
            }
        } else {
            v.push(bi.value);
        }
    }
    return v;
};
der.oid.fromBytes = function(bytes) {
    if (bytes.length <= 0) return '';
    var v = [];

    if (bytes[0] <= 39) {
        v.push(0);
        v.push(bytes[0]);
    } else if (bytes[0] <= 79) {
        v.push(1);
        v.push(bytes[0] - 40);
    } else {
        v.push(2);
        v.push(bytes[0] - 80);
    }

    var b = [];
    for (var i = 1; i < bytes.length; i++) {
        b.push(bytes[i] & 0x7f);
        if ((bytes[i] & 0x80) === 0) {
            v.push(bigInt.fromArray(b, 0x80).toString());
            b = [];
        }
    }

    return v.join('.');
};

der.toHex = function(v) {
    return (v instanceof Array) ? bigInt.fromArray(v, 256).toString(16) : bigInt(v).toString(16);
}

der.updateUtcTime = function(primitive) {
    if (primitive instanceof der.Primitive && (primitive.tag.value == der.TAG_VALUE_UTC_TIME || primitive.tag.value == der.TAG_VALUE_GENERALIZED_TIME)) {
        var year = moment(primitive.value, 'YYYY-MM-DD HH:mm:ss').utc().year();
        primitive.tag.value = year >= 1950 && year <= 2049 ? der.TAG_VALUE_UTC_TIME : der.TAG_VALUE_GENERALIZED_TIME;
    }
}

der.Tag = (function() {
    "use strict";

    function Tag(opt) {
        var o = typeof opt === 'undefined' ? {} : opt;
        var o = typeof o === 'object' ? o : {value:o};
        this.class = o.class || der.CLASS_UNIVERSAL;
        this.type = o.type || der.TYPE_PRIMITIVE;
        this.value = o.value || 0;
        this.tagType = o.tagType || der.TAG_TYPE_NORMAL;
        this.tagValue = typeof o.tagValue === 'undefined' ? this.value : o.tagValue;   // 当类型为implicit和explict时tag的value
    }

    Tag.prototype.encode = function(baBuf) {
        var t = [];
        while (true) {
            var v = bigInt(this.tagType === der.TAG_TYPE_IMPLICIT ? this.tagValue : this.value).shiftRight((8*t.length)).and(0xff).value;
            if (v === 0) {if(t.length === 0){t.push(v);}break;}
            t.push(v);
        }
        t.reverse();
        baBuf.appendUint8((this.class << 6) | (this.type << 5) | t[0]);
        baBuf.appendBytes(t, 1);
    };

    Tag.prototype.decode = function(baBuf, start, end) {

        end = typeof end === 'undefined' ? baBuf.length : end;

        if (end < start) {
            throw "Tag decode error, the message buffer is too short";
        }

        var v = baBuf.getUint8(start);

        this.class = (v >> 6) & 3;
        this.type = (v >> 5) & 1;
        this.tagValue = v & 0x1f;

        if (this.tagValue === 0x1f) {
            // 多个八位组
            var b = bigInt(this.tagValue);
            for (var i = start + 1; i < end; i++) {
                var tv = baBuf.getUint8(i);
                b.or(bigInt(tv).shiftLeft(8*(i-start)));
                if ((tv & 0x80) === 0) break;
            }
            this.tagValue = b.toString();
            if (this.tagType != der.TAG_TYPE_IMPLICIT) this.value = this.tagValue;
            return Math.ceil(b.bitLength().value/8);
        }
        if (this.tagType != der.TAG_TYPE_IMPLICIT) this.value = this.tagValue;
        return Uint8Array.BYTES_PER_ELEMENT;
    };

    Tag.prototype.fromJson = function(tag) {
        var o = tag || {};
        this.class = o.class || der.CLASS_UNIVERSAL;
        this.type = o.type || der.TYPE_PRIMITIVE;
        this.value = o.value || 0;
    };

    Tag.prototype.toJson = function() {
        return {class: this.class, type: this.type, value: this.value};
    };

    return Tag;
})();

der.Length = (function() {
    "use strict";

    function Length(len) {
        this.len = len || 0;
    }

    Length.prototype.encode = function(baBuf) {
        var b = bigInt(this.len);
        // 不定长度
        if (b.lt(0)) {
            baBuf.appendUint8(0x80);
        } else if (b.leq(127)) {
            baBuf.appendUint8(this.len);
        } else {
            var v = bigInt(this.len).toArray(256).value;
            baBuf.appendUint8(0x80 | v.length);
            baBuf.appendBytes(v);
        }
    };

    Length.prototype.decode = function(baBuf, start, end) {
        end = typeof end === 'undefined' ? baBuf.length : end;

        if (end < start) {
            throw "Length decode error, the message buffer is too short";
        }
        var v = baBuf.getUint8(start);
        if (v === 0x80) {
            // TODO: 
            this.len = -1;
        } else if ((v & 0x80) === 0) {
            this.len = v & 0x7f;
        } else {
            var l = v & 0x7f;
            if (end < start + 1 + l) {
                throw "Length decode error, the message buffer is too short";
            }
            var b = baBuf.getBytes(start + 1, l);
            this.len = bigInt.fromArray(b, 256).value;
            return l + Uint8Array.BYTES_PER_ELEMENT;
        }
        return Uint8Array.BYTES_PER_ELEMENT;
    };

    return Length;
})();

der.Primitive = (function() {
    "use strict";
    
    function Primitive(opt) {
        var o = opt || {};
        this.tag = new der.Tag(o.tag);
        this.value = typeof o.value === 'undefined' ? 0 : o.value;
        this.padding = typeof o.padding === 'undefined' ? 0 : o.padding;
        this.optional = typeof o.optional === 'undefined' ? false : o.optional;
        this.present = typeof o.present === 'undefined' ? true : o.present;
        this.bits = o.bits || 0;
        this.explicitTag = o.explicitTag;
    }

    Primitive.prototype.encode = function(baBuf) {

        if (!this.present) return;

        var baMsg = this.tag.tagType === der.TAG_TYPE_EXPLICIT ? new ByteArray() : baBuf;

        // tag编码
        this.tag.encode(baMsg);

        switch (this.tag.value) {
            case der.TAG_VALUE_NULL: // 如果是NULL，则只编码长度
                baMsg.appendUint8(0);
                break;
            case der.TAG_VALUE_BOOLEAN:
                baMsg.appendUint8(1);
                baMsg.appendUint8(this.value ? 0xff : 0);
                break;
            case der.TAG_VALUE_REAL:
                throw "Primitive encode error, un-suport tag value 'real'";
                //break;
            case der.TAG_VALUE_BIT_STRING: {
                if (this.value == 0) {
                    baMsg.appendUint8(1);
                    baMsg.appendUint8(0);
                } else {
                    var b = bigInt(this.value);
                    var bs = b.toString(2);
                    var pl = 8 - bs.length%8; // padding length
                    pl = this.padding === -1 || this.padding > pl ? pl : this.padding;
                    var v = b.shiftLeft(pl).toArray(256).value;
                    // bits长度
                    var bn = this.bits > v.length ? this.bits - v.length : 0;
                    // 长度编码
                    new der.Length(v.length + 1 + bn).encode(baMsg);
                    // padding编码
                    baMsg.appendUint8(pl);
                    // 值编码
                    for (var i = 0; i < bn; i++) baMsg.appendUint8(0);
                    baMsg.appendBytes(v);
                }
                break;
            }
            case der.TAG_VALUE_OBJECT_IDENTIFIER: {
                var v = der.oid.toBytes(this.value);
                // 长度编码
                new der.Length(v.length).encode(baMsg);
                // 值编码
                baMsg.appendBytes(v);
                break;
            }
            case der.TAG_VALUE_IA5_STRING:          // ascii字符（IA5String类型的编码对象是ASCII集合中的大多数．包括NULL,BEL,TAB,NL,LF,CR以及32~126）
            case der.TAG_VALUE_PRINTABLE_STRING: {  // 可打印字符串对象是ASCII集合的一个有限子集，这个子集包括32,39,40~41,43~58,61,63以及65~122.
                if (typeof this.value !== 'string') {
                    throw "Primitive encode error, the value is not a string";
                }
                var v = this.value.split('').map(function(c) {return c.charCodeAt();});
                // 长度编码
                new der.Length(v.length).encode(baMsg);
                // 值编码
                baMsg.appendBytes(v);
                break;
            }
            case der.TAG_VALUE_INTEGER:
            case der.TAG_VALUE_ENUMERATED: {
                var b = bigInt(this.value);
                if (b.lt(0)) {
                    throw "Primitive-integer encode error, un-suport negative value";
                } else {
                    var v = b.toArray(256).value;
                    if ((v[0] & 0x80) === 0x80) {
                        // 长度
                        new der.Length(v.length + 1).encode(baMsg);
                        // 补0
                        baMsg.appendUint8(0);
                    } else {
                        new der.Length(v.length).encode(baMsg);
                    }
                    // 值编码
                    baMsg.appendBytes(v);
                }
                break;
            }
            case der.TAG_VALUE_UTF8_STRING: {
                var v = ByteArray.toUTF8(this.value);
                // 长度编码
                new der.Length(v.length).encode(baMsg);
                // 值编码
                baMsg.appendBytes(v);
                break;
            }
            case der.TAG_VALUE_UTC_TIME: {// 注意1950-2049年的时间用UTCTime，1950年前和2049年后的时间用GeneralizedTime
                var v = moment(this.value, 'YYYY-MM-DD HH:mm:ss').utc().format('YYMMDDHHmmss\\Z');
                v = v.split('').map(function(c) {return c.charCodeAt();});
                // 长度编码
                new der.Length(v.length).encode(baMsg);
                // 值编码
                baMsg.appendBytes(v);
                break;
            }
            case der.TAG_VALUE_GENERALIZED_TIME: {// 注意1950-2049年的时间用UTCTime，1950年前和2049年后的时间用GeneralizedTime
                var v = moment(this.value, 'YYYY-MM-DD HH:mm:ss').utc().format('YYYYMMDDHHmmss\\Z');
                v = v.split('').map(function(c) {return c.charCodeAt();});
                // 长度编码
                new der.Length(v.length).encode(baMsg);
                // 值编码
                baMsg.appendBytes(v);
                break;
            }
            case der.TAG_VALUE_OCTET_STRING:    // 可以理解为字节数组
            case der.TAG_VALUE_BMP_STRING:      // 可以理解为字节数组
            default: {
                // 长度编码
                new der.Length(this.value.length).encode(baMsg);
                // 值编码
                baMsg.appendBytes(this.value);
                break;
            }
        }

        if (this.tag.tagType === der.TAG_TYPE_EXPLICIT) {
            var v = baMsg.getBytes();
            // explicit tag
            this.explicitTag.encode(baBuf);
            // Length
            new der.Length(v.length).encode(baBuf);
            // Value
            baBuf.appendBytes(v);
        }
    };

    Primitive.prototype.decode = function(baBuf, start, end) {
        end = typeof end === 'undefined' ? baBuf.length : end;
        start = start || 0;
        var etaglen = 0;

        if (this.tag.tagType === der.TAG_TYPE_EXPLICIT) {
            var istart = start;
            start += this.explicitTag.decode(baBuf, start, end);
            start += new der.Length().decode(baBuf, start, end);
            etaglen = start - istart;
        }

        // tag解码
        var tl = this.tag.decode(baBuf, start, end);
        // length解码
        var len = new der.Length();
        var ll = len.decode(baBuf, start + tl, end);
        var mlen = tl + ll + len.len;
        if (end < start + mlen) {
            throw "Primitive decode error, the message buffer is too short";
        }
        // value解码
        var b = baBuf.getBytes(start + tl + ll, len.len);

        switch (this.tag.value) {
            case der.TAG_VALUE_NULL:
                this.value = 0;
                break;
            case der.TAG_VALUE_BOOLEAN:
                this.value = bigInt.fromArray(b, 256).toString() === '0' ? false : true;
                break;
            case der.TAG_VALUE_REAL:
                throw "Primitive decode error, un-suport tag value 'real'";
            case der.TAG_VALUE_BIT_STRING: {
                if (b.length <= 0 || (b.length === 1 && b[0] === 0)) {
                    this.value = 0;
                } else {
                    var pl = b[0];
                    this.value = bigInt.fromArray(b.slice(1), 256).shiftRight(pl).toString();
                    this.bits = b.length - 1;
                }
                break;
            }
            case der.TAG_VALUE_OBJECT_IDENTIFIER: {
                this.value = der.oid.fromBytes(b);
                break;
            }
            case der.TAG_VALUE_IA5_STRING:          // ascii字符（IA5String类型的编码对象是ASCII集合中的大多数．包括NULL,BEL,TAB,NL,LF,CR以及32~126）
            case der.TAG_VALUE_PRINTABLE_STRING: {  // 可打印字符串对象是ASCII集合的一个有限子集，这个子集包括32,39,40~41,43~58,61,63以及65~122.
                this.value = b.map(function(c) {return String.fromCharCode(c);}).join('');
                break;
            }
            case der.TAG_VALUE_INTEGER:
            case der.TAG_VALUE_ENUMERATED: {
                if (b.length <= 0) {
                    this.value = 0;
                    break;
                }
                if ((b[0] & 0x80) !== 0) {
                    throw "Primitive-integer decode error, un-suport negative value";
                }
                this.value = bigInt.fromArray(b, 256).toString();
                break;
            }
            case der.TAG_VALUE_UTF8_STRING: {
                this.value = ByteArray.fromUTF8(b);
                break;
            }
            case der.TAG_VALUE_UTC_TIME: {
                var v = b.map(function(c) {return String.fromCharCode(c);}).join('');
                v = v >= '50' ? '19' + v : '20' + v;
                this.value = moment.utc(v, 'YYYYMMDDHHmmss\\Z').local().format('YYYY-MM-DD HH:mm:ss');
                break;
            }
            case der.TAG_VALUE_GENERALIZED_TIME: {
                var v = b.map(function(c) {return String.fromCharCode(c);}).join('');
                this.value = moment.utc(v, 'YYYYMMDDHHmmss\\Z').local().format('YYYY-MM-DD HH:mm:ss');
                break;
            }
            case der.TAG_VALUE_OCTET_STRING:    // 可以理解为字节数组
            case der.TAG_VALUE_BMP_STRING:      // 可以理解为字节数组
            default:
                this.value = b;
                break;
        }
        return mlen + etaglen;
    };

    Primitive.prototype.fromJson = function(bi) {
        var o = bi || {};
        this.tag.fromJson(o.tag);
        this.value = typeof o.value === 'undefined' ? 0 : o.value;
    };

    Primitive.prototype.toJson = function() {
        return {tag: this.tag.toJson(), value: this.value, /*hex: bigInt(this.value).toString(16)*/};
    };

    Primitive.prototype.toBytes = function() {
        var ba = new ByteArray();
        this.encode(ba);
        return ba.getBytes();
    };

    Primitive.prototype.toString = function(encoding='base64') {
        return new Buffer(this.toBytes()).toString(encoding);
    };

    return Primitive;
})();

der.Sequence = (function() {
    "use strict";
    
    function Sequence(opt) {
        var o = opt || {};
        this.tag = new der.Tag(o.tag || {
            class: asn1.der.CLASS_UNIVERSAL,
            type: asn1.der.TYPE_CONSTRUCTED,
            value: asn1.der.TAG_VALUE_SEQUENCE
        });
        this.optional = typeof o.optional === 'undefined' ? false : o.optional;
        this.present = typeof o.present === 'undefined' ? true : o.present;
        this.elements = o.elements || [];
        this.explicitTag = o.explicitTag;
    }

    Sequence.prototype.encode = function(baBuf) {

        if (!this.present) return;

        var baMsg = this.tag.tagType === der.TAG_TYPE_EXPLICIT ? new ByteArray() : baBuf;

        // 子元素编码
        var baElm = new ByteArray();
        this.elements.forEach(function(element) {
            element.encode(baElm);
        });

        var v = baElm.length > 0 ? baElm.getBytes() : [];

        // tag编码
        this.tag.encode(baMsg);
        // 长度编码
        new der.Length(v.length).encode(baMsg);
        // 值编码
        baMsg.appendBytes(v);

        if (this.tag.tagType === der.TAG_TYPE_EXPLICIT) {
            var v = baMsg.getBytes();
            // explicit tag
            this.explicitTag.encode(baBuf);
            // Length
            new der.Length(v.length).encode(baBuf);
            // Value
            baBuf.appendBytes(v);
        }
    };

    Sequence.prototype.decode = function(baBuf, start, end) {
        end = typeof end === 'undefined' ? baBuf.length : end;
        start = start || 0;
        var etaglen = 0;
    
        if (this.tag.tagType === der.TAG_TYPE_EXPLICIT) {
            var istart = start;
            start += this.explicitTag.decode(baBuf, start, end);
            start += new der.Length().decode(baBuf, start, end);
            etaglen = start - istart;
        }

        // tag解码
        var tl = this.tag.decode(baBuf, start, end);
        // length解码
        var len = new der.Length();
        var ll = len.decode(baBuf, start + tl, end);
        var mlen = tl + ll + len.len;
        var elmEnd = start + mlen;
        if (end < elmEnd) {
            throw "Sequence decode error, the message buffer is too short";
        }
        // elements解码
        this.elements = [];

        if (len.len <= 0) return mlen + etaglen;

        start += tl + ll;
        var readLen = 0;
        var elmTag = new der.Tag();
        while (readLen < len.len) {
            // 读子元素tag
            elmTag.decode(baBuf, start, elmEnd);
            var curElm = elmTag.type === der.TYPE_PRIMITIVE ? new der.Primitive() : new Sequence();
            var elmLen = curElm.decode(baBuf, start, elmEnd);
            this.elements.push(curElm);
            readLen += elmLen;
            start += elmLen;
        }
        return mlen + etaglen;
    };

    Sequence.prototype.fromJson = function(se) {
        var o = se || {};
        this.tag.fromJson(se.tag || this.tag);
        this.elements = o.elements || [];
    };

    Sequence.prototype.toJson = function() {
        var sequence = [];

        this.elements.forEach(function(element) {
            sequence.push(element.toJson());
        });

        return {tag: this.tag.toJson(), sequence};
    };

    Sequence.prototype.toBytes = function() {
        var ba = new ByteArray();
        this.encode(ba);
        return ba.getBytes();
    };

    Sequence.prototype.toString = function(encoding='base64') {
        return new Buffer(this.toBytes()).toString(encoding);
    };

    return Sequence;

})();

der.Constructive = (function() {
    "use strict";
    
    function Constructive(opt) {
        var o = opt || {};
        this.tag = new asn1.der.Tag(o.tag || {
            class: asn1.der.CLASS_UNIVERSAL,
            type: asn1.der.TYPE_CONSTRUCTED,
            value: asn1.der.TAG_VALUE_SEQUENCE
        });
        this.optional = typeof o.optional === 'undefined' ? false : o.optional;
        this.present = typeof o.present === 'undefined' ? true : o.present;
        this.elements = o.elements || [];
        this.explicitTag = o.explicitTag;
    }

    Constructive.prototype.encodeSubField = function(baBuf) {
        this.elements.forEach(function(element) {
            element.encode(baBuf);
        });
    };

    Constructive.prototype.encode = function(baBuf) {

        if (!this.present) return;

        var baMsg = this.tag.tagType === der.TAG_TYPE_EXPLICIT ? new ByteArray() : baBuf;

        // 子元素编码
        var baElm = new ByteArray();
        this.encodeSubField(baElm);

        var v = baElm.length > 0 ? baElm.getBytes() : [];

        // tag编码
        this.tag.encode(baMsg);
        // 长度编码
        new der.Length(v.length).encode(baMsg);
        // 值编码
        baMsg.appendBytes(v);

        if (this.tag.tagType === der.TAG_TYPE_EXPLICIT) {
            var vv = baMsg.getBytes();
            // explicit tag
            this.explicitTag.encode(baBuf);
            // Length
            new der.Length(vv.length).encode(baBuf);
            // Value
            baBuf.appendBytes(vv);
        }
    };

    Constructive.prototype.decodeSubField = function(baBuf, start, end) {
        var tag = new der.Tag();
        this.elements.forEach(function(element) {
            if (element.optional) {
                if (start >= end) {
                    element.present = false;
                    return;
                }
                var elmTag = element.tag.tagType === der.TAG_TYPE_EXPLICIT ? element.explicitTag.value : element.tag.tagValue;
                tag.decode(baBuf, start, end);
                if (tag.value != elmTag) {
                    element.present = false;
                    return;
                }
            }
            element.present = true;
            start += element.decode(baBuf, start, end);
        });
    };

    Constructive.prototype.decode = function(baBuf, start, end) {
        end = typeof end === 'undefined' ? baBuf.length : end;
        start = start || 0;
        var etaglen = 0;
    
        if (this.tag.tagType === der.TAG_TYPE_EXPLICIT) {
            var istart = start;
            start += this.explicitTag.decode(baBuf, start, end);
            start += new der.Length().decode(baBuf, start, end);
            etaglen = start - istart;
        }

        // tag解码
        var tl = this.tag.decode(baBuf, start, end);
        // length解码
        var len = new der.Length();
        var ll = len.decode(baBuf, start + tl, end);
        var mlen = tl + ll + len.len;
        var elmEnd = start + mlen;
        if (end < elmEnd) {
            throw "Constructive decode error, the message buffer is too short";
        }
        // elements解码
        start += tl + ll;

        // 子元素解码
        if (len.len > 0) this.decodeSubField(baBuf, start, elmEnd);

        return mlen + etaglen;
    };

    Constructive.prototype.toBytes = function() {
        var ba = new ByteArray();
        this.encode(ba);
        return ba.getBytes();
    };

    Constructive.prototype.toString = function(encoding='base64') {
        return new Buffer(this.toBytes()).toString(encoding);
    };

    return Constructive;

})();

der.Set = (function() {
    "use strict";
    
    function Set(opt) {
        var o = opt || {};
        this.sequence = o.sequence || false;
        this.tag = new asn1.der.Tag(o.tag || {
            class: asn1.der.CLASS_UNIVERSAL,
            type: asn1.der.TYPE_CONSTRUCTED,
            value: this.sequence ? asn1.der.TAG_VALUE_SEQUENCE : asn1.der.TAG_VALUE_SET
        });
        this.optional = typeof o.optional === 'undefined' ? false : o.optional;
        this.present = typeof o.present === 'undefined' ? true : o.present;
        this.elements = o.elements || [];
        this.elementCreator = o.elementCreator || function() {return new der.Primitive();}
        this.explicitTag = o.explicitTag;
    }

    Set.prototype.encode = function(baBuf) {

        if (!this.present) return;

        var baMsg = this.tag.tagType === der.TAG_TYPE_EXPLICIT ? new ByteArray() : baBuf;

        if (this.sequence) {
            // 子元素编码
            this.elements.forEach(function(element) {
                element.encode(baMsg);
            });
        } else {
            if (this.tag.tagType === der.TAG_TYPE_IMPLICIT) {
                // 子元素编码
                var baElm = new ByteArray();
                this.elements.forEach(function(element) {
                    element.encode(baElm);
                });
                if (baElm.length > 0) {
                    var v = baElm.getBytes();
                    // tag编码
                    this.tag.encode(baMsg);
                    // 长度编码
                    new der.Length(v.length).encode(baMsg);
                    // 值编码
                    baMsg.appendBytes(v);
                }
            } else {
                // 子元素编码
                var baElm = new ByteArray();
                var tag = this.tag;
                this.elements.forEach(function(element) {
                    
                    element.encode(baElm);

                    if (baElm.length > 0) {
                        var v = baElm.getBytes();
                        // tag编码
                        tag.encode(baMsg);
                        // 长度编码
                        new der.Length(v.length).encode(baMsg);
                        // 值编码
                        baMsg.appendBytes(v);
                        // 重置
                        baElm.clear();
                    }
                });
                // 没有元素的情况
                if ((!this.optional || this.present) && this.elements.length === 0) {
                    this.tag.encode(baMsg);
                    new der.Length(0).encode(baMsg);
                }
            }
        }

        if (this.tag.tagType === der.TAG_TYPE_EXPLICIT) {
            var v = baMsg.getBytes();
            // explicit tag
            this.explicitTag.encode(baBuf);
            // Length
            new der.Length(v.length).encode(baBuf);
            // Value
            baBuf.appendBytes(v);
        }
    };

    Set.prototype.decode = function(baBuf, start, end) {
        end = typeof end === 'undefined' ? baBuf.length : end;
        start = start || 0;

        var etaglen = 0;

        if (this.tag.tagType === der.TAG_TYPE_EXPLICIT) {
            var istart = start;
            start += this.explicitTag.decode(baBuf, start, end);
            start += new der.Length().decode(baBuf, start, end);
            etaglen = start - istart;
        }
    
        this.elements = [];

        var mlen = 0;
        var tag = new der.Tag();
        var len = new der.Length();

        if (this.sequence) {
            while (start < end) {
                // tag解码
                var tl = tag.decode(baBuf, start, end);

                if (tag.value !== this.tag.tagValue) {
                    break;
                }

                var elm = this.elementCreator();
                var elen = elm.decode(baBuf, start, end);
                this.elements.push(elm);
                mlen += elen;
                start += elen;
            }
        } else {
            if (this.tag.tagType === der.TAG_TYPE_IMPLICIT) {
                // tag解码
                var tl = this.tag.decode(baBuf, start, end);

                // length解码
                var ll = len.decode(baBuf, start + tl, end);
                var elen = tl + ll + len.len;
                if (end < start + elen) {
                    throw "Set decode error, the message buffer is too short";
                }

                // elements解码
                start += tl + ll;
                mlen += tl + ll;
                if (len.len > 0) {
                    var elmEnd = start + len.len;
                    while (start < elmEnd) {
                        var elm = this.elementCreator();
                        elen = elm.decode(baBuf, start, elmEnd);
                        this.elements.push(elm);
                        start += elen;
                        mlen += elen;
                    }
                }
            } else {
                while (start < end) {
                    // tag解码
                    var tl = tag.decode(baBuf, start, end);
                    if (tag.value !== this.tag.tagValue) {
                        break;
                    }
                    // length解码
                    var ll = len.decode(baBuf, start + tl, end);
                    if (len.len <= 0) {
                        mlen += tl + ll;
                        break;
                    }

                    var elen = tl + ll + len.len;
                    if (end < start + elen) {
                        throw "Set decode error, the message buffer is too short";
                    }
                    // elements解码
                    start += tl + ll;
                    var elm = this.elementCreator();
                    start += elm.decode(baBuf, start, end);
                    this.elements.push(elm);
                    mlen += elen;
                }
            }
        }

        return mlen + etaglen;
    };

    Set.prototype.toJson = function() {
        var o = [];

        this.elements.forEach(function(element) {
            o.push(element.toJson());
        });

        return o;
    };

    Set.prototype.toBytes = function() {
        var ba = new ByteArray();
        this.encode(ba);
        return ba.getBytes();
    };

    Set.prototype.toString = function(encoding='base64') {
        return new Buffer(this.toBytes()).toString(encoding);
    };

    return Set;

})();

// Node.js check
if (typeof module !== "undefined" && module.hasOwnProperty("exports")) {
    module.exports = asn1;
}

// amd check
if (typeof define === "function" && define.amd) {
    define("asn-der", [], function() {
        return asn1;
    });
}