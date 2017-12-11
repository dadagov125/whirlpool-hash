'use strict';
import base64 from './base64';

/**
 * Convert UTF8/UTF16 string to binary input for hasher
 *
 * @param {string} message
 * @returns {string}
 */
function fromUtf(message) {
    let raw = '';
    for (let i = 0, msgLen = message.length; i < msgLen; i++) {
        let charCode = message.charCodeAt(i);
        if (charCode < 0x80) {
            raw += String.fromCharCode(charCode);
        }
        else if (charCode < 0x800) {
            raw += String.fromCharCode(0xc0 | (charCode >> 6));
            raw += String.fromCharCode(0x80 | (charCode & 0x3f));
        }
        else if (charCode < 0xd800 || charCode >= 0xe000) {
            raw += String.fromCharCode(0xe0 | (charCode >> 12));
            raw += String.fromCharCode(0x80 | ((charCode >> 6) & 0x3f));
            raw += String.fromCharCode(0x80 | (charCode & 0x3f));
        }
        // surrogate pair
        else {
            i++;
            // UTF-16 encodes 0x10000-0x10FFFF by
            // subtracting 0x10000 and splitting the
            // 20 bits of 0x0-0xFFFFF into two halves
            charCode = 0x10000 + (((charCode & 0x3ff) << 10)
                | (message.charCodeAt(i) & 0x3ff));
            raw += String.fromCharCode(0xf0 | (charCode >> 18));
            raw += String.fromCharCode(0x80 | ((charCode >> 12) & 0x3f));
            raw += String.fromCharCode(0x80 | ((charCode >> 6) & 0x3f));
            raw += String.fromCharCode(0x80 | (charCode & 0x3f));
        }
    }
    return raw;
}


/**
 * Convert binary result of hash to hex
 *
 * @param {string} raw
 * @returns {string}
 */
function toHex(raw) {
    let str = '';
    for (let i = 0, l = raw.length; i < l; i++) {
        str += (raw.charCodeAt(i) < 16 ? '0' : '') + raw.charCodeAt(i).toString(16);
    }
    return str;
}

/**
 * Convert binary result of hash to Base64
 *
 * @param {string} input
 * @returns {string}
 */
function toBase64(input) {
    return base64.encode(input);
}

/**
 * Convert Base64 result of hash to binary
 *
 * @param {string} input
 * @returns {string}
 */
function fromBase64(input) {
    return base64.decode(input)
}

export {fromUtf, toHex, toBase64, fromBase64};