;(function (root) {
    /*----------------------------AMD----------------------------------------------*/
    // Detect free variables `exports`.
    var freeExports = typeof exports == 'object' && exports;

    // Detect free variable `module`.
    var freeModule = typeof module == 'object' && module &&
        module.exports == freeExports && module;

    // Detect free variable `global`, from Node.js or Browserified code, and use
    // it as `root`.
    var freeGlobal = typeof global == 'object' && global;
    if (freeGlobal.global === freeGlobal || freeGlobal.window === freeGlobal) {
        root = freeGlobal;
    }

    /*-----------------------------Whirlpool---------------------------------------------*/


    /**
     * Base hasher class
     * @interface
     */
    class Hasher {
        /**
         * @param {Object} options
         * @constructor
         */
        constructor(options) {
            /**
             * Size of unit in bytes (4 = 32 bits)
             * @type {number}
             */
            this.unitSize = 4;
            /**
             * Bytes order in unit
             *   0 - normal
             *   1 - reverse
             * @type {number}
             */
            this.unitOrder = 0;
            /**
             * Size of block in units
             * @type {number}
             */
            this.blockSize = 16;
            /**
             * Size of block in bytes
             * @type {number}
             */
            this.blockSizeInBytes = this.blockSize * this.unitSize;
            /**
             * All algorithm variables that changed during process
             * @protected
             * @type {Object}
             * @property {string} state.message - Unprocessed Message
             * @property {number} state.length - Length of message
             */
            this.state = {};
            this.state.message = '';
            this.state.length = 0;
            /**
             * Options from initialization
             * @protected
             * @type {Object}
             */
            this.options = options || {};
        }

        /**
         * Reset hasher to initial state
         */
        reset() {
            this.state = {};
            this.constructor(this.options);
        }

        /**
         * Return current state
         *
         * @returns {Object}
         */
        getState() {
            return JSON.parse(JSON.stringify(this.state));
        }

        /**
         * Set current state
         *
         * @param {Object} state
         */
        setState(state) {
            this.state = state;
        }

        /**
         * Update message from binary string
         *
         * @param {string} message
         */
        update(message) {
            this.state.message += message;
            this.state.length += message.length;
            this.process();
        }

        /**
         * Process ready blocks
         *
         * @protected
         */
        process() {
        }

        /**
         * Finalize hash and return result
         *
         * @returns {string}
         */
        finalize() {
            return '';
        }

        /**
         * Get hash from state
         *
         * @protected
         * @param {number} [size=this.state.hash.length] - Limit hash size (in chunks)
         * @returns {string}
         */
        getStateHash(size) {
            return '';
        }

        /**
         * Add PKCS7 padding to message
         *
         * @protected
         * @param {number} length
         */
        addPaddingPKCS7(length) {
            this.state.message += new Array(length + 1).join(String.fromCharCode(length));
        }

        /**
         * Add ISO7816 padding to message
         *
         * @protected
         * @param {number} length
         */
        addPaddingISO7816(length) {
            this.state.message += "\x80" + new Array(length).join("\x00");
        }

        /**
         * Add zero padding to message
         *
         * @protected
         * @param {number} length
         */
        addPaddingZero(length) {
            this.state.message += new Array(length + 1).join("\x00");
        }
    }

    /**
     * Hasher for 32 bit big endian blocks
     * @interface
     */
    class Hasher32be extends Hasher {
        /**
         * @param {Object} [options]
         */
        constructor(options) {
            super(options);

            /**
             * Reverse order of bytes
             * @type {number}
             */
            this.unitOrder = 1;
            /**
             * Current block (only for speed optimization)
             * @private
             * @type {number[]}
             */
            this.blockUnits = [];
        }

        /**
         * Process ready blocks
         *
         * @protected
         */
        process() {
            while (this.state.message.length >= this.blockSizeInBytes) {
                this.blockUnits = [];
                for (let b = 0; b < this.blockSizeInBytes; b += 4) {
                    this.blockUnits.push(this.state.message.charCodeAt(b) << 24 | this.state.message.charCodeAt(b + 1) << 16 |
                        this.state.message.charCodeAt(b + 2) << 8 | this.state.message.charCodeAt(b + 3));
                }
                this.state.message = this.state.message.substr(this.blockSizeInBytes);
                this.processBlock(this.blockUnits);
            }
        }

        /**
         * Process ready blocks
         *
         * @protected
         * @param {number[]} M
         */
        processBlock(M) {
        }

        /**
         * Get hash from state
         *
         * @protected
         * @param {number} [size=this.state.hash.length] - Limit hash size (in chunks)
         * @returns {string}
         */
        getStateHash(size) {
            size = size || this.state.hash.length;
            let hash = '';
            for (let i = 0; i < size; i++) {
                hash += String.fromCharCode(this.state.hash[i] >> 24 & 0xff) +
                    String.fromCharCode(this.state.hash[i] >> 16 & 0xff) +
                    String.fromCharCode(this.state.hash[i] >> 8 & 0xff) +
                    String.fromCharCode(this.state.hash[i] & 0xff);
            }
            return hash;
        }

        /**
         * Add to message cumulative size of message in bits
         *
         * @protected
         */
        addLengthBits() {
            // @todo fix length to 64 bit
            this.state.message += "\x00\x00\x00\x00";
            let lengthBits = this.state.length << 3;
            for (let i = 3; i >= 0; i--) {
                this.state.message += String.fromCharCode(lengthBits >> (i << 3));
            }
        }
    }


    /**
     * Rotate x to n bits left
     *
     * @param {number} x
     * @param {number} n
     * @returns {number}
     */
    function rotateLeft(x, n) {
        return ((x << n) | (x >>> (32 - n))) | 0;
    }

    /**
     * Rotate x to n bits right
     * @param {number} x
     * @param {number} n
     * @returns {number}
     */
    function rotateRight(x, n) {
        return ((x >>> n) | (x << (32 - n))) | 0;
    }

    /**
     * Rotate 64bit to n bits right and return hi
     *
     * @param {number} hi
     * @param {number} lo
     * @param {number} n
     * @returns {number}
     */
    function rotateRight64hi(hi, lo, n) {
        if (n === 32) {
            return lo;
        }
        if (n > 32) {
            return rotateRight64hi(lo, hi, n - 32);
        }
        return ((hi >>> n) | (lo << (32 - n))) & (0xFFFFFFFF);
    }

    /**
     * Rotate 64bit to n bits right and return lo
     *
     * @param {number} hi
     * @param {number} lo
     * @param {number} n
     * @returns {number}
     */
    function rotateRight64lo(hi, lo, n) {
        if (n === 32) {
            return hi;
        }
        if (n > 32) {
            return rotateRight64lo(lo, hi, n - 32);
        }
        return ((lo >>> n) | (hi << (32 - n))) & (0xFFFFFFFF);
    }


//Whirlpool
    /** @type {number[]} */
    const SBOX = new Array(256);
    /** @type {number[]} */
    const SBOX0 = [
        0x68, 0xd0, 0xeb, 0x2b, 0x48, 0x9d, 0x6a, 0xe4, 0xe3, 0xa3, 0x56, 0x81,
        0x7d, 0xf1, 0x85, 0x9e, 0x2c, 0x8e, 0x78, 0xca, 0x17, 0xa9, 0x61, 0xd5,
        0x5d, 0x0b, 0x8c, 0x3c, 0x77, 0x51, 0x22, 0x42, 0x3f, 0x54, 0x41, 0x80,
        0xcc, 0x86, 0xb3, 0x18, 0x2e, 0x57, 0x06, 0x62, 0xf4, 0x36, 0xd1, 0x6b,
        0x1b, 0x65, 0x75, 0x10, 0xda, 0x49, 0x26, 0xf9, 0xcb, 0x66, 0xe7, 0xba,
        0xae, 0x50, 0x52, 0xab, 0x05, 0xf0, 0x0d, 0x73, 0x3b, 0x04, 0x20, 0xfe,
        0xdd, 0xf5, 0xb4, 0x5f, 0x0a, 0xb5, 0xc0, 0xa0, 0x71, 0xa5, 0x2d, 0x60,
        0x72, 0x93, 0x39, 0x08, 0x83, 0x21, 0x5c, 0x87, 0xb1, 0xe0, 0x00, 0xc3,
        0x12, 0x91, 0x8a, 0x02, 0x1c, 0xe6, 0x45, 0xc2, 0xc4, 0xfd, 0xbf, 0x44,
        0xa1, 0x4c, 0x33, 0xc5, 0x84, 0x23, 0x7c, 0xb0, 0x25, 0x15, 0x35, 0x69,
        0xff, 0x94, 0x4d, 0x70, 0xa2, 0xaf, 0xcd, 0xd6, 0x6c, 0xb7, 0xf8, 0x09,
        0xf3, 0x67, 0xa4, 0xea, 0xec, 0xb6, 0xd4, 0xd2, 0x14, 0x1e, 0xe1, 0x24,
        0x38, 0xc6, 0xdb, 0x4b, 0x7a, 0x3a, 0xde, 0x5e, 0xdf, 0x95, 0xfc, 0xaa,
        0xd7, 0xce, 0x07, 0x0f, 0x3d, 0x58, 0x9a, 0x98, 0x9c, 0xf2, 0xa7, 0x11,
        0x7e, 0x8b, 0x43, 0x03, 0xe2, 0xdc, 0xe5, 0xb2, 0x4e, 0xc7, 0x6d, 0xe9,
        0x27, 0x40, 0xd8, 0x37, 0x92, 0x8f, 0x01, 0x1d, 0x53, 0x3e, 0x59, 0xc1,
        0x4f, 0x32, 0x16, 0xfa, 0x74, 0xfb, 0x63, 0x9f, 0x34, 0x1a, 0x2a, 0x5a,
        0x8d, 0xc9, 0xcf, 0xf6, 0x90, 0x28, 0x88, 0x9b, 0x31, 0x0e, 0xbd, 0x4a,
        0xe8, 0x96, 0xa6, 0x0c, 0xc8, 0x79, 0xbc, 0xbe, 0xef, 0x6e, 0x46, 0x97,
        0x5b, 0xed, 0x19, 0xd9, 0xac, 0x99, 0xa8, 0x29, 0x64, 0x1f, 0xad, 0x55,
        0x13, 0xbb, 0xf7, 0x6f, 0xb9, 0x47, 0x2f, 0xee, 0xb8, 0x7b, 0x89, 0x30,
        0xd3, 0x7f, 0x76, 0x82
    ];
    /** @type {number[]} */
    const eBOX = [
        0x1, 0xb, 0x9, 0xc, 0xd, 0x6, 0xf, 0x3,
        0xe, 0x8, 0x7, 0x4, 0xa, 0x2, 0x5, 0x0
    ];
    /** @type {number[]} */
    const rBOX = [
        0x7, 0xc, 0xb, 0xd, 0xe, 0x4, 0x9, 0xf,
        0x6, 0x3, 0x8, 0xa, 0x2, 0x5, 0x1, 0x0
    ];
    /** @type {number[]} */
    const iBOX = new Array(16);
    /** @type {number[]} */
    const theta = [1, 1, 4, 1, 8, 5, 2, 9];
    /** @type {number[]} */
    const theta0 = [1, 1, 3, 1, 5, 8, 9, 5];
    /** @type {Array[]} */
    let C = new Array(512);
    /** @type {number[]} */
    let RC = new Array(22);
    /** @type {Array[]} */
    let C0 = new Array(512);
    /** @type {number[]} */
    let RC0 = new Array(22);
    /** @type {Array[]} */
    let CT = new Array(512);
    /** @type {number[]} */
    let RCT = new Array(22);

    /**
     * Calculates SBOX from eBOX & rBOX
     *
     * @private
     * @returns {void}
     */
    function calculateSBOX() {
        for (let i = 0; i < 16; i++) {
            iBOX[eBOX[i]] = i | 0;
        }
        for (let i = 0; i < 256; i++) {
            let left = eBOX[i >> 4];
            let right = iBOX[i & 0xf];
            let temp = rBOX[left ^ right];
            SBOX[i] = (eBOX[left ^ temp] << 4) | iBOX[right ^ temp];
        }
    }

    /**
     * Calculates C* & RC* transform tables
     *
     * @private
     * @param {number[]} SBOX
     * @param {number[]} theta
     * @returns {[Array[], number[]]}
     */
    function calculateRC(SBOX, theta) {
        /** @type {Array[]} */
        const C = new Array(512);
        /** @type {number[]} */
        const RC = new Array(22);

        for (let t = 0; t < 8; t++) {
            C[t] = [];
        }
        for (let i = 0; i < 256; i++) {
            let V = new Array(10);
            V[1] = SBOX[i];
            V[2] = V[1] << 1;
            if (V[2] >= 0x100) {
                V[2] ^= 0x11d;
            }
            V[3] = V[2] ^ V[1];
            V[4] = V[2] << 1;
            if (V[4] >= 0x100) {
                V[4] ^= 0x11d;
            }
            V[5] = V[4] ^ V[1];
            V[8] = V[4] << 1;
            if (V[8] >= 0x100) {
                V[8] ^= 0x11d;
            }
            V[9] = V[8] ^ V[1];

            // build the circulant table C[0][x] = S[x].[1, 1, 4, 1, 8, 5, 2, 9] | S[x].[1, 1, 3, 1, 5, 8, 9, 5]
            C[0][i * 2] = (V[theta[0]] << 24) | (V[theta[1]] << 16) | (V[theta[2]] << 8) | V[theta[3]];
            C[0][i * 2 + 1] = (V[theta[4]] << 24) | (V[theta[5]] << 16) | (V[theta[6]] << 8) | V[theta[7]];

            // build the remaining circulant tables C[t][x] = C[0][x] rotr t
            for (let t = 1; t < 8; t++) {
                C[t][i * 2] = rotateRight64lo(C[0][i * 2 + 1], C[0][i * 2], t << 3);
                C[t][i * 2 + 1] = rotateRight64hi(C[0][i * 2 + 1], C[0][i * 2], t << 3);
            }
        }
        // build the round constants
        RC[0] = 0;
        RC[1] = 0;
        for (let i = 1; i <= 10; i++) {
            RC[i * 2] = (C[0][16 * i - 16] & 0xff000000) ^
                (C[1][16 * i - 14] & 0x00ff0000) ^
                (C[2][16 * i - 12] & 0x0000ff00) ^
                (C[3][16 * i - 10] & 0x000000ff);
            RC[i * 2 + 1] = (C[4][16 * i - 7] & 0xff000000) ^
                (C[5][16 * i - 5] & 0x00ff0000) ^
                (C[6][16 * i - 3] & 0x0000ff00) ^
                (C[7][16 * i - 1] & 0x000000ff);
        }

        return [C, RC];
    }

// Build transform tables
    (function () {
        calculateSBOX();

        // whirlpool-0
        let x = calculateRC(SBOX0, theta0);
        C0 = x[0];
        RC0 = x[1];
        // whirlpool-t
        x = calculateRC(SBOX, theta0);
        CT = x[0];
        RCT = x[1];
        // whirlpool
        x = calculateRC(SBOX, theta);
        C = x[0];
        RC = x[1];
    })();

    /**
     * Calculates [WHIRLPOOL (WHIRLPOOL-0, WHIRLPOOL-T)](http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html) hash
     */
    class Whirlpool extends Hasher32be {
        /**
         * @param {Object} [options]
         * @param {number} [options.rounds=10] - Number of rounds (Can be from 1 to 10)
         * @param {string} [options.type] - Algorithm type
         *
         * | Hash type   | Type      |
         * |-------------|-----------|
         * | whirlpool-0 | '0'       |
         * | whirlpool-t | 't'       |
         * | whirlpool   | undefined |
         */
        constructor(options) {
            super(options);

            this.options.type = this.options.type || '';
            this.options.rounds = this.options.rounds || 10;

            this.state.hash = new Array(16);
            for (let i = 0; i < 16; i++) {
                this.state.hash[i] = 0;
            }

            switch (this.options.type) {
                case '0':
                case 0:
                    /**
                     *  @type {{number[]}[]}
                     *  @ignore
                     *  */
                    this.C = C0;
                    /**
                     *  @type {number[]}
                     *  @ignore
                     *  */
                    this.RC = RC0;
                    break;
                case 't':
                    this.C = CT;
                    this.RC = RCT;
                    break;
                default:
                    this.C = C;
                    this.RC = RC;
            }
        }

        /**
         * Process ready blocks
         *
         * @protected
         * @ignore
         * @param {number[]} block - Block
         */
        processBlock(block) {
            // compute and apply K^0 to the cipher state
            let K = new Array(16);
            let state = [];
            for (let i = 0; i < 16; i++) {
                state[i] = block[i] ^ (K[i] = this.state.hash[i]) | 0;
            }

            // iterate over all rounds
            let L = [];
            for (let r = 1; r <= this.options.rounds; r++) {
                // compute K^r from K^{r-1}
                for (let i = 0; i < 8; i++) {
                    L[i * 2] = 0;
                    L[i * 2 + 1] = 0;
                    for (let t = 0, s = 56, j = 0; t < 8; t++, s -= 8, j = s < 32 ? 1 : 0) {
                        L[i * 2] ^= this.C[t][((K[((i - t) & 7) * 2 + j] >>> (s % 32)) & 0xff) * 2];
                        L[i * 2 + 1] ^= this.C[t][((K[((i - t) & 7) * 2 + j] >>> (s % 32)) & 0xff) * 2 + 1];
                    }
                }
                for (let i = 0; i < 16; i++) {
                    K[i] = L[i];
                }
                K[0] ^= this.RC[r * 2];
                K[1] ^= this.RC[r * 2 + 1];

                // apply the r-th round transformation
                for (let i = 0; i < 8; i++) {
                    L[i * 2] = K[i * 2];
                    L[i * 2 + 1] = K[i * 2 + 1];
                    for (let t = 0, s = 56, j = 0; t < 8; t++, s -= 8, j = s < 32 ? 1 : 0) {
                        L[i * 2] ^= this.C[t][((state[((i - t) & 7) * 2 + j] >>> (s % 32)) & 0xff) * 2];
                        L[i * 2 + 1] ^= this.C[t][((state[((i - t) & 7) * 2 + j] >>> (s % 32)) & 0xff) * 2 + 1];
                    }
                }
                for (let i = 0; i < 16; i++) {
                    state[i] = L[i];
                }
            }
            // apply the Miyaguchi-Preneel compression function
            for (let i = 0; i < 16; i++) {
                this.state.hash[i] ^= state[i] ^ block[i];
            }
        }

        /**
         * Finalize hash and return result
         *
         * @returns {string}
         */
        finalize() {
            this.addPaddingISO7816(
                this.state.message.length < 32 ?
                    (56 - this.state.message.length) | 0 :
                    (120 - this.state.message.length) | 0);
            this.addLengthBits();
            this.process();
            return this.getStateHash();
        }


        /**
         * Return hash result
         * @param {string} message
         * @returns {string}
         */
        getHash(message) {
            this.update(message);
            return this.finalize();
        }
    }


    /*---------------------------------fromUtf-----------------------------------------*/
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

    /*----------------------------------toHex----------------------------------------*/
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


    /*--------------------------------BASE64------------------------------------------*/

    var InvalidCharacterError = function (message) {
        this.message = message;
    };
    InvalidCharacterError.prototype = new Error;
    InvalidCharacterError.prototype.name = 'InvalidCharacterError';

    var error = function (message) {
        // Note: the error messages used throughout this file match those used by
        // the native `atob`/`btoa` implementation in Chromium.
        throw new InvalidCharacterError(message);
    };

    var TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

    var REGEX_SPACE_CHARACTERS = /[\t\n\f\r ]/g;

    var decode = function (input) {
        input = String(input)
            .replace(REGEX_SPACE_CHARACTERS, '');
        var length = input.length;
        if (length % 4 == 0) {
            input = input.replace(/==?$/, '');
            length = input.length;
        }
        if (
            length % 4 == 1 ||
            // http://whatwg.org/C#alphanumeric-ascii-characters
            /[^+a-zA-Z0-9/]/.test(input)
        ) {
            error(
                'Invalid character: the string to be decoded is not correctly encoded.'
            );
        }
        var bitCounter = 0;
        var bitStorage;
        var buffer;
        var output = '';
        var position = -1;
        while (++position < length) {
            buffer = TABLE.indexOf(input.charAt(position));
            bitStorage = bitCounter % 4 ? bitStorage * 64 + buffer : buffer;
            // Unless this is the first of a group of 4 characters…
            if (bitCounter++ % 4) {
                // …convert the first 8 bits to a single ASCII character.
                output += String.fromCharCode(
                    0xFF & bitStorage >> (-2 * bitCounter & 6)
                );
            }
        }
        return output;
    };

    var encode = function (input) {
        input = String(input);
        if (/[^\0-\xFF]/.test(input)) {
            // Note: no need to special-case astral symbols here, as surrogates are
            // matched, and the input is supposed to only contain ASCII anyway.
            error(
                'The string to be encoded contains characters outside of the ' +
                'Latin1 range.'
            );
        }
        var padding = input.length % 3;
        var output = '';
        var position = -1;
        var a;
        var b;
        var c;
        var d;
        var buffer;
        // Make sure any padding is handled outside of the loop.
        var length = input.length - padding;

        while (++position < length) {
            // Read three bytes, i.e. 24 bits.
            a = input.charCodeAt(position) << 16;
            b = input.charCodeAt(++position) << 8;
            c = input.charCodeAt(++position);
            buffer = a + b + c;
            // Turn the 24 bits into four chunks of 6 bits each, and append the
            // matching character for each of them to the output.
            output += (
                TABLE.charAt(buffer >> 18 & 0x3F) +
                TABLE.charAt(buffer >> 12 & 0x3F) +
                TABLE.charAt(buffer >> 6 & 0x3F) +
                TABLE.charAt(buffer & 0x3F)
            );
        }

        if (padding == 2) {
            a = input.charCodeAt(position) << 8;
            b = input.charCodeAt(++position);
            buffer = a + b;
            output += (
                TABLE.charAt(buffer >> 10) +
                TABLE.charAt((buffer >> 4) & 0x3F) +
                TABLE.charAt((buffer << 2) & 0x3F) +
                '='
            );
        } else if (padding == 1) {
            buffer = input.charCodeAt(position);
            output += (
                TABLE.charAt(buffer >> 2) +
                TABLE.charAt((buffer << 4) & 0x3F) +
                '=='
            );
        }

        return output;
    };

    /**
     * Convert binary result of hash to Base64
     *
     * @param {string} input
     * @returns {string}
     */
    function toBase64(input) {
        return encode(input);
    }

    /**
     * Convert Base64 result of hash to binary
     *
     * @param {string} input
     * @returns {string}
     */
    function fromBase64(input) {
        return decode(input)
    }

    /*-----------------------------RESULT--------------------------------------------*/
    const result = {
        Whirlpool,
        encoders: {
            toHex, fromBase64, toBase64, fromUtf
        }
    };
    /*------------------------------AMD Module--------------------------------------------*/
    // Some AMD build optimizers, like r.js, check for specific condition patterns
    // like the following:
    if (typeof define == 'function' && typeof define.amd == 'object' && define.amd) {
        define(function () {
            return result
        });
    } else if (freeExports && !freeExports.nodeType) {
        if (freeModule) { // in Node.js or RingoJS v0.8.0+

            freeModule.exports = result
        } else { // in Narwhal or RingoJS v0.7.0-
            for (var key in result) {
                result.hasOwnProperty(key) && (freeExports[key] = result[key]);
            }
        }
    } else { // in Rhino or a web browser
        root.whirlpool = result
    }
}(this));


