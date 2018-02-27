export class Whirlpool {
    getHash(message: String): String;
}

export namespace encoders {
    // function fromUtf(message: string): String
    function toHex(message: String): String

    function toBase64(input: String): String

    function fromBase64(input: String): String

    function fromUtf(input: String): String
}


