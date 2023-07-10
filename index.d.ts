export class Whirlpool {
    constructor(options?: {
        type?: 't' | '0' | '',
        rounds?: number
    });
    getHash(message: string): string;
}

export namespace encoders {
    // function fromUtf(message: string): String
    function toHex(message: string): string

    function toBase64(input: string): string

    function fromBase64(input: string): string

    function fromUtf(input: string): string
}


