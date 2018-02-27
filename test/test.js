function test(whirlpool) {


    var message = whirlpool.encoders.fromUtf('message');
    var messageToHashToBase64 = 'Oigu+crBYZFCGIKHAxA63FZMhhceaH1Gi40tPCMthadhKyFsJv8dhfgNlXmFSVK3+9t+f5kGjDRq8os05C3Q/w==';
    var messageToBase64 = 'bWVzc2FnZQ==';
    var messageToHex = '6d657373616765';

    var wh = new whirlpool.Whirlpool();

    var hash = wh.getHash(message);
    console.assert(hash, 'Hash is null');
    console.assert(hash !== '', 'Hash is empty');

    var base64 = whirlpool.encoders.toBase64(hash);
    console.assert(messageToHashToBase64 == base64, 'base64 is not equal messageToHashToBase64');

    var fromBase64 = whirlpool.encoders.fromBase64(messageToBase64);
    console.assert(message === fromBase64, 'fromBase64 is not equal messageToBase64');

    var hex = whirlpool.encoders.toHex(message);
    console.assert(messageToHex === hex, 'hex is not equal message');
    console.log("END")
}

if (typeof global == 'object') {
    module.exports = test
}
