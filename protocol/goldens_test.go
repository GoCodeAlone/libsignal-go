package protocol

// Golden wire encodings for the Task 10 message types, built from fixed keys
// and fixed signature nonces (see each test for the exact inputs). These are
// self-generated layout locks (NOT upstream vectors); Task 12 replaces them
// with upstream test vectors. They guard against accidental wire-layout changes
// in the interim.
const (
	goldenSenderKeyMessageHex             = "330a108c78cd2a16ff427d83dc1a5e36ce713d108486880818888e98282206676f6c64656e0992f965a5c273a68b6fdd548ce6304c7244ac2896a110da828b385111da62cd4a9bc9d6bd7e4c6b23c53f04e484ecd6b90f4800816122b00561fe965b80a30e"
	goldenSenderKeyDistributionMessageHex = "330a108c78cd2a16ff427d83dc1a5e36ce713d108486880818888e98282220abababababababababababababababababababababababababababababababab2a2105358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
	goldenDecryptionErrorMessageHex       = "0a210534e42d4af5ef94a07a3a84201b889d4cd1a743cb27b11b6a10438a8feb8e58471088ef99abc5e88c91111809"
	goldenPlaintextContentHex             = "c0422f0a210534e42d4af5ef94a07a3a84201b889d4cd1a743cb27b11b6a10438a8feb8e58471088ef99abc5e88c9111180980"
)
