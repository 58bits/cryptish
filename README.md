cryptish
=========

A fast and furious set of crypto utilities.

(with fixedTimeComparison, randomBits, randomString from [Cryptiles](https://github.com/hueniverse/cryptiles) and copyright Eran Hammer)

## Methods

### `randomString(<Number> size)`
Returns a cryptographically strong pseudo-random data string. Takes a size argument for the length of the string and returns a safe string token (with / = + removed).

### `randomBits(<Number> size)`
Returns a cryptographically buffer. Takes a size argument in bits.

### `generateSalt(<Number> size)`
Returns a cryptographic salt value. Takes a size argument in bits, and returns a base64 encoded string.

### `hashPassword(<String> password, <String> salt)`
Returns a pbkdf2 cryptographically hashed password. Takes password and salt as arguments.

### `verifyPassword(<String> password, <String> storedValue)`
Returns true or false for a comparision of a pbkdf2 cryptographically hashed password.

### `fixedTimeComparison(<String> a, <String> b)`
Compare two strings using fixed time algorithm (to prevent time-based analysis of MAC digest match). Returns `true` if the strings match, `false` if they differ.

### `binaryToBase64(<Buffer> buffer)`
Convert a buffer to a base64 encoded string

### `base64ToBuffer(<String> string)`
Convert a base64 encoded string to a binary buffer.

### `sha256(<String> string)`
Perform sha256 hash on input returning hex digest.
