import { SerializableHash } from "@stablelib/hash";
import { readUint32LE, writeUint32LE } from "@stablelib/binary";
import { wipe } from "@stablelib/wipe";
const arrayBufferToHex = require("array-buffer-to-hex");

export const DIGEST_LENGTH = 16;
export const BLOCK_SIZE = 64;

export class MD5 implements SerializableHash {
    /** Length of hash output */
    readonly digestLength: number = DIGEST_LENGTH;
    /** Block size */
    readonly blockSize: number = BLOCK_SIZE;

    protected _state = new Int32Array(4);
    private _temp = new Int32Array(64);
    private _buffer = new Uint8Array(128);
    private _bufferLength = 0;
    private _bytesHashed = 0;
    private _finished = false;

    constructor() {
        this.reset()
    }

    protected _initState() {
        this._state[0] = 0x67452301;
        this._state[1] = 0xefcdab89;
        this._state[2] = 0x98badcfe;
        this._state[3] = 0x10325476;
    }

    /**
     * Resets hash state making it possible
     * to re-use this instance to hash other data.
     */
    reset(): this {
        this._initState();
        this._bufferLength = 0;
        this._bytesHashed = 0;
        this._finished = false;
        return this;
    }

    /**
     * Cleans internal buffers and resets hash state.
     */
    clean() {
        wipe(this._buffer);
        wipe(this._temp);
        this.reset();
    }

    /**
     * Updates hash state with the given data.
     *
     * Throws error when trying to update already finalized hash:
     * instance must be reset to update it again.
     */
    update(data: Uint8Array, dataLength: number = data.length): this {
        if (this._finished) {
            throw new Error("MD5: can't update because hash was finished.");
        }
        let dataPos = 0;
        this._bytesHashed += dataLength;
        if (this._bufferLength > 0) {
            while (this._bufferLength < this.blockSize && dataLength > 0) {
                this._buffer[this._bufferLength++] = data[dataPos++];
                dataLength--;
            }
            if (this._bufferLength === this.blockSize) {
                hashBlocks(this._temp, this._state, this._buffer, 0, this.blockSize);
                this._bufferLength = 0;
            }
        }
        if (dataLength >= this.blockSize) {
            dataPos = hashBlocks(this._temp, this._state, data, dataPos, dataLength);
            dataLength %= this.blockSize;
        }
        while (dataLength > 0) {
            this._buffer[this._bufferLength++] = data[dataPos++];
            dataLength--;
        }
        return this;
    }

    /**
     * Finalizes hash state and puts hash into out.
     * If hash was already finalized, puts the same value.
     */
    finish(out: Uint8Array): this {
        if (!this._finished) {
            const bytesHashed = this._bytesHashed;
            const left = this._bufferLength;
            const bitLenHi = (bytesHashed / 0x20000000) | 0;
            const bitLenLo = bytesHashed << 3;
            const padLength = ((bytesHashed) % 64 < 56) ? 64 : 128;

            this._buffer[left] = 0x80;
            for (let i = left + 1; i < padLength - 8; i++) {
                this._buffer[i] = 0;
            }
            writeUint32LE(bitLenLo, this._buffer, padLength - 8);
            writeUint32LE(bitLenHi, this._buffer, padLength - 4);

            hashBlocks(this._temp, this._state, this._buffer, 0, padLength);
            this._finished = true;
        }

        for (let i = 0; i < this.digestLength / 4; i++) {
            writeUint32LE(this._state[i], out, i * 4);
        }

        return this;
    }

    /**
     * Returns the final hash digest.
     */
    digest(): Uint8Array {
        const out = new Uint8Array(this.digestLength);
        this.finish(out);
        return out;
    }

    /**
     * Function useful for HMAC/PBKDF2 optimization.
     * Returns hash state to be used with restoreState().
     * Only chain value is saved, not buffers or other
     * state variables.
     */
    saveState(): SavedState {
        if (this._finished) {
            throw new Error("SHA256: cannot save finished state");
        }
        return {
            state: new Int32Array(this._state),
            buffer: this._bufferLength > 0 ? new Uint8Array(this._buffer) : undefined,
            bufferLength: this._bufferLength,
            bytesHashed: this._bytesHashed
        };
    }

    /**
     * Function useful for HMAC/PBKDF2 optimization.
     * Restores state saved by saveState() and sets bytesHashed
     * to the given value.
     */
    restoreState(savedState: SavedState): this {
        this._state.set(savedState.state);
        this._bufferLength = savedState.bufferLength;
        if (savedState.buffer) {
            this._buffer.set(savedState.buffer);
        }
        this._bytesHashed = savedState.bytesHashed;
        this._finished = false;
        return this;
    }

    /**
     * Cleans state returned by saveState().
     */
    cleanSavedState(savedState: SavedState) {
        wipe(savedState.state);
        if (savedState.buffer) {
            wipe(savedState.buffer);
        }
        savedState.bufferLength = 0;
        savedState.bytesHashed = 0;
    }
}

export type SavedState = {
    state: Int32Array;
    buffer: Uint8Array | undefined;
    bufferLength: number;
    bytesHashed: number;
};

const s = new Int8Array([
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21

])

const K = new Int32Array([
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
])

function leftrotate(x: number, c: number) {
    return (x << c) | (x >>> (32 - c));
}

function safeAdd(x: number, y: number): number {
    var lsw = (x & 0xffff) + (y & 0xffff)
    var msw = (x >> 16) + (y >> 16) + (lsw >> 16)
    return (msw << 16) | (lsw & 0xffff)
}

function hashBlocks(w: Int32Array, v: Int32Array, p: Uint8Array, pos: number, len: number): number {
    while (len >= 64) {
        let a = v[0];
        let b = v[1];
        let c = v[2];
        let d = v[3];

        for (let i = 0; i < 16; i++) {
            let j = pos + i * 4;
            w[i] = readUint32LE(p, j);
        }

        for (let i = 0; i < 64; i++) {
            let F = 0;
            let g = 0;
            if (i >= 0 && i <= 15) {
                F = d ^ (b & (c ^ d))
                g = i;
            } else if (i >= 16 && i <= 31) {
                F = c ^ (d & (b ^ c))
                g = (5 * i + 1) % 16;
            } else if (i >= 32 && i <= 47) {
                F = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            } else {
                F = c ^ (b | ~d);
                g = (7 * i) % 16;
            }
            F = safeAdd(F, safeAdd(a, safeAdd(K[i], w[g])));
            a = d;
            d = c;
            c = b;
            b = safeAdd(b, leftrotate(F, s[i]));
        }

        v[0] = safeAdd(v[0], a);
        v[1] = safeAdd(v[1], b);
        v[2] = safeAdd(v[2], c);
        v[3] = safeAdd(v[3], d);

        pos += 64;
        len -= 64;
    } 
    return pos;
}

export function hash(data: Uint8Array): Uint8Array {
    const h = new MD5();
    h.update(data);
    const digest = h.digest();
    h.clean();
    return digest;
}

export function md5(s: string): string {
    let enc = new TextEncoder();
    let arr = enc.encode(s);
    let h = hash(arr);
    return arrayBufferToHex(h.buffer);
}
