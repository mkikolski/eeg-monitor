// hook_key.js — extract the EPOC X AES key from the Android app.
//
// Three vectors, ordered by signal strength:
//   1. libEmbeddedLibQt.so + 0x26f6518  ← BTLEDeviceFactory::getDeviceKey
//      Returns the AES key in a QByteArray (offset 0x70 of returned struct).
//      ARM64 ABI: non-trivial return → caller passes hidden ptr in x8.
//   2. libEmotivPRO_arm64-v8a.so AesCrypto::doCrypt(bool, key*, iv*, in*, n, out*, &outN)
//      args[1] = 16-byte key.
//   3. Generic AES_set_decrypt_key / AES_ecb_encrypt fallback across all modules.
//
// Also: libEmbeddedLibQt.so + 0x273abec  ← extractEmotivInfos
//      Logs what GATT chars feed the key derivation.

'use strict';

var GET_DEVICE_KEY_VA     = 0x26f6518;
var EXTRACT_INFOS_VA      = 0x273abec;
var QT_LIB                = 'libEmbeddedLibQt.so';
var EMOTIV_LIB            = 'libEmotivPRO_arm64-v8a.so';

var found_keys = new Set();
var pktCount   = 0;

function hexStr(ptr, len) {
    try {
        return Array.from(new Uint8Array(ptr.readByteArray(len)))
            .map(function (b) { return b.toString(16).padStart(2, '0'); })
            .join('');
    } catch (e) { return '(err:' + e.message + ')'; }
}

function recordKey(source, hex) {
    if (hex.length !== 32) {
        console.log('[KEY?] ' + source + ' wrong-length=' + hex);
        return;
    }
    // Filter UTF-16LE ASCII strings (every second byte == 0): not a key.
    var isUtf16Ascii = true;
    for (var i = 2; i < hex.length; i += 4) {
        if (hex.substr(i, 2) !== '00') { isUtf16Ascii = false; break; }
    }
    if (isUtf16Ascii) {
        console.log('[KEY?] ' + source + ' looks like UTF-16 string, skipping: ' + hex);
        return;
    }
    if (found_keys.has(hex)) return;
    found_keys.add(hex);
    console.log('[KEY] ★★★ ' + source + ' = ' + hex);
}

// ─── QByteArray dumper ────────────────────────────────────────────────────────
// Qt5: QByteArray { QArrayData* d; }
//   QArrayData = { int ref; int size; uint alloc:31; uint capRsvd:1; qptrdiff offset; }
//   Data lives at d + offset.
// Qt6: QByteArray { DataPtr { QArrayData* d; char* ptr; qsizetype size; } d; }
//   QArrayData = { QBasicAtomicInt ref; qsizetype size; qsizetype alloc; uint flags; }
//   Data is pointed to by d.ptr directly.
// We try Qt5 first, fall back to a fat-pointer scan.
function dumpQByteArray(qbaPtr, label) {
    try {
        // Try Qt5: single pointer to QArrayData
        var dPtr = qbaPtr.readPointer();
        if (dPtr.isNull()) {
            console.log('[' + label + '] QByteArray null');
            return null;
        }
        // Heuristic: Qt5 QArrayData has int size at +4
        var size5    = dPtr.add(4).readU32();
        var offset5  = dPtr.add(16).readS64();
        if (size5 > 0 && size5 < 1024 && offset5 > 0 && offset5 < 4096) {
            var dataPtr = dPtr.add(offset5.valueOf());
            var hex = hexStr(dataPtr, Math.min(size5, 32));
            console.log('[' + label + '] Qt5 size=' + size5 + ' data=' + hex);
            if (size5 >= 16) recordKey(label, hex.slice(0, 32));
            return { size: size5, data: dataPtr };
        }
        // Try Qt6 fat-pointer: { d, ptr, size }
        var ptr6   = qbaPtr.add(8).readPointer();
        var size6  = qbaPtr.add(16).readS64();
        if (size6 > 0 && size6 < 1024 && !ptr6.isNull()) {
            var hex6 = hexStr(ptr6, Math.min(size6.valueOf(), 32));
            console.log('[' + label + '] Qt6 size=' + size6 + ' data=' + hex6);
            if (size6 >= 16) recordKey(label, hex6.slice(0, 32));
            return { size: size6, data: ptr6 };
        }
        console.log('[' + label + '] unrecognised QByteArray layout — first 64B raw:');
        console.log('    qba   : ' + hexStr(qbaPtr, 64));
        console.log('    d     : ' + hexStr(dPtr, 64));
        return null;
    } catch (e) {
        console.log('[' + label + '] dump error: ' + e.message);
        return null;
    }
}

// ─── Wait for a module then run callback ─────────────────────────────────────
function whenModuleLoaded(name, cb) {
    var existing = Process.findModuleByName(name);
    if (existing) { cb(existing); return; }

    console.log('[*] Waiting for ' + name + ' to load...');
    var attempts = 0;
    var timer = setInterval(function () {
        attempts++;
        var m = Process.findModuleByName(name);
        if (m) {
            clearInterval(timer);
            console.log('[+] ' + name + ' loaded at ' + m.base + ' (' + attempts + ' polls)');
            cb(m);
        } else if (attempts > 600) {        // ~60 s
            clearInterval(timer);
            console.log('[-] gave up waiting for ' + name);
        }
    }, 100);
}

// ─── 1. getDeviceKey hook (highest priority) ─────────────────────────────────
whenModuleLoaded(QT_LIB, function (mod) {
    // Dump every AES/crypto-related INTERNAL symbol in libEmbeddedLibQt.so
    // so we can identify the EEG decrypt entry point.
    console.log('[*] Scanning ' + mod.name + ' internal symbols for crypto...');
    var cryptoSyms = 0;
    try {
        mod.enumerateSymbols().forEach(function (s) {
            if (s.type !== 'function') return;
            var n = s.name;
            if (/aes|rijndael|^AES_|EVP_|crypt|key_schedule|expand[Kk]ey/i.test(n)) {
                console.log('    ' + n + '  @ ' + s.address +
                            '  (+0x' + s.address.sub(mod.base).toString(16) + ')');
                cryptoSyms++;
            }
        });
        console.log('[*] ' + cryptoSyms + ' crypto-like symbols in ' + mod.name);
    } catch (e) {
        console.log('[-] symbol scan failed: ' + e.message);
    }

    var addr = mod.base.add(GET_DEVICE_KEY_VA);
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                // ARM64 hidden retval pointer is in x8
                this.retSlot = this.context.x8;
                this.thisPtr = this.context.x0;
                this.infoPtr = this.context.x1;  // InputDeviceInformation const&
                console.log('[hit] getDeviceKey this=' + this.thisPtr +
                            ' info=' + this.infoPtr +
                            ' retSlot=' + this.retSlot);
            },
            onLeave: function (retval) {
                // Dump the returned QByteArray
                if (this.retSlot && !this.retSlot.isNull()) {
                    dumpQByteArray(this.retSlot, 'getDeviceKey-ret');
                }
                // Walk the InputDeviceInformation struct in 8-byte strides.
                // At each offset, try to interpret as Qt6 QByteArray:
                //   { d:heap-ptr, ptr:heap-ptr, size:1..1024 }
                // Dump the data for any plausible match.
                if (this.infoPtr && !this.infoPtr.isNull()) {
                    var info = this.infoPtr;
                    for (var off = 0; off <= 0xf0; off += 8) {
                        try {
                            var p1 = info.add(off).readPointer();
                            var p2 = info.add(off + 8).readPointer();
                            var sz = info.add(off + 16).readS64().valueOf();
                            // Heap pointers on aarch64 Android are typically 0x70…0x7f range
                            var pp1 = p1.toString();
                            var pp2 = p2.toString();
                            var p1ok = pp1.length >= 10 && pp1.indexOf('0x7') === 0;
                            var p2ok = pp2.length >= 10 && pp2.indexOf('0x7') === 0;
                            if (p1ok && p2ok && sz >= 1 && sz <= 1024) {
                                console.log('[info+0x' + off.toString(16) + '] QBA size=' +
                                            sz + ' data=' + hexStr(p2, Math.min(sz, 64)));
                            }
                        } catch (e) { /* skip invalid offset */ }
                    }
                }
                // Also dump raw bytes of the InputDeviceInformation struct
                // so we can spot the key visually.
                if (this.infoPtr && !this.infoPtr.isNull()) {
                    try {
                        console.log('[info struct first 256B]');
                        console.log('    ' + hexStr(this.infoPtr, 256));
                    } catch (e) { /* skip */ }
                }
            }
        });
        console.log('[+] Hooked getDeviceKey @ ' + addr);
    } catch (e) {
        console.log('[-] getDeviceKey hook failed: ' + e.message);
    }

    // ─── extractEmotivInfos: see what feeds the key derivation ──────────────
    var infoAddr = mod.base.add(EXTRACT_INFOS_VA);
    try {
        Interceptor.attach(infoAddr, {
            onEnter: function (args) {
                this.outStruct = this.context.x0;   // typical: out struct ptr
                this.clientPtr = this.context.x1;
                console.log('[hit] extractEmotivInfos out=' + this.outStruct +
                            ' client=' + this.clientPtr);
            },
            onLeave: function () {
                if (this.outStruct && !this.outStruct.isNull()) {
                    console.log('[extractEmotivInfos] struct first 256B:');
                    console.log('    ' + hexStr(this.outStruct, 256));
                }
            }
        });
        console.log('[+] Hooked extractEmotivInfos @ ' + infoAddr);
    } catch (e) {
        console.log('[-] extractEmotivInfos hook failed: ' + e.message);
    }
});

// ─── 2. AesCrypto::doCrypt in libEmotivPRO ───────────────────────────────────
// C++ member functions: args[0] = this. Real args start at args[1].
//
// doCrypt(bool enc, const uchar* key, const uchar* iv, const uchar* in,
//         int inLen, uchar* out, int& outLen)
//   args[0]=this  [1]=enc  [2]=key  [3]=iv  [4]=in  [5]=inLen  [6]=out  [7]=&outLen
//
// decrypt/encrypt(const QByteArray& key, const QByteArray& iv, QByteArray& out)
//   args[0]=this  [1]=&keyQBA  [2]=&ivQBA  [3]=&outQBA
whenModuleLoaded(EMOTIV_LIB, function (mod) {
    var hits = 0;
    mod.enumerateSymbols().forEach(function (s) {
        if (s.type !== 'function') return;
        var name = s.name;
        var isDoCrypt = name.indexOf('doCrypt') !== -1;
        var isDecrypt = name.indexOf('AesCrypto7decrypt') !== -1 ||
                        name.indexOf('AesCrypto7encrypt') !== -1;
        if (!isDoCrypt && !isDecrypt && name.indexOf('AesCrypto') === -1) return;

        try {
            if (isDoCrypt) {
                Interceptor.attach(s.address, {
                    onEnter: function (args) {
                        try {
                            this.enc    = args[1].toInt32() & 1;
                            this.keyHex = hexStr(args[2], 16);
                            this.ivHex  = hexStr(args[3], 16);
                            this.inLen  = args[5].toInt32();
                            this.inHex  = hexStr(args[4], Math.min(this.inLen, 48));
                            this.outPtr = args[6];
                            this.outLenPtr = args[7];
                            recordKey('doCrypt', this.keyHex);
                            console.log('[doCrypt] enc=' + this.enc +
                                        ' inLen=' + this.inLen +
                                        ' key=' + this.keyHex +
                                        ' iv=' + this.ivHex);
                            console.log('  in  : ' + this.inHex);
                        } catch (e) {
                            console.log('[doCrypt] onEnter err: ' + e.message);
                        }
                    },
                    onLeave: function () {
                        try {
                            if (this.outPtr && !this.outPtr.isNull() &&
                                this.outLenPtr && !this.outLenPtr.isNull()) {
                                var outLen = this.outLenPtr.readU32();
                                var outHex = hexStr(this.outPtr, Math.min(outLen, 48));
                                console.log('  out : ' + outHex + '  (len=' + outLen + ')');
                            }
                        } catch (e) { /* ignore */ }
                    }
                });
            } else if (isDecrypt) {
                Interceptor.attach(s.address, {
                    onEnter: function (args) {
                        try {
                            console.log('[AesCrypto::de/encrypt] ' + name);
                            dumpQByteArray(args[1], 'arg-key-QBA');
                            dumpQByteArray(args[2], 'arg-iv-QBA');
                        } catch (e) {
                            console.log('[de/encrypt] err: ' + e.message);
                        }
                    }
                });
            } else {
                Interceptor.attach(s.address, {
                    onEnter: function (args) {
                        console.log('[AesCrypto::*] ' + name +
                                    ' this=' + args[0] + ' arg1=' + args[1]);
                    }
                });
            }
            console.log('[+] Hooked ' + name + ' @ ' + s.address);
            hits++;
        } catch (e) {
            console.log('[-] failed to hook ' + name + ': ' + e.message);
        }
    });
    if (hits === 0) {
        console.log('[-] no AesCrypto/doCrypt symbols found — likely stripped.');
        console.log('    Falling back to module-wide symbol dump:');
        mod.enumerateSymbols().forEach(function (s) {
            if (s.type === 'function' &&
                (s.name.toLowerCase().indexOf('aes') !== -1 ||
                 s.name.toLowerCase().indexOf('crypt') !== -1 ||
                 s.name.toLowerCase().indexOf('key') !== -1)) {
                console.log('    candidate: ' + s.name + ' @ ' + s.address);
            }
        });
    }
});

// ─── 3. Generic AES symbol fallback across ALL modules ───────────────────────
// IMPORTANT: libEmbeddedLibQt.so statically links its own libcrypto — the
// AES_ecb_encrypt symbol there is INTERNAL, not exported. So we must scan
// both enumerateExports() AND enumerateSymbols(), de-duplicated by address.
Process.enumerateModules().forEach(function (mod) {
    var fns = [];
    try { fns = fns.concat(mod.enumerateExports()); } catch (e) {}
    try { fns = fns.concat(mod.enumerateSymbols()); } catch (e) {}

    var seenAddrs = new Set();
    fns.forEach(function (e) {
        if (e.type !== 'function') return;
        var key = e.address.toString();
        if (seenAddrs.has(key)) return;
        seenAddrs.add(key);

        if (e.name === 'AES_set_decrypt_key' || e.name === 'AES_set_encrypt_key') {
            try {
                Interceptor.attach(e.address, {
                    onEnter: function (args) {
                        var bits = args[1].toInt32();
                        if (bits === 128) {
                            recordKey(e.name + '/' + mod.name, hexStr(args[0], 16));
                        }
                    }
                });
                console.log('[+] Hooked ' + e.name + ' in ' + mod.name);
            } catch (err) { /* ignore */ }
        }

        if (e.name === 'AES_ecb_encrypt') {
            try {
                Interceptor.attach(e.address, {
                    onEnter: function (args) {
                        this.outPtr = args[1];
                        this.enc    = args[3].toInt32();
                        this.rk0    = hexStr(args[2],          16);
                        this.rk10   = hexStr(args[2].add(160), 16);
                        this.ct     = hexStr(args[0], 16);
                    },
                    onLeave: function () {
                        if (this.enc !== 0) return;
                        pktCount++;
                        if (pktCount <= 10) {
                            console.log('[PKT #' + pktCount + ' /' + mod.name + ']');
                            console.log('  cipher : ' + this.ct);
                            console.log('  plain  : ' + hexStr(this.outPtr, 32));
                            console.log('  rk[0]  : ' + this.rk0);
                            console.log('  rk[10] : ' + this.rk10);
                        } else if (pktCount === 11) {
                            console.log('... (silencing further packets)');
                        }
                    }
                });
                console.log('[+] Hooked AES_ecb_encrypt in ' + mod.name);
            } catch (err) { /* ignore */ }
        }

        if (e.name.indexOf('EVP_DecryptInit') !== -1 ||
            e.name.indexOf('EVP_CipherInit') !== -1) {
            try {
                Interceptor.attach(e.address, {
                    onEnter: function (args) {
                        // EVP_{Cipher,Decrypt}Init_ex(ctx, type, impl, key, iv)
                        var keyArg = args[3];
                        if (!keyArg.isNull()) {
                            recordKey(e.name + '/' + mod.name, hexStr(keyArg, 16));
                        }
                    }
                });
                console.log('[+] Hooked ' + e.name + ' in ' + mod.name);
            } catch (err) { /* ignore */ }
        }
    });
});

console.log('[*] hook_key.js loaded — connect EPOC X now.');
console.log('[*] Known keys will be printed as [KEY] ...');
