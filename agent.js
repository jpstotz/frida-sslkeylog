"use strict"

const moduleName = "myexecutable"; //TODO: set main executable module name here
const imgBaseAddr = 0x400000; // standard image base address in IDA
const moduleBaseAddr = Module.findBaseAddress(moduleName);

// TODO: open the binary in IDA and extract the 6 function addresses
// Note them as shown by IDA, we adapt the base address
const SSL_connect_ptr = moduleBaseAddr.add(0x8E5880 - imgBaseAddr); // SSL_connect
const SSL_read_ptr = moduleBaseAddr.add(0x8E5B00 - imgBaseAddr); // SSL_read
const SSL_write_ptr = moduleBaseAddr.add(0x8E5C10 - imgBaseAddr); // SSL_write
const SSL_get_session_ptr = moduleBaseAddr.add(0x8EC120 - imgBaseAddr); // SSL_get_session
const i2d_SSL_SESSION_ptr = moduleBaseAddr.add(0x90D270 - imgBaseAddr); // i2d_SSL_SESSION
const SSL_get_client_random_ptr = moduleBaseAddr.add(0x8E8530 - imgBaseAddr); // SSL_get_client_random

const SSL_get_session = new NativeFunction(SSL_get_session_ptr, "pointer", ["pointer"]);
const i2d_SSL_SESSION = new NativeFunction(i2d_SSL_SESSION_ptr, "int", ["pointer", "pointer"]);
const SSL_get_client_random = new NativeFunction(SSL_get_client_random_ptr, "int", ["pointer", "pointer", "int"]);

function allocPointer(value) {
    const address = Memory.alloc(Process.pointerSize);
    Memory.writePointer(address, value);
    return address;
}

function handleSSL(ssl) {
    // Save clientRandomData and ASN1 encoded session data into one memory region

    const session = SSL_get_session(ssl);

    const length = i2d_SSL_SESSION(session, NULL) + 32;
    const address = Memory.alloc(length);

    // Get client random
    SSL_get_client_random(ssl, address, 32);
    // Get ASN.1 encoded SSL session data
    i2d_SSL_SESSION(session, allocPointer(address.add(32)));

    let data = Memory.readByteArray(address, length);
    send("session", data);
}

Interceptor.attach(SSL_connect_ptr, {
    onEnter: function (args) {
        this.ssl = args[0];
    },

    onLeave: function (retvalue) {
        handleSSL(this.ssl);
    }
});

function attachSSL(address) {
    Interceptor.attach(address, {
        onEnter: function (args) {
            const ssl = args[0];
            handleSSL(ssl);
        }
    });
}

attachSSL(SSL_read_ptr);
attachSSL(SSL_write_ptr);
