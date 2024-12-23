// Example of unsafe buffer usage
const unsafeBuffer = Buffer.allocUnsafe(1024);
const oldBuffer = new Buffer(16);

// Some operations with the buffers
unsafeBuffer.write('This is unsafe!');
oldBuffer.write('Also unsafe!'); 