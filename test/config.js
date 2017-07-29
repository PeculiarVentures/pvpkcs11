const os = require("os");


const config = {
}

switch (os.platform()) {
    case "darwin": {
        config.lib = "out/Debug_x64/libpvpkcs11.dylib";
        break;
    }
    case "win32": {
        config.lib = "build/Debug/pvpkcs11.dll";
        break;
    }
}

module.exports = config;