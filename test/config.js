const os = require("os");
const fs = require("fs");


const config = {
}

let libs;

switch (os.platform()) {
  case "darwin": {
    libs = [
      "out/Debug_x64/libpvpkcs11.dylib",
      "out/Debug/libpvpkcs11.dylib",
      "out/Release_x64/libpvpkcs11.dylib",
      "out/Release/libpvpkcs11.dylib",
    ];
    break;
  }
  case "win32": {
    libs = [
      "out/Debug_x64/pvpkcs11.dll",
      "out/Debug/pvpkcs11.dll",
      "out/Release_x64/pvpkcs11.dll",
      "out/Release/pvpkcs11.dll",
    ];
    break;
  }
  default:
    throw new Error("Cannot get pvpkcs11 compiled library. Unsupported OS");
}
config.lib = libs.find(o => fs.existsSync(o));
if (!config.lib) {
  throw new Error("config.lib is empty");
}

module.exports = config;