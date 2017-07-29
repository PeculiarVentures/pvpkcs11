```
# install build tools
sudo npm install gyp.js -g
brew install ninja

# configure project
gyp

# Build library
cd out/<arch>
ninja

# or

ninja -C out/<arch>
```