{
    'target_defaults': {
        'default_configuration': 'Release_x64',
        'configurations': {
            'Debug': {
                # configuration specific settings
            },
            'Release': {
                # configuration specific settings
            },
            'Debug_x64': {
                'inherit_from': ['Debug'],
                'msvs_configuration_platform': 'x64',
                'xcode_settings': {
                    'ARCHS': ['x86_64'],
                }
            },
            'Release_x64': {
                'inherit_from': ['Release'],
                'msvs_configuration_platform': 'x64',
                'xcode_settings': {
                    'ARCHS': ['x86_64'],
                }
            },
        },
    },
    'targets': [
        {
            'target_name': 'pvpkcs11',
            'defines': [
                'PVPKCS11_VERSION_MAJOR=1',
                'PVPKCS11_VERSION_MINOR=1',
            ],
            'include_dirs': [
            ],
            'type': 'shared_library',
            'sources': [
                # core
                'src/stdafx.cpp',
                'src/pkcs11.cpp',
                'src/logger.cpp',
                'src/core/crypto_digest.cpp',
                'src/core/crypto_sign.cpp',
                'src/core/crypto_encrypt.cpp',
                'src/core/excep.cpp',
                'src/core/module.cpp',
                'src/core/object.cpp',
                'src/core/session.cpp',
                'src/core/slot.cpp',
                'src/core/attribute.cpp',
                'src/core/template.cpp',
                'src/core/keypair.cpp',
                # core/objects
                'src/core/objects/mechanism.cpp',
                'src/core/objects/storage.cpp',
                'src/core/objects/key.cpp',
                'src/core/objects/private_key.cpp',
                'src/core/objects/public_key.cpp',
                'src/core/objects/secret_key.cpp',
                'src/core/objects/aes_key.cpp',
                'src/core/objects/rsa_private_key.cpp',
                'src/core/objects/rsa_public_key.cpp',
                'src/core/objects/ec_key.cpp',
                'src/core/objects/certificate.cpp',
                'src/core/objects/x509_certificate.cpp',
                'src/core/objects/data.cpp',
            ],
            'conditions': [
                ['OS=="win"', {
                    'cflags': ['-Fo=$(IntDir)/%(RelativeDir)/'],
                    'libraries': [
                        'Crypt32.lib',
                        'Advapi32.lib',
                        'Bcrypt.lib',
                        'Ncrypt.lib'
                    ],
                    'msvs_settings': {
                        'VCCLCompilerTool': {
                            'ObjectFile': '$(IntDir)/%(RelativeDir)/'  # /Fo
                        },
                    },
                    'sources': [
                        # mscapi
                        'src/mscapi/helper.cpp',
                        'src/mscapi/session.cpp',
                        'src/mscapi/slot.cpp',
                        'src/mscapi/data.cpp',
                        'src/mscapi/key.cpp',
                        'src/mscapi/rsa.cpp',
                        'src/mscapi/ec.cpp',
                        'src/mscapi/aes.cpp',
                        'src/mscapi/certificate.cpp',
                        # mscapi/crypto
                        'src/mscapi/crypto_digest.cpp',
                        'src/mscapi/crypto_sign.cpp',
                        'src/mscapi/crypto_encrypt.cpp',
                        # mscapi/bcrypt
                        'src/mscapi/bcrypt/algorithm.cpp',
                        'src/mscapi/bcrypt/key.cpp',
                        # mscapi/ncrypt
                        'src/mscapi/ncrypt/provider.cpp',
                        'src/mscapi/ncrypt/key.cpp',
                        # mscapi/crypt
                        'src/mscapi/crypt/prov.cpp',
                        'src/mscapi/crypt/excep.cpp',
                        'src/mscapi/crypt/cert.cpp',
                        'src/mscapi/crypt/key.cpp',
                        'src/mscapi/crypt/cert_store.cpp'
                    ],
                }],
                ['OS=="mac"', {
                    'include_dirs': [
                        '/System/Library/Frameworks/CoreFoundation.framework/Headers',
                        '/System/Library/Frameworks/Security.framework/Headers',
                    ],
                    'xcode_settings': {
                        'GCC_ENABLE_CPP_EXCEPTIONS': 'YES',
                        'OTHER_CFLAGS': [
                            '-ObjC++',
                        ],
                    },
                    'cflags': [
                        '-Wc++11-extensions',
                    ],
                    'link_settings': {
                        'libraries': [
                            '-lobjc',
                            '-framework CoreFoundation',
                            '-framework Security',
                        ],
                    },
                    'sources': [
                        # osx
                        'src/osx/helper.cpp',
                        'src/osx/slot.cpp',
                        'src/osx/session.cpp',
                        'src/osx/key.cpp',
                        'src/osx/aes.cpp',
                        'src/osx/rsa.cpp',
                        'src/osx/ec.cpp',
                        'src/osx/certificate.cpp',
                        'src/osx/data.cpp',
                        # crypto
                        'src/osx/crypto/digest.cpp',
                        'src/osx/crypto/aes.cpp',
                        'src/osx/crypto/rsa.cpp',
                        'src/osx/crypto/ec.cpp',
                    ],
                }],
            ],
        }
    ]
}
