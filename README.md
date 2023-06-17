# desfire-tools-for-android
A collection of tools for interaction with [MIFARE DESFire EV1] NFC tags using Android, mostly adapted from [libfreefare] and [nfcjlib].

Features:
  * [MIFARE DESFire EV1] tag model
  * Encryption support
    * AES
    * (3)DES 
    * 3K3DES
  * [Mifare Desfire Tool] demo application

As NXP now has a freely available [TapLinx] SDK for supporting these cards, so this project is mostly for educational and/or debugging purposes.

## Licenses
For following licenses apply

  * nfcjlib - [Modified BSD License (3-clause BSD)]
  * libfreefare - [LGPL 3.0 with classpath exception]
  * everything else - [Apache 2.0]

# Obtain
The project is based on [Gradle].

# Usage
See the example application.

# See also

 * [android-nfc-wrapper](https://github.com/skjolber/android-nfc-wrapper)
 * [android-nfc-lib](https://github.com/entur/android-nfc-lib)
 * [android-nfc-lifecycle-wrapper](https://github.com/skjolber/android-nfc-lifecycle-wrapper)

# History
 - 1.0.1: Maintainance release (only available as source code).
 - 1.0.0: Initial version

[Gradle]:                               https://gradle.org/
[Apache 2.0]:          		            http://www.apache.org/licenses/LICENSE-2.0.html
[issue-tracker]:       		            https://github.com/skjolber/desfire-tools-for-android/issues
[Modified BSD License (3-clause BSD)]:  nfcjlib/LICENSE
[LGPL 3.0 with classpath exception]:    libfreefare/LICENSE
[Mifare Desfire Tool]:          		https://play.google.com/store/apps/details?id=com.skjolberg.mifare.desfiretool&hl=no
[TapLinx]:                              https://www.mifare.net/en/products/tools/taplinx/
[MIFARE DESFire EV1]:                   https://en.wikipedia.org/wiki/MIFARE#MIFARE_DESFire_EV1_(previously_called_DESFire8)
[libfreefare]:                          https://github.com/nfc-tools/libfreefare
[nfcjlib]:                              https://github.com/Andrade/nfcjlib
