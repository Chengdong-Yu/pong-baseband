# PongBaseband

SM8475 / X65 board backend for native iPhone17,2 iOS18.6.2 (22G100), Darwin24 and arm64e. It connects the actual Pong PAS/SMEM/SMP2P/GLINK/QRTR and IPA5.1/GSI3.0 implementation to the original AppleBaseband, PCIControl and QMUX interfaces.

Build this driver through the device repository's `scripts/build-pong-ios18e.py`; board inputs, original OS ABI records and private firmware paths belong to that repository. Sibling driver names and exported runtime class names are preserved.

Device evidence: actual SIM identities, network registration, addressed IPv4/IPv6 WAN sessions and bidirectional packet transport are implemented. A cellular-only native HTTP request returned 200 with Wi-Fi excluded (device record287). Real IMS registration and voice/SMS service availability were observed (record297). These observations do not prove native calls, SMS delivery, microphone capture or receiver call audio: calls still end immediately and those paths remain under repair.

Hardware addresses and layouts target Pong IPA5.1/GSI3.0; they are not SC7180 IPA4.2 values. Real DMA completion, endpoint ownership, teardown and errors remain mandatory. No SIM, registration, address, packet or call success is manufactured. Firmware, Apple images, modem identities and EFS/NV never belong in this repository.

The upstream QcomBaseband control bridge retains its identity and license in its separate pinned source checkout: https://github.com/UniXNU/QcomBaseband . `LICENSE.tqftpserv` covers the explicitly attributed RFS portions; other source headers retain their respective SPDX declarations.
