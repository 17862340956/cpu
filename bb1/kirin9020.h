#ifndef _KIRIN9020_H
#define _KIRIN9020_H

#define FAKE_N_CPUS 12

static const unsigned int fake_cpu_part[FAKE_N_CPUS] = {
	0xd23, 0xd23, 0xd23, 0xd23,
	0xd46, 0xd46, 0xd46, 0xd46, 0xd46, 0xd46,
	0xd05, 0xd05,
};

#define FAKE_IMPLEMENTER 0x48
#define FAKE_VARIANT 0x2
#define FAKE_ARCH 8
#define FAKE_REVISION 1

#define FAKE_UTS_RELEASE "5.15.167-HUAWEI-Kirin9020"
#define FAKE_UTS_VERSION "#1 SMP PREEMPT Fri Sep 5 06:37:22 UTC 2025"
#define FAKE_UTS_MACHINE "aarch64"

#define FAKE_HARDWARE "HUAWEI Kirin9020"
#define FAKE_BOGOMIPS "38.40"

#define FAKE_FEATURES \
	"fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp " \
	"cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp sha512 " \
	"asimdfhm dit uscat ilrcpc flagm sb paca pacg dcpodp flagm2 frint " \
	"i8mm bf16 bti"

#endif
