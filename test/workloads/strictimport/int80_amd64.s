// SPDX-License-Identifier: Apache-2.0

#include "textflag.h"

// func int80Call(nr int32) int32
TEXT ·int80Call(SB), NOSPLIT, $0-12
	MOVL nr+0(FP), AX
	MOVL $0, BX
	MOVL $0, CX
	MOVL $0, DX
	INT  $0x80
	MOVL AX, ret+8(FP)
	RET
