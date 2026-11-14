#pragma once
#include <fltKernel.h>

/*
 * Two PID sets with deliberately different meanings. No call site may use one
 * in place of the other.
 *
 *   PROTECTED  "we defend this process"  — the game.
 *              Scopes every detection (ObCallback, thread/image notify, ...).
 *              Set by the GUI (explicit PID) or by a successful Game inject.
 *              Grants the process nothing.
 *
 *   TRUSTED    "this process is us"      — the elevated GUI.
 *              Exempts the caller from ObCallback reporting and from the
 *              minifilter's AC file self-defense.
 *              Only ever set through ComsCmdTrustCaller, for the PID that
 *              issued the IOCTL. Never set by inject success, never by name.
 */

#define STATE_MAX_PROTECTED 64
#define STATE_MAX_TRUSTED   8

VOID StateInit(VOID);

/* Idempotent. STATUS_INSUFFICIENT_RESOURCES when the set is full. */
NTSTATUS StateProtectPid(_In_ HANDLE Pid);
/* STATUS_NOT_FOUND when the PID was not in the set. */
NTSTATUS StateUnprotectPid(_In_ HANDLE Pid);
VOID     StateClearProtected(VOID);
BOOLEAN  StateIsPidProtected(_In_ HANDLE Pid);

/* Idempotent. STATUS_INSUFFICIENT_RESOURCES when the set is full. */
NTSTATUS StateTrustPid(_In_ HANDLE Pid);
BOOLEAN  StateIsPidTrusted(_In_ HANDLE Pid);

/* Drops the PID from both sets so a recycled PID inherits nothing. */
VOID StateOnProcessExit(_In_ HANDLE Pid);
