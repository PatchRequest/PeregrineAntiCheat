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
 *              Exactly one process at a time, and every other request on the
 *              control device requires it.
 */

#define STATE_MAX_PROTECTED 64
#define STATE_MAX_TRUSTED   1

VOID StateInit(VOID);

/* Idempotent. STATUS_INSUFFICIENT_RESOURCES when the set is full. */
NTSTATUS StateProtectPid(_In_ HANDLE Pid);
/* STATUS_NOT_FOUND when the PID was not in the set. */
NTSTATUS StateUnprotectPid(_In_ HANDLE Pid);
VOID     StateClearProtected(VOID);
BOOLEAN  StateIsPidProtected(_In_ HANDLE Pid);
/* Copies up to Capacity protected PIDs; returns how many were written. */
ULONG    StateSnapshotProtected(_Out_writes_(Capacity) HANDLE* Out, _In_ ULONG Capacity);

/* Exclusive: succeeds for the first caller and, idempotently, for that same
   process again; STATUS_ACCESS_DENIED while another live process holds it. */
NTSTATUS StateTrustPid(_In_ HANDLE Pid);
BOOLEAN  StateIsPidTrusted(_In_ HANDLE Pid);

/* Drops the PID from both sets so a recycled PID inherits nothing. */
VOID StateOnProcessExit(_In_ HANDLE Pid);
