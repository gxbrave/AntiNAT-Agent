//go:build windows

package main

import (
	"errors"
	"io"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const maxEnrollmentTokenBytes = 4096
const maxEnrollmentTokenChars = 256
const agentWindowsServiceAccount = `NT SERVICE\AntiNATAgent`
const windowsFileFullControl = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff

var (
	errTokenSourceConflict = errors.New("token input sources conflict")
	errTokenFDInvalid      = errors.New("token fd is invalid or unsafe")
	errTokenFileUnsafe     = errors.New("token file is not an owner-only regular file")
	errTokenTooLarge       = errors.New("token input exceeds size limit")
	errTokenMalformed      = errors.New("token input is malformed")
	errTokenReplaced       = errors.New("token file changed before cleanup")
)

type tokenInput struct {
	token     string
	path      string
	file      *os.File
	closeOnce bool
}

func openTokenInput(fd int, path string) (*tokenInput, error) {
	if fd >= 0 && path != "" {
		return nil, errTokenSourceConflict
	}
	if fd >= 0 {
		if fd <= 2 {
			return nil, errTokenFDInvalid
		}
		file := os.NewFile(uintptr(fd), "antinat-enrollment-token-fd")
		if file == nil {
			return nil, errTokenFDInvalid
		}
		if err := windows.SetHandleInformation(windows.Handle(file.Fd()), windows.HANDLE_FLAG_INHERIT, 0); err != nil {
			_ = file.Close()
			return nil, errTokenFDInvalid
		}
		input, err := readWindowsToken(file)
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		input.file = file
		input.closeOnce = true
		return input, nil
	}
	if path == "" {
		return nil, errTokenFDInvalid
	}
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errTokenFileUnsafe
	}
	h, err := windows.CreateFile(wide, windows.GENERIC_READ|windows.READ_CONTROL|windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, errTokenFileUnsafe
	}
	file := os.NewFile(uintptr(h), path)
	if file == nil {
		_ = windows.CloseHandle(h)
		return nil, errTokenFileUnsafe
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.NumberOfLinks != 1 {
		_ = file.Close()
		return nil, errTokenFileUnsafe
	}
	if err := requireOwnerOnlyWindowsACL(h); err != nil {
		_ = file.Close()
		return nil, errTokenFileUnsafe
	}
	input, err := readWindowsToken(file)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	input.file, input.path, input.closeOnce = file, path, true
	return input, nil
}

func readWindowsToken(file *os.File) (*tokenInput, error) {
	raw, err := io.ReadAll(io.LimitReader(file, maxEnrollmentTokenBytes+1))
	if err != nil {
		return nil, errTokenMalformed
	}
	if len(raw) > maxEnrollmentTokenBytes {
		return nil, errTokenTooLarge
	}
	token := strings.TrimSpace(string(raw))
	if token == "" || len(token) > maxEnrollmentTokenChars || strings.IndexFunc(token, func(r rune) bool {
		return r == '\r' || r == '\n' || r == '\t' || r == ' '
	}) >= 0 {
		return nil, errTokenMalformed
	}
	return &tokenInput{token: token}, nil
}

// requireOwnerOnlyWindowsACL accepts exactly the ACL produced by install.ps1:
// LocalService owns the file and both LocalService and the restricted Agent
// service SID have one explicit FullControl ACE. No inherited or unrelated
// principal is accepted.
func requireOwnerOnlyWindowsACL(handle windows.Handle) error {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return errTokenFileUnsafe
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errTokenFileUnsafe
	}
	current, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return errTokenFileUnsafe
	}
	defer current.Close()
	user, err := current.GetTokenUser()
	if err != nil || user == nil || !owner.Equals(user.User.Sid) {
		return errTokenFileUnsafe
	}
	serviceSID, _, _, err := windows.LookupSID("", agentWindowsServiceAccount)
	if err != nil || serviceSID == nil || !strings.HasPrefix(serviceSID.String(), "S-1-5-80-") {
		return errTokenFileUnsafe
	}
	return validateWindowsTokenSecurityDescriptor(sd, owner, serviceSID)
}

func validateWindowsTokenSecurityDescriptor(sd *windows.SECURITY_DESCRIPTOR, owner, serviceSID *windows.SID) error {
	if sd == nil {
		return errTokenFileUnsafe
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errTokenFileUnsafe
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return errTokenFileUnsafe
	}
	return validateWindowsTokenDACL(dacl, owner, serviceSID)
}

func validateWindowsTokenDACL(dacl *windows.ACL, owner, serviceSID *windows.SID) error {
	if dacl == nil || owner == nil || serviceSID == nil || dacl.AceCount != 2 {
		return errTokenFileUnsafe
	}
	seenOwner, seenService := false, false
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			return errTokenFileUnsafe
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags&windows.INHERITED_ACE != 0 || ace.Mask != windowsFileFullControl {
			return errTokenFileUnsafe
		}
		sid := (*windows.SID)(unsafe.Pointer(uintptr(unsafe.Pointer(ace)) + unsafe.Offsetof(ace.SidStart)))
		switch {
		case owner.Equals(sid) && !seenOwner:
			seenOwner = true
		case serviceSID.Equals(sid) && !seenService:
			seenService = true
		default:
			return errTokenFileUnsafe
		}
	}
	if !seenOwner || !seenService {
		return errTokenFileUnsafe
	}
	return nil
}

// The deletion is handle-based: pathname replacement or rename cannot cause
// the replacement object to be removed.
func (in *tokenInput) commit() error {
	if in == nil || in.path == "" || in.file == nil {
		return nil
	}
	disposition := byte(1)
	if err := windows.SetFileInformationByHandle(windows.Handle(in.file.Fd()), windows.FileDispositionInfo, &disposition, 1); err != nil {
		return errTokenReplaced
	}
	return nil
}

func (in *tokenInput) abort() error { return nil }

func (in *tokenInput) close() error {
	if in == nil || !in.closeOnce || in.file == nil {
		return nil
	}
	in.closeOnce = false
	return in.file.Close()
}
