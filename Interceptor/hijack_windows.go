//go:build windows
// +build windows

// SPDX-LICENSE-IDENTIFIER: GPL-2.0
// (C) 2024 Author: <kisfg@hotmail.com>
/*
CREDITS:

	WireGuard github dot com/WireGuard/wintun
	git dot zx2c4 dot com/wintun-go/tree/wintun dot go
	skyblond dot info/archives/989 dot html`
	www dot kandaoni dot com/news/31395 dot html
	www dot hackerfactor dot com
*/

package interceptor

import (
	"encoding/hex"
	"errors"
	"log"
	"path/filepath"
	"runtime"
	"unsafe"

	utils "selfproxy/utils"

	"golang.org/x/sys/windows"
)

// quit while cleaning all libs and drivers.
var (
	/*
		QuitEvent    windows.Handle
		kernel32Dll  = windows.NewLazyDLL(`kernel32.dll`)
		CreateEventW = kernel32Dll.NewProc(`CreateEventW`)
		SetEvent     = kernel32Dll.NewProc(`SetEvent`)
		CloseHandle  = kernel32Dll.NewProc(`CloseHandle`)
	*/
	ipHelpApi = windows.NewLazyDLL(`iphlpapi.dll`)
	// learn.microsoft.com/zh-cn/windows-hardware/drivers/network/initializeunicastipaddressentry
	InitializeUnicastIpAddressEntry = ipHelpApi.NewProc(`InitializeUnicastIpAddressEntry`)
	CreateUnicastIpAddressEntry     = ipHelpApi.NewProc(`CreateUnicastIpAddressEntry`)
	GetUnicastIpAddressTable        = ipHelpApi.NewProc(`GetUnicastIpAddressTable`)

	// https://learn.microsoft.com/zh-cn/windows/win32/api/combaseapi/nf-combaseapi-cocreateguid
	Ole32        = windows.NewLazyDLL(`Ole32.dll`)
	CoCreateGuid = Ole32.NewProc("coCreateGuid")
	curr_dir, _  = utils.GetFilePath(filepath.Dir(`.`))
	path2dll     = curr_dir + `\wintun\bin\` + runtime.GOARCH + `\wintun.dll`
	/* wintun domain */
	dllWintun                            = windows.NewLazyDLL(path2dll)
	syscallWintunCreateAdapter           = dllWintun.NewProc(`WintunCreateAdapter`)           // return handle if success, otherwise return nil
	syscallWintunOpenAdapter             = dllWintun.NewProc(`WintunOpenAdapter`)             // return handle if success, otherwise return nil
	syscallWintunCloseAdapter            = dllWintun.NewProc(`WintunCloseAdapter`)            // invoke this before preparing to quit
	syscallWintunGetAdapterLUID          = dllWintun.NewProc(`WintunGetAdapterLUID`)          // gain LUID of current adapter
	syscallWintunGetRunningDriverVersion = dllWintun.NewProc(`WintunGetRunningDriverVersion`) // gain wintun driver version
	syscallWintunDeleteDriver            = dllWintun.NewProc(`WintunDeleteDriver`)            // delete driver
	/* session domain */
	// syscallWintunSetLogger            = dllWintun.NewProc(`WintunSetLogger`) 			  // message logger
	syscallWintunStartSession         = dllWintun.NewProc(`WintunStartSession`)
	syscallWintunEndSession           = dllWintun.NewProc(`WintunEndSession`)
	syscallWintunReceivePacket        = dllWintun.NewProc(`WintunReceivePacket`)
	syscallWintunReleaseReceivePacket = dllWintun.NewProc(`WintunReleaseReceivePacket`)
	syscallWintunAllocateSendPacket   = dllWintun.NewProc(`WintunAllocateSendPacket`)
	syscallWintunSendPacket           = dllWintun.NewProc(`WintunSendPacket`)
	syscallWintunGetReadWaitEvent     = dllWintun.NewProc("WintunGetReadWaitEvent")
)

type (
	_GUID struct {
		Data1 uint32
		Data2 uint16
		Data3 uint16
		Data4 [8]byte
	}

	WintunAdapter struct {
		Name    string
		TunType string
		GUID    string

		handle windows.Handle
	}
	CurrSession struct {
		handle windows.Handle
	}
)

// cast the address of obj into uintptr
func UintptrCaster(obj any) uintptr {
	return uintptr(unsafe.Pointer(&obj))
}

func WintunDriverRunningVersion() (version uint32, err error) {
	err = syscallWintunGetRunningDriverVersion.Find()
	if err != nil {
		return 0, err
	}
	r1, _, err := syscallWintunGetRunningDriverVersion.Call()
	if r1 == 0 {
		return 0, err
	}
	version = uint32(r1)
	return version, nil
}

/*
each data-domain should place bytes in little endian. If invalid then throw an error.

	string: `xxxxxxxx-yyyy-zzzz-wwwwwwwwwwwwwwww`
	bytes:  `xxxxxxxxyyyyzzzzwwwwwwwwwwwwwwww`
*/
func (guid *_GUID) GUIDSetfromBytes(inp []byte) error {
	if len(inp) != 16 {
		return errors.New(`invalid inp for GUID detected from bad len`)
	}
	guid.Data1 = utils.BytesToUint32([4]byte(inp[:4]))
	guid.Data2 = utils.BytesToUint16([2]byte(inp[4:6]))
	guid.Data3 = utils.BytesToUint16([2]byte(inp[6:8]))
	guid.Data4 = [8]byte(inp[8:16])
	return nil
}

/*
convert string to GUID. if invalid, then throw an error.

	inp should in the shape of `xxxxxxxx-xxxx-xxxx-xxxxxxxxxxxxxxxx`.
		                        0       8    d    1
	                            0       0    0    1
*/
func (guid *_GUID) GUIDSetfromString(inp string) error {
	if len(inp) != 8+1+4+1+4+1+16 {
		return errors.New(`invalid inp for setting wintun GUID detected from bad len`)
	}
	data1_st, data2_st, data3_st := 0x08, 0x0d, 0x11

	_tmp, err := hex.DecodeString(inp[:data1_st])
	if err != nil {
		return err
	}
	guid.Data1 = utils.BytesToUint32([4]byte(_tmp))

	_tmp, err = hex.DecodeString(inp[data1_st:data2_st])
	if err != nil {
		return err
	}
	guid.Data2 = utils.BytesToUint16([2]byte(_tmp))

	_tmp, err = hex.DecodeString(inp[data2_st:data3_st])
	if err != nil {
		return err
	}
	guid.Data3 = utils.BytesToUint16([2]byte(_tmp))

	_tmp, err = hex.DecodeString(inp[data3_st:])
	if err != nil {
		return err
	}
	guid.Data4 = [8]byte(_tmp)
	return nil
}

func (guid *_GUID) GUIDtoString() string {
	data1 := hex.EncodeToString(utils.Uint32ToBytesInLittleEndian(guid.Data1))
	data2 := hex.EncodeToString(utils.Uint16ToBytesInLittleEndian(guid.Data2))
	data3 := hex.EncodeToString(utils.Uint16ToBytesInLittleEndian(guid.Data3))
	data4 := hex.EncodeToString(guid.Data4[:])
	return data1 + "-" + data2 + "-" + data3 + "-" + data4
}

func (guid *_GUID) GUIDtoBytes() [8 + 1 + 4 + 1 + 4 + 1 + 16]byte {
	data1 := utils.Uint32ToBytesInLittleEndian(guid.Data1)
	data2 := utils.Uint16ToBytesInLittleEndian(guid.Data2)
	data3 := utils.Uint16ToBytesInLittleEndian(guid.Data3)
	data4 := guid.Data4[:]
	data1 = append(data1, data2...)
	data1 = append(data1, data3...)
	data1 = append(data1, data4...)
	return [35]byte(data1)
}

func (adapter *WintunAdapter) SetName(name string) {
	adapter.Name = name
}

func (adapter *WintunAdapter) SetType(_type string) {
	adapter.TunType = _type
}

func (adapter *WintunAdapter) LUID() (luid uint64) {
	err := syscallWintunGetAdapterLUID.Find()
	if err != nil {
		return
	}
	syscallWintunGetAdapterLUID.Call(uintptr(adapter.handle), UintptrCaster(luid))
	return
}

func (adapter *WintunAdapter) Init() error {
	var guid _GUID
	err := CoCreateGuid.Find()
	if err != nil {
		return err
	}
	r1, _, err := CoCreateGuid.Call(UintptrCaster(&guid))
	if r1 == 0 {
		return err
	}
	err = guid.GUIDSetfromString(adapter.GUID)
	if err != nil {
		return err
	}
	err = syscallWintunCreateAdapter.Find()
	if err != nil {
		return err
	}
	r1, _, err = syscallWintunCreateAdapter.Call(
		UintptrCaster(adapter.Name),
		UintptrCaster(adapter.TunType),
		UintptrCaster(guid),
	)
	if r1 == 0 {
		return err
	}
	adapter.handle = windows.Handle(r1)
	log.Println(`r1 is:`, r1) // to be tested

	return err
}

func (adapter *WintunAdapter) Open(dev_name string) error {
	err := syscallWintunOpenAdapter.Find()
	if err != nil {
		return err
	}
	r1, _, err := syscallWintunOpenAdapter.Call(UintptrCaster(dev_name))
	if r1 == 0 {
		log.Println(err.Error()) // to Be Tested.
		return err
	}
	adapter.handle = windows.Handle(r1)
	return nil
}

func (adapter *WintunAdapter) StartSession(capacity uint32) (CurrSession, error) {
	var res CurrSession = CurrSession{}
	err := syscallWintunStartSession.Find()
	if err != nil {
		return res, err
	}
	r1, _, err := syscallWintunStartSession.Call(uintptr(adapter.handle), uintptr(capacity))
	if r1 == 0 {
		return res, err
	}
	res = CurrSession{handle: windows.Handle(r1)}
	return res, nil
}

func (adapter *WintunAdapter) Close() error {
	err := syscallWintunCloseAdapter.Find()
	if err != nil {
		return err
	}
	// runtime.SetFinalizer(adapter, nil)
	r1, _, err := syscallWintunCloseAdapter.Call(uintptr(adapter.handle))
	if r1 == 0 {
		return err
	}
	return nil
}

func (adapter *WintunAdapter) UninstallDriver() error {
	err := syscallWintunDeleteDriver.Find()
	if err != nil {
		return err
	}
	r1, _, err := syscallWintunDeleteDriver.Call()
	if r1 == 0 {
		return err
	}
	return nil
}

func (cs *CurrSession) EndSession() error {
	err := syscallWintunEndSession.Find()
	if err != nil {
		return err
	}
	r1, _, err := syscallWintunEndSession.Call(uintptr(cs.handle))
	if r1 == 0 {
		return err
	}
	return nil
}

func (cs *CurrSession) ReadWaitEvent() (handle windows.Handle) {
	err := syscallWintunGetReadWaitEvent.Find()
	if err != nil {
		return
	}
	r1, _, _ := syscallWintunGetReadWaitEvent.Call(uintptr(cs.handle))
	handle = windows.Handle(r1)
	return
}

func (cs *CurrSession) ReceivePacket() (res []byte, err error) {
	err = syscallWintunReceivePacket.Find()
	if err != nil {
		return
	}
	var pack_size uint32
	r1, _, err := syscallWintunReceivePacket.Call(uintptr(cs.handle), UintptrCaster(pack_size))
	if r1 == 0 {
		return
	}

	_addr := unsafe.Pointer(r1)
	res = unsafe.Slice((*byte)(_addr), pack_size)
	return
}

func (cs *CurrSession) SendPacket(pack []byte) error {
	err := syscallWintunSendPacket.Find()
	if err != nil {
		return err
	}
	r1, _, err := syscallWintunSendPacket.Call(uintptr(cs.handle), UintptrCaster(pack[0]))
	if r1 == 0 {
		return err
	}
	return nil
}

func (cs *CurrSession) ReleaseReceivePacket(pack []byte) error {
	err := syscallWintunReleaseReceivePacket.Find()
	if err != nil {
		return err
	}
	r1, _, err := syscallWintunReleaseReceivePacket.Call(uintptr(cs.handle), UintptrCaster(pack[0]))
	if r1 == 0 {
		return err
	}
	return nil
}

func (cs *CurrSession) AllocateSendPacket(packSize int) (res []byte, err error) {
	r1, _, err := syscallWintunAllocateSendPacket.Call(uintptr(cs.handle), uintptr(packSize))
	if r1 == 0 {
		return
	}
	_addr := unsafe.Pointer(r1)
	res = unsafe.Slice((*byte)(_addr), (packSize))
	return
}

/*
TODO: IP Configuration

	Module Testing

AF_UNSPEC 0      指定此参数时，此函数返回包含 IPv4 和 IPv6 条目的单播 IP 地址表。
AF_INET   2 IPv4 指定此参数时，此函数返回仅包含 IPv4 条目的单播 IP 地址表。
AF_INET6 23 IPv6 指定此参数时，此函数返回仅包含 IPv6 条目的单播 IP 地址表。
*/
// windows.NOERROR windows.ERROR_NOT_FOUND
// a pointer points to MIB_UNICASTIPADDRESS_TABLE
// r1, _, err := GetUnicastIpAddressTable.Call(UintptrCaster(addr_table_type))
